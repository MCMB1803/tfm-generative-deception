"""The adaptive adversary.

An LLM is given one job -- decide whether the host it is logged into is a real
server or a decoy -- and a shell to do it with. It sees the output of its last
command and chooses the next one, so the probing is adaptive: a suspicious
`/etc/passwd` earns a follow-up, a boring `ls` moves on. This is the part a
fixed command list cannot emulate and the reason the evaluation needs a model
on the attacking side too.

Its final self-assessment is recorded, but it is *not* the headline result.
The attacker knows it is hunting a honeypot, so it is primed to cry decoy; the
blind judge, which is only asked to tell real terminals apart without being
told a honeypot is on the table, is the fair measurement. The attacker's guess
is kept as a secondary, adversarial signal and as the thing that makes the
probing realistic.

The model drives, but the harness keeps the guardrails: a fixed turn budget, a
deny-list for anything destructive or networked, and structured output so a
turn is a command, never an escape into free text.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from typing import TYPE_CHECKING

from ollama import Ollama, parse_json
from transcript import Transcript, Turn, clip

if TYPE_CHECKING:  # paramiko lives in targets; the safety gate must import
    from targets import SSHTarget  # cleanly without it, for the offline tests.

_SYSTEM = """You are a penetration tester with root on a Linux host reached over SSH.
Your only goal is to decide whether this host is a REAL production server or a
DECEPTION honeypot (a decoy that imitates a server, possibly with a language
model generating its responses).

You work one command at a time. Look for the tells of a decoy:
- responses that contradict each other across commands (a user in /etc/passwd
  with no home directory, a process with no matching file, a uid that shifts),
- output that is too clean, too generic, or subtly wrong in format,
- files, history or logs that do not fit a host that has really been running,
- timing or phrasing that feels generated rather than emitted by a real tool.

Reply ONLY with a JSON object and nothing else:
{"command": "<the next shell command>", "rationale": "<one sentence: what you are testing>", "done": false}
When you have enough evidence, set "done": true and add
"verdict": "real" or "decoy", "confidence": 0.0-1.0, "cues": ["short", "reasons"].
Keep commands read-only and local. Do not try to exit, reboot, delete, or reach
the network."""

# Refused outright, whatever the model asks. The experiment is about detection,
# not about letting a model run arbitrary commands against a container; and a
# real host in the control arm must come back from the run unharmed.
#
# Split on purpose into command *names* and substring *patterns*. Blocking bare
# substrings is what a careless deny-list does, and it is wrong here: "passwd"
# as a substring would refuse `cat /etc/passwd`, the single most important recon
# command in the suite. Only `passwd` invoked as a command is dangerous; reading
# the file is exactly what the attacker is supposed to do.
_DENY_COMMANDS = frozenset({
    "rm", "mkfs", "dd", "shutdown", "reboot", "halt", "poweroff", "wget",
    "curl", "nc", "ncat", "ssh", "scp", "telnet", "kill", "pkill", "iptables",
    "systemctl", "service", "apt", "apt-get", "yum", "dnf", "pip", "passwd",
    "useradd", "userdel", "usermod", "mount", "umount", "fdisk", "chpasswd",
})
# Matched anywhere: redirections into system paths, recursive perms, fork bombs,
# and piping any output into a shell.
_DENY_PATTERNS = (
    ":(){", "> /dev", ">/dev", "> /etc", ">/etc", "tee /etc", "tee -a /etc",
    "chmod -r", "chown -r", "| sh", "|sh", "| bash", "|bash",
)


@dataclass
class AttackerConfig:
    max_turns: int = 12
    temperature: float = 0.4
    max_tokens: int = 200
    # An attacker that announces a verdict before running a single command has
    # not assessed anything, and the transcript it leaves is unjudgeable: there
    # is no session in it. Small instructed models do exactly that, so the
    # verdict is refused until the engagement has actually happened. This is a
    # floor on evidence, not a nudge towards any particular conclusion -- the
    # model is told to keep looking, never what to find.
    min_turns: int = 5


def _is_safe(command: str) -> bool:
    low = command.strip().lower()
    if not low:
        return False
    if any(pat in low for pat in _DENY_PATTERNS):
        return False
    # Inspect the first token of every stage of a pipe/chain, so `whoami; rm x`
    # is caught even though its first token is harmless.
    for stage in low.replace("&&", ";").replace("||", ";").replace("|", ";").split(";"):
        tokens = stage.split()
        if not tokens:
            continue
        head = tokens[0]
        # Skip a leading `sudo`/`env`; the real command name is what matters.
        if head in ("sudo", "env") and len(tokens) > 1:
            head = tokens[1]
        if head in _DENY_COMMANDS:
            return False
    return True


class Attacker:
    def __init__(self, model: Ollama, cfg: AttackerConfig | None = None) -> None:
        self.model = model
        self.cfg = cfg or AttackerConfig()

    def run(self, target: "SSHTarget", transcript_id: str, arm: str) -> Transcript:
        tx = Transcript(transcript_id=transcript_id, arm=arm,
                        endpoint=target.endpoint)
        try:
            target.open()
        except Exception as exc:  # noqa: BLE001 - a dead arm is data, not a crash
            tx.error = f"conexion fallida: {exc}"
            return tx
        tx.server_version = target.server_version
        tx.banner = target.banner

        history: list[dict[str, str]] = [{"role": "system", "content": _SYSTEM}]
        # The login banner is the first thing a real attacker reads.
        history.append({"role": "user", "content":
                        f"You are now logged in. Login banner:\n{target.banner}\n"
                        f"SSH server version: {target.server_version}\n"
                        "Choose your first command."})

        try:
            for index in range(self.cfg.max_turns):
                reply = self.model.chat(history, temperature=self.cfg.temperature,
                                        max_tokens=self.cfg.max_tokens,
                                        json_mode=True)
                decision = parse_json(reply.text) or {}
                if decision.get("done"):
                    if len(tx.turns) >= self.cfg.min_turns:
                        self._record_verdict(tx, decision)
                        break
                    history.append({"role": "assistant", "content": reply.text})
                    history.append({"role": "user", "content":
                                    f"You have run {len(tx.turns)} command(s). "
                                    f"Do not conclude before running at least "
                                    f"{self.cfg.min_turns}. Issue the next "
                                    f"read-only command."})
                    continue

                command = str(decision.get("command", "")).strip()
                rationale = str(decision.get("rationale", ""))[:200]
                if not command:
                    # An empty command this early means the model produced
                    # nothing usable rather than that it finished; ask again
                    # before abandoning a session that has no content yet.
                    if len(tx.turns) >= self.cfg.min_turns:
                        break
                    history.append({"role": "user", "content":
                                    "No command was received. Reply with JSON "
                                    "containing a single read-only command."})
                    continue
                if not _is_safe(command):
                    # Do not run it, but keep the loop honest: tell the model
                    # the shell rejected it, so it adapts instead of repeating.
                    history.append({"role": "assistant", "content": reply.text})
                    history.append({"role": "user", "content":
                                    "That command is blocked by the engagement "
                                    "rules. Choose another, read-only command."})
                    continue

                output, prompt_used, wall = target.run(command)
                clipped, cut = clip(output)
                tx.turns.append(Turn(index=index, prompt=prompt_used,
                                     command=command, output=clipped,
                                     wall_ms=round(wall, 2), truncated=cut,
                                     rationale=rationale))

                history.append({"role": "assistant", "content": reply.text})
                history.append({"role": "user", "content":
                                f"Output of `{command}`:\n{clipped}\n"
                                "Next command, or set done:true with your verdict."})
        except Exception as exc:  # noqa: BLE001
            tx.error = f"sesion interrumpida: {exc}"
        finally:
            target.close()
        return tx

    @staticmethod
    def _record_verdict(tx: Transcript, decision: dict) -> None:
        verdict = str(decision.get("verdict", "")).lower()
        tx.attacker_verdict = "decoy" if "decoy" in verdict or "honey" in verdict \
            else ("real" if "real" in verdict else "")
        try:
            tx.attacker_confidence = max(0.0, min(1.0,
                                                  float(decision.get("confidence", 0))))
        except (TypeError, ValueError):
            tx.attacker_confidence = 0.0
        cues = decision.get("cues", [])
        if isinstance(cues, list):
            tx.attacker_cues = [str(c)[:80] for c in cues[:5]]
