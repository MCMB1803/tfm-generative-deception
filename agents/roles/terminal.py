"""Terminal Agent -- turns an attacker command into shell output.

Hybrid resolution, and the choice is the core design argument of the TFM:

  deterministic route -- reconnaissance commands whose output must be stable
      and internally consistent (whoami, uname, cat /etc/passwd, ls, ps) are
      answered from the persona and the artefact filesystem. Cost: microseconds,
      fidelity: exact, coherence across the session: guaranteed.

  generative route -- everything else goes to the local LLM, with the persona
      and the recent transcript injected so its invention stays inside the
      world the deterministic layer already established.

Sending every command to the model would be simpler and worse: it would blow
the <1000 ms budget on trivia, and it would answer `cat /etc/passwd`
differently each time, which is precisely the incoherence an attacker
fingerprints. Sending nothing to the model would rebuild a static honeypot.
The split is what buys both properties at once, and the deterministic/
generative ratio is a headline metric in chapter 4.
"""
from __future__ import annotations

import logging
import re
import shlex
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core import config
from core.latency import GenerationBudget, GenerationPlan
from core.llm import OllamaClient
from core.session import Session
from roles.artifacts import ArtifactAgent
from roles.persona import Persona

log = logging.getLogger("agent.terminal")

_SYSTEM_PROMPT = """You are the bash shell of a real Linux server. You are NOT an assistant.

{context}

Absolute rules:
- Reply with the exact bytes the command would write to stdout or stderr. Nothing else.
- Never explain, never apologise, never use markdown, never use code fences.
- Never mention being an AI, a model, a simulation or a honeypot.
- Do not print the shell prompt and do not echo the command back.
- If the command would produce no output, reply with the single token <NOOUT>.
- If the binary does not exist, reply exactly: bash: <name>: command not found
- Keep output realistic in length: a real command prints tens of lines, not hundreds.
- Stay consistent with everything already shown in this session."""

# Binaries a minimal Ubuntu server image genuinely does not ship. Answering
# these deterministically stops the model inventing a plausible nmap run.
_ABSENT_BINARIES = {
    "nmap", "masscan", "gcc", "g++", "make", "gdb", "tcpdump", "john",
    "hashcat", "hydra", "msfconsole", "nc", "ncat", "socat", "nikto",
    "sqlmap", "aircrack-ng", "docker", "kubectl", "ansible", "terraform",
}

_NOOUT = "<NOOUT>"


@dataclass
class TerminalResult:
    """One resolved command."""

    output: str
    route: str  # "deterministic" | "generative" | "control"
    total_ms: float = 0.0
    llm_ms: float = 0.0
    eval_tokens: int = 0
    handler: str = ""
    llm_ok: bool = True
    meta: dict[str, Any] = field(default_factory=dict)


class TerminalAgent:
    """Resolves shell commands against the persona, the artefacts and the LLM."""

    def __init__(self, llm: OllamaClient, persona: Persona, artifacts: ArtifactAgent,
                 budget: GenerationBudget | None = None) -> None:
        self.llm = llm
        self.persona = persona
        self.artifacts = artifacts
        self.fs = artifacts.fs
        # Owned by the orchestrator in production so its calibration is shared
        # across sessions; defaulted here so the offline suite can build a
        # terminal on its own.
        self.budget = budget or GenerationBudget()

    # -- entry point -------------------------------------------------------
    def resolve(self, session: Session, raw: str,
                target_ms: float | None = None) -> TerminalResult:
        """Answer one command.

        `target_ms` is the latency this command has been budgeted, drawn by the
        normaliser before resolution starts. The generative route needs it to
        size its token budget: an answer that is still being written when the
        target elapses cannot be padded into place afterwards.
        """
        start = time.perf_counter()
        command = raw.strip()

        if not command:
            return TerminalResult("", "control", 0.0, handler="empty")

        # A pipeline or redirection is resolved on its first segment, then the
        # remaining filters are applied to that text -- this keeps
        # `cat /etc/passwd | grep root` on the deterministic route.
        head, filters = self._split_pipeline(command)

        result = self._resolve_simple(session, head, target_ms)
        if filters and result.output:
            result.output = self._apply_filters(result.output, filters)

        result.total_ms = (time.perf_counter() - start) * 1000
        return result

    def _resolve_simple(self, session: Session, command: str,
                        target_ms: float | None = None) -> TerminalResult:
        det = self._deterministic(session, command)
        if det is not None:
            return det
        return self._generative(session, command, target_ms)

    # -- pipeline handling -------------------------------------------------
    @staticmethod
    def _split_pipeline(command: str) -> tuple[str, list[str]]:
        # Naive split is acceptable: a quoted pipe inside a recon command is
        # rare, and when it happens the segment simply falls to the LLM.
        if "|" not in command:
            return command, []
        parts = [p.strip() for p in command.split("|")]
        return parts[0], [p for p in parts[1:] if p]

    def _apply_filters(self, text: str, filters: list[str]) -> str:
        for f in filters:
            try:
                argv = shlex.split(f)
            except ValueError:
                return text
            if not argv:
                continue
            name, args = argv[0], argv[1:]
            lines = text.split("\n")

            if name == "grep":
                flags = [a for a in args if a.startswith("-")]
                pats = [a for a in args if not a.startswith("-")]
                if not pats:
                    continue
                pattern = pats[0]
                invert = any("v" in fl for fl in flags)
                icase = any("i" in fl for fl in flags)
                count = any("c" in fl for fl in flags)
                try:
                    rx = re.compile(pattern, re.IGNORECASE if icase else 0)
                except re.error:
                    rx = re.compile(re.escape(pattern), re.IGNORECASE if icase else 0)
                kept = [ln for ln in lines if bool(rx.search(ln)) != invert]
                text = str(len(kept)) if count else "\n".join(kept)
            elif name == "head":
                n = self._numeric_arg(args, 10)
                text = "\n".join(lines[:n])
            elif name == "tail":
                n = self._numeric_arg(args, 10)
                text = "\n".join(lines[-n:])
            elif name == "wc":
                if "-l" in args:
                    text = str(len(lines))
                elif "-c" in args:
                    text = str(len(text.encode()))
                else:
                    text = f"{len(lines)} {len(text.split())} {len(text.encode())}"
            elif name == "sort":
                text = "\n".join(sorted(lines, reverse="-r" in args))
            elif name == "uniq":
                out, prev = [], object()
                for ln in lines:
                    if ln != prev:
                        out.append(ln)
                    prev = ln
                text = "\n".join(out)
            elif name in ("cut", "awk", "sed", "tr", "xargs", "less", "more", "cat"):
                # Out of scope to emulate faithfully; pass through unchanged
                # rather than invent, which would contradict the source text.
                continue
        return text

    @staticmethod
    def _numeric_arg(args: list[str], default: int) -> int:
        for i, a in enumerate(args):
            if a.startswith("-") and a[1:].isdigit():
                return int(a[1:])
            if a in ("-n", "-c") and i + 1 < len(args) and args[i + 1].isdigit():
                return int(args[i + 1])
        return default

    # -- path helpers ------------------------------------------------------
    def _abspath(self, session: Session, path: str) -> str:
        path = path.strip().strip('"').strip("'")
        if not path:
            return session.cwd
        if path == "~":
            return "/root"
        if path.startswith("~/"):
            path = "/root/" + path[2:]
        if not path.startswith("/"):
            path = f"{session.cwd.rstrip('/')}/{path}"

        parts: list[str] = []
        for seg in path.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(seg)
        return "/" + "/".join(parts)

    def _read(self, session: Session, path: str) -> str | None:
        """Session overlay first, then the artefact filesystem."""
        if session.is_deleted(path):
            return None
        overlaid = session.read_file(path)
        if overlaid is not None:
            return overlaid
        node = self.fs.get(path)
        if node is None or node.kind == "dir":
            return None
        return node.content

    # -- deterministic layer ----------------------------------------------
    def _deterministic(self, session: Session, command: str) -> TerminalResult | None:
        """Return a result, or None to defer to the LLM."""
        p = self.persona
        try:
            argv = shlex.split(command)
        except ValueError:
            return None
        if not argv:
            return None

        name = argv[0]
        args = argv[1:]
        pos = [a for a in args if not a.startswith("-")]
        flags = "".join(a.lstrip("-") for a in args if a.startswith("-"))

        def ok(text: str, handler: str) -> TerminalResult:
            return TerminalResult(text, "deterministic", handler=handler)

        # --- identity ---
        if name == "whoami":
            return ok("root", "whoami")
        if name == "id" and not pos:
            return ok("uid=0(root) gid=0(root) groups=0(root)", "id")
        if name == "groups" and not pos:
            return ok("root", "groups")
        if name in ("hostname", "hostnamectl") and not args:
            if name == "hostname":
                return ok(p.hostname, "hostname")
            return ok(
                f"   Static hostname: {p.hostname}\n"
                f"         Icon name: computer-vm\n"
                f"           Chassis: vm\n"
                f"  Operating System: {p.distro}\n"
                f"            Kernel: Linux {p.kernel}\n"
                f"      Architecture: {p.arch}", "hostnamectl")
        if name == "uname":
            if "a" in flags:
                return ok(p.uname_a(), "uname")
            if "r" in flags:
                return ok(p.kernel, "uname")
            if "m" in flags:
                return ok(p.arch, "uname")
            return ok("Linux", "uname")

        # --- navigation ---
        if name == "pwd":
            return ok(session.cwd, "pwd")
        if name == "cd":
            target = self._abspath(session, pos[0] if pos else "~")
            node = self.fs.get(target)
            known_dir = (node is not None and node.kind == "dir") or target in ("/root", "/")
            if known_dir or target in session.created_entries:
                session.cwd = target
                return ok("", "cd")
            if node is not None and node.kind != "dir":
                return ok(f"bash: cd: {pos[0]}: Not a directory", "cd")
            return ok(f"bash: cd: {pos[0] if pos else target}: No such file or directory", "cd")

        # --- listing ---
        if name in ("ls", "ll", "dir"):
            if name == "ll":
                flags += "la"
            target = self._abspath(session, pos[0] if pos else ".")
            node = self.fs.get(target)
            if node is not None and node.kind == "file":
                return ok(target if "l" not in flags else
                          f"{node.mode} 1 {node.owner:<8} {node.group:<8} {node.size:>7} "
                          f"{node.mtime} {target}", "ls")
            if node is None and target not in session.created_entries:
                return ok(f"ls: cannot access '{pos[0] if pos else target}': "
                          "No such file or directory", "ls")
            listing = self.fs.listing(
                target,
                long="l" in flags,
                all_files="a" in flags,
                extra_names=session.created_entries.get(target),
            )
            return ok(listing, "ls")

        # --- file reads ---
        if name in ("cat", "head", "tail", "less", "more", "view"):
            if not pos:
                return None
            target = self._abspath(session, pos[0])

            if target == "/var/log/nginx/access.log":
                n = self._numeric_arg(args, 10) if name in ("head", "tail") else None
                body = self.artifacts.access_log(n if name == "tail" else None)
                if name == "head" and n:
                    body = "\n".join(body.split("\n")[:n])
                return ok(body, "log")
            if target == "/var/log/auth.log":
                n = self._numeric_arg(args, 10) if name in ("head", "tail") else None
                body = self.artifacts.auth_log(n if name == "tail" else None)
                if name == "head" and n:
                    body = "\n".join(body.split("\n")[:n])
                return ok(body, "log")

            content = self._read(session, target)
            if content is not None:
                lines = content.rstrip("\n").split("\n")
                if name == "head":
                    lines = lines[: self._numeric_arg(args, 10)]
                elif name == "tail":
                    lines = lines[-self._numeric_arg(args, 10):]
                return ok("\n".join(lines), f"read:{name}")

            node = self.fs.get(target)
            if node is not None and node.kind == "dir":
                return ok(f"{name}: {pos[0]}: Is a directory", "read")
            if node is not None and node.content is None:
                # Registered but binary (a .sql.gz dump): emit believable noise.
                return ok("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xed\xbd\x07`\x1cI"
                          "\x96%&/m\xca{\x7fJ\xf5J\xd7\xe0\x74\xa1\x08\x80`\x13$\xd8"
                          "\x90@\x10\xec\xc1\x88\xcd\xe6\x92\xec\x1di\x47#)\xab*\x81"
                          "\xca eof", "read:binary")
            return ok(f"{name}: {pos[0]}: No such file or directory", "read")

        # --- history ---
        if name == "history":
            hist = self._read(session, "/root/.bash_history") or ""
            lines = [ln for ln in hist.split("\n") if ln.strip()]
            lines += [t.command for t in session.transcript]
            width = len(str(len(lines))) + 1
            return ok("\n".join(f"{i + 1:>{width}}  {ln}" for i, ln in enumerate(lines)),
                      "history")

        # --- system state ---
        if name == "ps":
            return ok(p.ps_aux(), "ps")
        if name in ("ip", "ifconfig"):
            if name == "ifconfig":
                return ok(p.ifconfig(), "net")
            if pos and pos[0] in ("a", "addr", "address", "link"):
                return ok(p.ip_a(), "net")
            if pos and pos[0] in ("r", "route"):
                return ok(f"default via {p.gateway} dev eth0 proto static\n"
                          f"10.42.18.0/24 dev eth0 proto kernel scope link src {p.ip_addr}",
                          "net")
            return ok(p.ip_a(), "net")
        if name in ("netstat", "ss"):
            return ok(p.netstat(), "net")
        if name == "df":
            return ok(p.df_h(), "df")
        if name == "free":
            return ok(p.free_h(), "free")
        if name == "uptime":
            return ok(" 10:14:52 up 47 days,  7:02,  1 user,  load average: 0.08, 0.12, 0.09",
                      "uptime")
        if name == "date":
            return ok(datetime.now().strftime("%a %b %d %H:%M:%S CET %Y"), "date")
        if name == "arch":
            return ok(p.arch, "arch")
        if name == "lsb_release":
            return ok("Distributor ID:\tUbuntu\n"
                      f"Description:\t{p.distro}\n"
                      "Release:\t22.04\nCodename:\tjammy", "lsb_release")
        if name == "crontab" and "l" in flags:
            return ok(
                "30 2 * * * /opt/scripts/backup_db.sh >> /var/log/backup.log 2>&1\n"
                f"*/10 * * * * /opt/scripts/healthcheck.sh\n"
                "0 4 * * 0 /usr/bin/certbot renew --quiet", "crontab")
        if name == "who":
            return ok(f"root     pts/0        {datetime.now().strftime('%Y-%m-%d %H:%M')} "
                      f"({session.src_ip})", "who")
        if name == "w":
            return ok(" 10:14:52 up 47 days,  7:02,  1 user,  load average: 0.08, 0.12, 0.09\n"
                      "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                      f"root     pts/0    {session.src_ip:<16} 10:02    0.00s  0.03s  0.00s w",
                      "w")
        if name in ("last", "lastlog"):
            entries = [
                f"root     pts/0        {session.src_ip:<15} "
                f"{datetime.now().strftime('%a %b %d %H:%M')}   still logged in",
            ]
            for u in p.users[:3]:
                entries.append(f"{u['name']:<8} pts/1        10.42.18.201    "
                               "Wed Dec 17 09:41 - 10:12  (00:31)")
            entries.append("\nwtmp begins Mon Nov  4 03:12:07 2025")
            return ok("\n".join(entries), "last")
        if name == "mount":
            return ok("/dev/sda2 on / type ext4 (rw,relatime)\n"
                      "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
                      "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
                      "tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=1608044k)\n"
                      "/dev/sda1 on /boot/efi type vfat (rw,relatime,fmask=0077)\n"
                      "/dev/sdb1 on /var/lib/mysql type ext4 (rw,relatime)", "mount")
        if name == "getent" and pos:
            if pos[0] == "passwd":
                return ok(p.etc_passwd() if len(pos) == 1 else "\n".join(
                    ln for ln in p.etc_passwd().split("\n") if ln.startswith(pos[1] + ":")),
                    "getent")
            if pos[0] == "group":
                return ok(p.etc_group(), "getent")
        if name == "lscpu":
            return ok(f"Architecture:            {p.arch}\n"
                      "  CPU op-mode(s):        32-bit, 64-bit\n"
                      f"CPU(s):                  {p.cpu_cores}\n"
                      f"Model name:              {p.cpu_model}\n"
                      "  Thread(s) per core:    2\n  Core(s) per socket:    4\n"
                      "  Socket(s):             1\n  Virtualization:        VT-x\n"
                      "Hypervisor vendor:       KVM\nVirtualization type:     full", "lscpu")

        # --- trivial builtins ---
        if name == "echo":
            body = " ".join(args)
            if body.startswith("$"):
                var = body[1:].strip("{}")
                mapping = {"HOME": "/root", "USER": "root", "SHELL": "/bin/bash",
                           "HOSTNAME": p.hostname, "PWD": session.cwd,
                           "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
                return ok(session.env.get(var, mapping.get(var, "")), "echo")
            return ok(body, "echo")
        if name in ("clear", "reset"):
            return TerminalResult("\x1b[H\x1b[2J", "control", handler="clear")
        if name in ("env", "printenv") and not pos:
            base = {"SHELL": "/bin/bash", "PWD": session.cwd, "LOGNAME": "root",
                    "HOME": "/root", "LANG": "en_US.UTF-8", "TERM": "xterm-256color",
                    "USER": "root", "SSH_CLIENT": f"{session.src_ip} {session.src_port} 22",
                    "SSH_CONNECTION": f"{session.src_ip} {session.src_port} {p.ip_addr} 22",
                    "SSH_TTY": "/dev/pts/0",
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "_": "/usr/bin/env"}
            base.update(session.env)
            return ok("\n".join(f"{k}={v}" for k, v in base.items()), "env")
        if name in ("which", "whereis", "command", "type"):
            if not pos:
                return None
            binary = pos[-1]
            if binary in _ABSENT_BINARIES:
                return ok("" if name == "which" else f"{binary}:", "which")
            return ok(f"/usr/bin/{binary}", "which")
        if name == "sudo" and args and args[0] == "-l":
            return ok("Matching Defaults entries for root on "
                      f"{p.hostname}:\n    env_reset, mail_badpass,\n"
                      "    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:"
                      "/usr/bin\\:/sbin\\:/bin\n\n"
                      f"User root may run the following commands on {p.hostname}:\n"
                      "    (ALL : ALL) ALL", "sudo")

        # --- mutations: recorded in the session overlay ---
        if name == "touch" and pos:
            for f in pos:
                session.add_file(self._abspath(session, f), "")
            return ok("", "touch")
        if name == "mkdir" and pos:
            for d in pos:
                target = self._abspath(session, d)
                session.add_file(target, "")
                session.created_entries.setdefault(target, set())
            return ok("", "mkdir")
        if name == "rm" and pos:
            for f in pos:
                session.remove_path(self._abspath(session, f))
            return ok("", "rm")
        if name == "export" and pos:
            for a in pos:
                if "=" in a:
                    k, v = a.split("=", 1)
                    session.env[k] = v
            return ok("", "export")

        # --- absent binaries ---
        if name in _ABSENT_BINARIES:
            return ok(f"bash: {name}: command not found", "notfound")

        return None  # defer to the generative layer

    # -- generative layer --------------------------------------------------
    def _generative(self, session: Session, command: str,
                    target_ms: float | None = None) -> TerminalResult:
        # A command already answered this session, over filesystem state that
        # has not changed since, must answer identically -- that is what a real
        # host does. Re-querying the model would produce a slightly different
        # answer each time, which is the incoherence the whole design exists to
        # avoid; it would also pay for inference again.
        key = (session.cwd, command)
        cached = session.gen_cache.get(key)
        if cached is not None:
            return TerminalResult(cached, "generative", handler="llm_cache",
                                  meta={"cache": "hit"})

        # How much this command can afford to spend, given the latency it has
        # already been budgeted. Without a target there is nothing to fit
        # inside, so the global ceiling stands.
        plan = self.budget.plan(command, target_ms) if target_ms else None

        messages = [{"role": "system",
                     "content": _SYSTEM_PROMPT.format(context=self.persona.context_block())}]

        turns = plan.context_turns if plan else config.SESSION_CONTEXT_TURNS
        chars = plan.context_chars if plan else config.GEN_CONTEXT_CHARS
        for turn in session.recent_context(turns):
            messages.append({"role": "user", "content": turn.command})
            messages.append({"role": "assistant",
                             "content": (turn.output or _NOOUT)[:chars]})

        messages.append({"role": "user", "content": f"[cwd={session.cwd}] {command}"})

        response = self.llm.chat(messages,
                                 max_tokens=plan.max_tokens if plan else None,
                                 stop=["\nuser:", "root@"])
        if not response.ok:
            log.warning("Ruta generativa degradada para '%s': %s", command, response.error)
            # Fail closed into a plausible shell error rather than leaking the
            # outage to the attacker.
            return TerminalResult(
                f"bash: {command.split()[0]}: command not found",
                "generative", llm_ms=response.latency_ms, handler="llm_error",
                llm_ok=False, meta={"error": response.error},
            )

        # Feed the real cost back into the estimate before anything else: the
        # budget is only as good as its last few observations, and a run that
        # never learns keeps sizing every command off the seed constants.
        if plan is not None:
            self.budget.observe(eval_tokens=response.eval_tokens,
                                eval_ms=response.eval_ms,
                                prompt_eval_ms=response.prompt_eval_ms,
                                lean=plan.lean)

        output = self._sanitise(response.text, command)
        session.gen_cache[key] = output
        meta: dict[str, Any] = {"prompt_eval_ms": round(response.prompt_eval_ms, 1),
                                "eval_ms": round(response.eval_ms, 1)}
        if plan is not None:
            meta.update(plan.as_telemetry())
        return TerminalResult(
            output, "generative", llm_ms=response.latency_ms,
            eval_tokens=response.eval_tokens, handler="llm", meta=meta,
        )

    # -- output hygiene ----------------------------------------------------
    _LEAK_PATTERNS = [
        re.compile(r"(?i)\b(as an ai|language model|i'?m an ai|i cannot|i can'?t help|"
                   r"simulat\w+|honeypot|assistant|openai|ollama|qwen)\b"),
    ]

    def _sanitise(self, text: str, command: str) -> str:
        """Strip the tells a small instruct model still emits under pressure."""
        text = text.strip()
        if not text or text == _NOOUT:
            return ""

        # Code fences.
        text = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", text).strip()

        # An echoed prompt, or the command repeated back. Strip the prompt as a
        # prefix rather than dropping the line: the model often puts real
        # output on the same line as the prompt it should not have printed.
        # Only the user@host form, or a bare "$ ". A bare leading "#" is left
        # alone: stripping it would corrupt the first line of any config file
        # the model renders, which is a worse failure than an echoed prompt.
        prompt_prefix = re.compile(r"^\s*(?:[\w.-]+@[\w.-]+[:\s][^#$]*[#$]|\$)\s+")
        lines = text.split("\n")
        while lines:
            stripped = prompt_prefix.sub("", lines[0]).strip()
            if stripped and stripped != command.strip():
                lines[0] = stripped
                break
            if stripped == "" and lines[0].strip() == "":
                break  # a genuine blank first line, not a prompt
            lines.pop(0)
        text = "\n".join(lines).strip()

        # Any line that breaks character kills the whole reply.
        for pattern in self._LEAK_PATTERNS:
            if pattern.search(text):
                log.warning("Salida del LLM descartada por fuga de rol: %r", text[:120])
                return f"bash: {command.split()[0] if command.split() else command}: " \
                       "command not found"

        # Bound the reply: no recon command prints 200 lines, and a wall of
        # text is itself a tell.
        lines = text.split("\n")
        if len(lines) > 60:
            text = "\n".join(lines[:60])
        return text
