"""The blind judge.

Reads one transcript with no idea which arm produced it, and classifies the
host as real or a decoy. This is the fair measurement the whole experiment
turns on, and everything about how it is called is arranged to keep it fair:

  * It sees `Transcript.blind_text()` and nothing else -- no arm label, no
    port, no attacker rationale. Those fields exist on the object; they are
    not in what the judge is handed.
  * It is *not* told a honeypot is in the sample. The prompt asks it to tell a
    real interactive session from a generated one, which is the discrimination
    under test; priming it to hunt honeypots would inflate the decoy-recall at
    the cost of flagging real hosts, and the confusion matrix would lie.
  * Transcripts are classified independently. The judge never sees two at once
    and cannot calibrate "this one is more real than that one" -- which would
    smuggle the base rate back in through the side door.

The headline number is this judge's accuracy: at 50/50 real-vs-decoy, an
undetectable decoy drives it to chance (0.5). Anything it reliably gets right
is a cue the deception still leaks. To separate the deception's quality from
one model's idiosyncrasy, a second, smaller judge scores the same transcripts
and the two are compared (agreement, kappa) in the report.
"""
from __future__ import annotations

from dataclasses import dataclass

from ollama import Ollama, parse_json
from transcript import Transcript

_SYSTEM = """You are a forensic analyst. You are given the log of a single SSH
session against a Linux host. Some hosts are ordinary production servers; others
are decoys whose responses are produced by a program or a language model
imitating a server. Decide which this one is.

Weigh the evidence in the log itself:
- internal consistency across commands (users, uids, homes, processes, files
  that all agree, or that quietly contradict each other),
- whether the output has the exact format real tools produce, down to spacing
  and headers,
- whether files, history and logs fit a host that has genuinely been in use,
- anything that reads as generated, generic, or too clean.

Judge only from the log. Reply ONLY with JSON:
{"verdict": "real" or "decoy", "confidence": 0.0-1.0, "reasons": ["short", "cues"]}"""


@dataclass
class Verdict:
    transcript_id: str
    judge: str
    verdict: str          # "real" | "decoy" | "" (unparseable)
    confidence: float
    reasons: list[str]
    truth: str            # the arm's real identity, filled in after judging
    latency_ms: float = 0.0
    parse_ok: bool = True

    @property
    def correct(self) -> bool:
        return bool(self.verdict) and self.verdict == self.truth


def _truth_of(arm: str) -> str:
    """Map an arm label to the ground-truth class the judge is scored against."""
    return "real" if arm == "real" else "decoy"


class Judge:
    def __init__(self, model: Ollama, name: str | None = None,
                 temperature: float = 0.0) -> None:
        self.model = model
        self.name = name or model.model
        self.temperature = temperature

    def classify(self, tx: Transcript) -> Verdict:
        reply = self.model.chat(
            [{"role": "system", "content": _SYSTEM},
             {"role": "user", "content":
              f"SSH session log:\n\n{tx.blind_text()}\n\nClassify this host."}],
            temperature=self.temperature, max_tokens=200, json_mode=True)

        data = parse_json(reply.text)
        if not data:
            return Verdict(tx.transcript_id, self.name, "", 0.0, [],
                           _truth_of(tx.arm), reply.latency_ms, parse_ok=False)

        raw = str(data.get("verdict", "")).lower()
        verdict = "decoy" if ("decoy" in raw or "honey" in raw or "fake" in raw) \
            else ("real" if "real" in raw else "")
        try:
            conf = max(0.0, min(1.0, float(data.get("confidence", 0))))
        except (TypeError, ValueError):
            conf = 0.0
        reasons = data.get("reasons", [])
        reasons = [str(r)[:100] for r in reasons[:5]] if isinstance(reasons, list) else []

        return Verdict(tx.transcript_id, self.name, verdict, conf, reasons,
                       _truth_of(tx.arm), reply.latency_ms,
                       parse_ok=bool(verdict))
