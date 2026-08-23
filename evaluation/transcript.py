"""The unit of evidence in this experiment: one shell session, recorded.

A transcript holds two kinds of information that must never mix:

  * What crossed the wire -- SSH version string, banner, prompt, commands and
    their output. This is what the blind judge is allowed to see.
  * How the harness produced it -- which arm it came from, which port it was
    collected on, what the attacker model was thinking between commands.
    This is what the judge must never see, because any of it identifies the
    arm outright and would turn the evaluation into a formality.

The split is enforced structurally rather than by convention: `blind_text()`
renders from the first group only, and the second group lives in fields it
does not read. A leak would have to be an edit to this function, not an
oversight somewhere in the calling code.

Both arms are captured, truncated and rendered by the same code path. That is
the point: any formatting difference the judge picks up has to come from the
hosts, not from the instrument.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

# Applied identically to every arm. A judge with a 8k context cannot read
# three `ps aux` dumps, and letting one arm overflow while the other fits
# would be a difference in the instrument, not in the hosts.
MAX_OUTPUT_LINES = 40
MAX_OUTPUT_CHARS = 2000
TRUNCATION_MARK = "[output truncated by the capture harness]"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "")


def clip(output: str) -> tuple[str, bool]:
    """Cap one command's output. Returns the text and whether it was cut."""
    lines = output.split("\n")
    cut = False
    if len(lines) > MAX_OUTPUT_LINES:
        lines = lines[:MAX_OUTPUT_LINES]
        cut = True
    text = "\n".join(lines)
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS]
        cut = True
    if cut:
        text = text.rstrip() + "\n" + TRUNCATION_MARK
    return text, cut


@dataclass
class Turn:
    """One command and what came back."""

    index: int
    prompt: str
    command: str
    output: str
    wall_ms: float
    truncated: bool = False
    # Why the attacker chose this command. Excluded from `blind_text()`: it
    # names the hypothesis under test and would hand the judge the answer.
    rationale: str = ""


@dataclass
class Transcript:
    transcript_id: str
    arm: str                  # "framework" | "real" | ... -- never rendered
    endpoint: str             # host:port -- never rendered
    server_version: str = ""
    banner: str = ""
    turns: list[Turn] = field(default_factory=list)
    # The attacker's own call at the end of its session. Recorded as a
    # secondary signal; it is *not* the blind result, because the attacker
    # was told what it was looking for and drove the session itself.
    attacker_verdict: str = ""
    attacker_confidence: float = 0.0
    attacker_cues: list[str] = field(default_factory=list)
    error: str = ""

    # -- what the judge sees ----------------------------------------------
    def blind_text(self) -> str:
        """Render the session as a terminal log, with nothing else in it.

        Scrubs the collection endpoint, because the two arms necessarily
        listen on different ports and a stray `2223` in the text would decide
        the verdict on its own.
        """
        parts = [f"$ ssh root@<target>", f"[server version: {self.server_version}]"]
        if self.banner.strip():
            parts.append(self.banner.strip())
        for turn in self.turns:
            parts.append(f"{turn.prompt}{turn.command}")
            if turn.output.strip():
                parts.append(turn.output.rstrip())
        return _scrub(self.endpoint, "\n".join(parts))

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Transcript":
        turns = [Turn(**t) for t in data.get("turns", [])]
        return cls(**{**data, "turns": turns})


def _scrub(endpoint: str, text: str) -> str:
    """Remove the harness's own addressing from the rendered session."""
    if not endpoint:
        return text
    host, _, port = endpoint.partition(":")
    out = text.replace(endpoint, "<target>")
    if host:
        out = out.replace(host, "<target>")
    if port:
        # Only as a standalone token: a port number that happens to be a byte
        # count inside `ls -l` output must survive untouched.
        out = re.sub(rf"(?<![0-9.]){re.escape(port)}(?![0-9])", "<port>", out)
    return out


def write_jsonl(path: str, transcripts: list[Transcript]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for t in transcripts:
            fh.write(json.dumps(t.to_json(), ensure_ascii=False) + "\n")


def read_jsonl(path: str) -> list[Transcript]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(Transcript.from_json(json.loads(line)))
    return out
