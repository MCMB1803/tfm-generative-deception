"""SSH driver used identically against every arm of the experiment.

The comparison only means something if the decoy and the control host are
interrogated by the same instrument. So there is one class here, not one per
arm: same client library, same pty, same read loop, same output extraction.
The arms differ in one thing -- the port they answer on -- and the harness
does not know which is which beyond a label it keeps out of the transcript.

Reading the output of a command over an interactive shell has no framing to
rely on: SSH gives a byte stream, and `whoami` and `ps aux` end the same way.
The loop below waits for the stream to go quiet *and* for the tail to look
like a shell prompt again. Quiet alone is not enough here, because latency
normalisation makes the decoy pause for most of a second between the echoed
command line and its output -- a naive idle timeout would cut every generative
answer in half and hand the judge an artefact of the instrument.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

import paramiko

from transcript import strip_ansi

# A prompt is the tail of the stream with no newline after it, ending in one
# of bash's usual terminators. Matched after ANSI removal.
_PROMPT_TAIL = re.compile(r"(?:^|\n)([^\n]{0,200}?[$#>]\s?)$")


@dataclass
class TargetSpec:
    name: str          # arm label, harness-side only
    host: str
    port: int
    username: str
    password: str


class SSHTarget:
    """One interactive SSH session against one arm."""

    def __init__(self, spec: TargetSpec, idle: float = 1.2,
                 deadline: float = 60.0, connect_timeout: float = 20.0) -> None:
        self.spec = spec
        self.idle = idle
        self.deadline = deadline
        self.connect_timeout = connect_timeout
        self._transport: paramiko.Transport | None = None
        self._chan: paramiko.Channel | None = None
        self.server_version = ""
        self.banner = ""
        self.prompt = "$ "

    @property
    def endpoint(self) -> str:
        return f"{self.spec.host}:{self.spec.port}"

    # -- lifecycle ---------------------------------------------------------
    def open(self) -> None:
        transport = paramiko.Transport((self.spec.host, self.spec.port))
        transport.banner_timeout = self.connect_timeout
        transport.start_client(timeout=self.connect_timeout)
        # The advertised version string is the cheapest honeypot tell there
        # is, so it belongs in the transcript verbatim.
        self.server_version = transport.remote_version
        transport.auth_password(self.spec.username, self.spec.password)

        chan = transport.open_session(timeout=self.connect_timeout)
        chan.get_pty(term="xterm", width=120, height=40)
        chan.invoke_shell()
        chan.settimeout(1.0)
        self._transport, self._chan = transport, chan

        # Everything up to the first prompt is the login banner: version
        # line, MOTD, last-login notice.
        first = strip_ansi(self._read())
        body, prompt = _split_prompt(first)
        self.banner = body.strip("\n")
        if prompt:
            self.prompt = prompt

    def close(self) -> None:
        for closer in (self._chan, self._transport):
            try:
                if closer is not None:
                    closer.close()
            except Exception:  # noqa: BLE001 - teardown must never raise
                pass
        self._chan = self._transport = None

    def __enter__(self) -> "SSHTarget":
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- command execution -------------------------------------------------
    def run(self, command: str) -> tuple[str, str, float]:
        """Send one command. Returns (output, prompt_it_was_typed_at, ms)."""
        if self._chan is None:
            raise RuntimeError("sesion no abierta")
        prompt_used = self.prompt
        start = time.perf_counter()
        self._chan.send(command + "\n")
        raw = strip_ansi(self._read())
        elapsed = (time.perf_counter() - start) * 1000

        body, prompt = _split_prompt(raw)
        if prompt:
            self.prompt = prompt
        return _strip_echo(body, command), prompt_used, elapsed

    # -- transport ---------------------------------------------------------
    def _read(self) -> str:
        assert self._chan is not None
        chunks: list[bytes] = []
        started = time.perf_counter()
        last_byte = started
        while True:
            if self._chan.recv_ready():
                data = self._chan.recv(65536)
                if not data:
                    break
                chunks.append(data)
                last_byte = time.perf_counter()
                continue

            now = time.perf_counter()
            if now - started >= self.deadline:
                break
            if chunks and now - last_byte >= self.idle:
                text = strip_ansi(b"".join(chunks).decode("utf-8", "replace"))
                # Quiet and a prompt at the tail: the command is done.
                if _PROMPT_TAIL.search(text):
                    break
                # Quiet for much longer than the idle window without a prompt:
                # the shell is wedged or the output genuinely ends without one.
                # Give up rather than burn the whole deadline.
                if now - last_byte >= self.idle * 5:
                    break
            if self._chan.exit_status_ready() and not self._chan.recv_ready():
                break
            time.sleep(0.03)
        return b"".join(chunks).decode("utf-8", "replace")


def _split_prompt(text: str) -> tuple[str, str]:
    """Peel a trailing prompt off the stream."""
    match = _PROMPT_TAIL.search(text)
    if not match:
        return text, ""
    return text[: match.start(1)], match.group(1)


def _strip_echo(text: str, command: str) -> str:
    """Drop the pty's echo of the command line.

    Both arms echo: the decoy emits each character as it arrives, a real pty
    does the same. Leaving the echo in would duplicate the command in the
    transcript, which is noise, not a cue.
    """
    lines = text.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].rstrip().endswith(command.strip()):
        lines.pop(0)
    return "\n".join(lines).strip("\n")
