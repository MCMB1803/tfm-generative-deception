"""Per-session state for the decoy.

The TFM (section 1.4.2) scopes state to the active session: a virtual
filesystem overlay and a command transcript that live as long as the
attacker's SSH connection. This is what makes the deception coherent --
without it, `touch /tmp/x` followed by `ls /tmp` contradicts itself and the
decoy fingerprints itself in two commands.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from core import config


@dataclass
class Turn:
    """One attacker command and the output the framework returned."""

    command: str
    output: str
    route: str
    latency_ms: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class Session:
    """State of a single attacker SSH session."""

    session_id: str
    src_ip: str
    src_port: int
    username: str = ""
    password: str = ""
    started_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Shell state
    cwd: str = "/root"
    env: dict[str, str] = field(default_factory=dict)

    # Session-scoped filesystem overlay written by the attacker.
    # path -> content ; a value of None marks a path deleted this session.
    overlay: dict[str, str | None] = field(default_factory=dict)
    # Extra directory entries created this session: dir -> {names}
    created_entries: dict[str, set[str]] = field(default_factory=dict)

    transcript: list[Turn] = field(default_factory=list)
    techniques_seen: set[str] = field(default_factory=set)
    max_severity: int = 0

    def touch(self) -> None:
        self.last_seen = time.time()

    def record(self, turn: Turn) -> None:
        self.transcript.append(turn)
        self.touch()

    def recent_context(self, turns: int | None = None) -> list[Turn]:
        """The last N turns, replayed to the LLM so answers stay consistent."""
        n = turns if turns is not None else config.SESSION_CONTEXT_TURNS
        return self.transcript[-n:] if n > 0 else []

    def add_file(self, path: str, content: str = "") -> None:
        self.overlay[path] = content
        parent = path.rsplit("/", 1)[0] or "/"
        name = path.rsplit("/", 1)[-1]
        self.created_entries.setdefault(parent, set()).add(name)

    def remove_path(self, path: str) -> None:
        self.overlay[path] = None
        parent = path.rsplit("/", 1)[0] or "/"
        name = path.rsplit("/", 1)[-1]
        if parent in self.created_entries:
            self.created_entries[parent].discard(name)

    def read_file(self, path: str) -> str | None:
        """Overlay lookup. Returns None if untouched, "" is a real empty file."""
        return self.overlay.get(path)

    def is_deleted(self, path: str) -> bool:
        return path in self.overlay and self.overlay[path] is None

    @property
    def duration_s(self) -> float:
        return self.last_seen - self.started_at

    def summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "username": self.username,
            "commands": len(self.transcript),
            "duration_s": round(self.duration_s, 2),
            "techniques": sorted(self.techniques_seen),
            "max_severity": self.max_severity,
        }


class SessionStore:
    """Thread-safe in-memory registry of live sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, src_ip: str, src_port: int, **kwargs: Any) -> Session:
        sid = uuid.uuid4().hex[:16]
        session = Session(session_id=sid, src_ip=src_ip, src_port=src_port, **kwargs)
        with self._lock:
            self._sessions[sid] = session
        return session

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def close(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.pop(session_id, None)

    def active(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())

    def reap_idle(self) -> list[Session]:
        """Drop sessions whose SSH connection died without a clean close."""
        cutoff = time.time() - config.SESSION_IDLE_TIMEOUT
        with self._lock:
            stale = [s for s in self._sessions.values() if s.last_seen < cutoff]
            for s in stale:
                self._sessions.pop(s.session_id, None)
        return stale
