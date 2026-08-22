"""Structured, SIEM-ready event logging.

Everything the framework observes is written as JSON Lines. One event per
line, flat keys, ISO-8601 UTC timestamps -- the shape Wazuh's JSON decoder
and Filebeat both ingest without a custom parser.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

from core import config

log = logging.getLogger("telemetry")

_lock = threading.Lock()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _append(path: str, record: dict[str, Any]) -> None:
    """Append one JSON object as a line. Serialised: decoy is multi-threaded."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with _lock:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except OSError as exc:
        log.error("No se pudo escribir telemetria en %s: %s", path, exc)


def emit_event(event_type: str, **fields: Any) -> dict[str, Any]:
    """Write a SOC event and echo it to stdout for `docker compose logs`."""
    record = {
        "timestamp": utcnow(),
        "product": "generative-deception-framework",
        "event_type": event_type,
        **fields,
    }
    _append(config.EVENT_LOG, record)
    log.info("[EVENT] %s", json.dumps(record, ensure_ascii=False, default=str))
    return record


def emit_latency(
    session_id: str,
    command: str,
    route: str,
    total_ms: float,
    llm_ms: float = 0.0,
    eval_tokens: int = 0,
    **extra: Any,
) -> dict[str, Any]:
    """Record one command's timing. This file is the source of the TFM's
    chapter 4 latency figures -- the benchmark reads it back, nothing is
    transcribed by hand."""
    record = {
        "timestamp": utcnow(),
        "session_id": session_id,
        "command": command,
        # "deterministic" (persona-derived) or "generative" (LLM inference)
        "route": route,
        "total_ms": round(total_ms, 3),
        "llm_ms": round(llm_ms, 3),
        "eval_tokens": eval_tokens,
        "within_target": total_ms <= config.LATENCY_TARGET_MS,
        "target_ms": config.LATENCY_TARGET_MS,
        **extra,
    }
    _append(config.LATENCY_LOG, record)
    return record


def configure_logging(level: str | None = None) -> None:
    logging.basicConfig(
        level=getattr(logging, (level or os.getenv("LOG_LEVEL", "INFO")).upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )
