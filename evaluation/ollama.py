"""Host-side Ollama client for the adversary-emulation harness.

Deliberately separate from `agents/core/llm.py`. That client is part of the
system under test: it is configured by the deception agent's own environment,
it pins the decoy's model and it lives inside the container. Reusing it here
would wire the evaluator to the thing being evaluated, and a reviewer would be
right to object. This one is a plain client the harness owns, pointed at
whatever model the experiment names.

Two features the decoy's client does not need:

  * `format="json"`, so the judge returns a parseable verdict instead of prose.
  * `num_ctx`, because a full attack transcript is far longer than the handful
    of turns the decoy ever sends, and a silently truncated context would make
    the judge look worse than it is for reasons that have nothing to do with
    the deception.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

import requests


@dataclass
class Reply:
    text: str
    latency_ms: float
    ok: bool = True
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class Ollama:
    def __init__(self, host: str, model: str, timeout: float = 300.0,
                 num_ctx: int = 8192) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self._http = requests.Session()

    # -- availability ------------------------------------------------------
    def tags(self) -> list[str]:
        try:
            r = self._http.get(f"{self.host}/api/tags", timeout=10)
            r.raise_for_status()
            return [m.get("name", "") for m in r.json().get("models", [])]
        except (requests.RequestException, ValueError):
            return []

    def has_model(self) -> bool:
        return any(n == self.model or n.split(":")[0] == self.model.split(":")[0]
                   for n in self.tags())

    def pull(self, on_progress=None) -> bool:
        """Download the model, streaming progress so a 5 GB judge is not a
        silent ten-minute hang."""
        try:
            r = self._http.post(f"{self.host}/api/pull",
                                json={"model": self.model, "stream": True},
                                stream=True, timeout=3600)
            r.raise_for_status()
            for line in r.iter_lines():
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if on_progress:
                    on_progress(event.get("status", ""))
                if event.get("error"):
                    return False
            return self.has_model()
        except requests.RequestException:
            return False

    # -- inference ---------------------------------------------------------
    def chat(self, messages: list[dict[str, str]], temperature: float = 0.2,
             max_tokens: int = 256, json_mode: bool = False) -> Reply:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "keep_alive": "30m",
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "num_ctx": self.num_ctx,
                "top_p": 0.9,
            },
        }
        if json_mode:
            payload["format"] = "json"

        start = time.perf_counter()
        try:
            r = self._http.post(f"{self.host}/api/chat", json=payload,
                                timeout=self.timeout)
        except requests.RequestException as exc:
            return Reply("", (time.perf_counter() - start) * 1000, ok=False,
                         error=str(exc))
        elapsed = (time.perf_counter() - start) * 1000
        if r.status_code != 200:
            return Reply("", elapsed, ok=False,
                         error=f"HTTP {r.status_code}: {r.text[:200]}")
        try:
            body = r.json()
        except ValueError as exc:
            return Reply("", elapsed, ok=False, error=f"respuesta no JSON: {exc}")
        return Reply((body.get("message") or {}).get("content", "").strip(),
                     elapsed, raw=body)


_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def parse_json(text: str) -> dict[str, Any] | None:
    """Best-effort JSON extraction.

    `format="json"` makes Ollama emit valid JSON in the common case, but small
    models still occasionally wrap it in a fence or prepend a sentence. A
    failure here is recorded as an unusable answer rather than silently
    defaulting to one of the two verdicts -- defaulting would bias the result
    towards whichever label the code happened to choose.
    """
    if not text:
        return None
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except ValueError:
        pass
    match = _JSON_BLOCK.search(text)
    if not match:
        return None
    try:
        value = json.loads(match.group(0))
        return value if isinstance(value, dict) else None
    except ValueError:
        return None
