"""Thin, instrumented client for the local Ollama inference engine.

Two things matter here for the TFM: every call is timed, and the model is
pinned in memory via keep_alive so measurements are not polluted by cold
model loads.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from core import config

log = logging.getLogger("llm")


@dataclass
class LLMResponse:
    """A single inference result plus the timings needed for evaluation."""

    text: str
    latency_ms: float
    ok: bool = True
    error: str | None = None
    # Timings reported by Ollama itself, in nanoseconds, converted to ms.
    eval_ms: float = 0.0
    prompt_eval_ms: float = 0.0
    eval_tokens: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


class OllamaClient:
    """Blocking client against Ollama's /api/chat endpoint."""

    def __init__(
        self,
        host: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.host = (host or config.OLLAMA_HOST).rstrip("/")
        self.model = model or config.MODEL_NAME
        self.timeout = timeout or config.LLM_TIMEOUT
        self._session = requests.Session()

    # -- health ------------------------------------------------------------
    def is_ready(self) -> bool:
        try:
            r = self._session.get(f"{self.host}/api/tags", timeout=5)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def has_model(self) -> bool:
        try:
            r = self._session.get(f"{self.host}/api/tags", timeout=5)
            if r.status_code != 200:
                return False
            names = [m.get("name", "") for m in r.json().get("models", [])]
            # Ollama reports e.g. "qwen2.5-coder:0.5b"; tolerate a missing :latest tag.
            return any(n == self.model or n.split(":")[0] == self.model.split(":")[0] for n in names)
        except (requests.RequestException, ValueError):
            return False

    def wait_until_ready(self, attempts: int = 60, delay: float = 5.0) -> bool:
        for i in range(attempts):
            if self.is_ready():
                return True
            log.info("Ollama no disponible todavia (intento %d/%d)", i + 1, attempts)
            time.sleep(delay)
        return False

    def warmup(self) -> LLMResponse:
        """Force the model into RAM so the first attacker command is not slow."""
        return self.chat(
            [{"role": "user", "content": "ok"}],
            max_tokens=1,
            temperature=0.0,
        )

    # -- inference ---------------------------------------------------------
    def chat(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
        temperature: float | None = None,
        stop: list[str] | None = None,
    ) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "keep_alive": config.MODEL_KEEP_ALIVE,
            "options": {
                "temperature": config.TEMPERATURE if temperature is None else temperature,
                "num_predict": max_tokens or config.MAX_TOKENS,
                "top_p": 0.9,
                # Discourage the chatty preamble small instruct models emit.
                "repeat_penalty": 1.05,
            },
        }
        if stop:
            payload["options"]["stop"] = stop

        start = time.perf_counter()
        try:
            r = self._session.post(
                f"{self.host}/api/chat", json=payload, timeout=self.timeout
            )
        except requests.RequestException as exc:
            elapsed = (time.perf_counter() - start) * 1000
            log.warning("Fallo de conexion con Ollama: %s", exc)
            return LLMResponse("", elapsed, ok=False, error=str(exc))

        elapsed = (time.perf_counter() - start) * 1000
        if r.status_code != 200:
            return LLMResponse(
                "", elapsed, ok=False, error=f"HTTP {r.status_code}: {r.text[:200]}"
            )

        try:
            body = r.json()
        except ValueError as exc:
            return LLMResponse("", elapsed, ok=False, error=f"respuesta no JSON: {exc}")

        text = (body.get("message") or {}).get("content", "")
        return LLMResponse(
            text=text.strip(),
            latency_ms=elapsed,
            ok=True,
            eval_ms=body.get("eval_duration", 0) / 1e6,
            prompt_eval_ms=body.get("prompt_eval_duration", 0) / 1e6,
            eval_tokens=body.get("eval_count", 0),
            raw=body,
        )
