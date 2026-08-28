"""Multi-agent orchestrator.

Single entry point that wires the four agents together and owns the lifecycle
of an attacker session:

    Persona Agent   -> who this host claims to be           (once, at boot)
    Artifact Agent  -> what is on its disk and in its logs   (once, at boot)
    Terminal Agent  -> what a given command answers          (per command)
    Alert Agent     -> what the SOC is told about it         (per event)

The decoy protocol frontends (SSH today, HTTP/FTP in future work) hold no
intelligence of their own: they speak their protocol and delegate here. That
separation is what lets a second decoy service reuse the same persona and the
same session model without duplicating any of this.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from core import config
from core.latency import GenerationBudget, LatencyNormalizer
from core.llm import OllamaClient
from core.session import Session, SessionStore
from core.telemetry import emit_event, emit_latency
from roles.alerting import AlertAgent
from roles.artifacts import ArtifactAgent
from roles.persona import PersonaAgent
from roles.terminal import TerminalAgent

log = logging.getLogger("orchestrator")


class DeceptionOrchestrator:
    """Owns the agent ensemble and the live session registry."""

    def __init__(self) -> None:
        self.llm = OllamaClient()
        self.sessions = SessionStore()
        # Holds every answer until its command-derived target has elapsed,
        # so response time never leaks which route produced it.
        self.normalizer = LatencyNormalizer()
        self.gen_budget = GenerationBudget()
        self.persona = None
        self.artifacts: ArtifactAgent | None = None
        self.terminal: TerminalAgent | None = None
        self.alerts: AlertAgent | None = None
        self.ready = False
        self.boot_ms = 0.0

    # -- bootstrap ---------------------------------------------------------
    def bootstrap(self, wait_for_llm: bool = True) -> None:
        start = time.perf_counter()
        log.info("Arrancando el orquestador multi-agente...")

        if wait_for_llm and not self.llm.wait_until_ready():
            log.error("Ollama no respondio; se continua con perfiles de reserva")
        elif self.llm.is_ready() and not self.llm.has_model():
            log.warning(
                "El modelo %s no esta descargado. Ejecuta: "
                "docker exec -it ollama_llm ollama pull %s",
                self.llm.model, self.llm.model,
            )

        # Pin the model in RAM before any attacker arrives, so the first
        # command is not the slowest one of the whole engagement.
        warm = self.llm.warmup()
        log.info("Warm-up del modelo: %.0f ms (ok=%s)", warm.latency_ms, warm.ok)

        persona_agent = PersonaAgent(self.llm)
        self.persona = persona_agent.load_or_generate()

        self.artifacts = ArtifactAgent(self.llm, self.persona)
        self.artifacts.build()
        self.artifacts.start_traffic()

        self.terminal = TerminalAgent(self.llm, self.persona, self.artifacts,
                                      budget=self.gen_budget)
        self.alerts = AlertAgent(honeytoken_matcher=self.artifacts.match_honeytoken)

        self.boot_ms = (time.perf_counter() - start) * 1000
        self.ready = True
        log.info("Orquestador listo en %.0f ms - persona '%s' (%s)",
                 self.boot_ms, self.persona.hostname, self.persona.company)
        emit_event(
            "system.ready",
            boot_ms=round(self.boot_ms, 1),
            model=self.llm.model,
            persona=self.persona.hostname,
            persona_source=self.persona.generated_by,
            honeytoken_count=len(self.artifacts.honeytokens),
            fs_nodes=len(self.artifacts.fs.nodes),
        )

    def _require_ready(self) -> None:
        if not self.ready:
            raise RuntimeError("El orquestador no ha completado el bootstrap")

    # -- session lifecycle -------------------------------------------------
    def open_session(self, src_ip: str, src_port: int) -> Session:
        self._require_ready()
        session = self.sessions.create(src_ip=src_ip, src_port=src_port)
        self.alerts.session_opened(session)  # type: ignore[union-attr]
        return session

    def authenticate(self, session_id: str, username: str, password: str,
                     method: str = "password") -> bool:
        """Always succeeds -- the point is to observe, not to keep them out."""
        session = self.sessions.get(session_id)
        if session is None:
            return False
        session.username = username
        session.password = password
        self.alerts.credentials_captured(session, username, password, method)  # type: ignore[union-attr]
        return True

    def banner(self, session_id: str) -> str:
        self._require_ready()
        return self.persona.motd()  # type: ignore[union-attr]

    def prompt(self, session_id: str) -> str:
        """The PS1 the decoy should draw, reflecting the session's real cwd."""
        self._require_ready()
        session = self.sessions.get(session_id)
        cwd = session.cwd if session else "/root"
        # Matches bash's \w: the full path, with $HOME collapsed to "~".
        display = "~" if cwd == "/root" else (
            "~" + cwd[len("/root"):] if cwd.startswith("/root/") else cwd)
        return f"root@{self.persona.hostname}:{display}# "  # type: ignore[union-attr]

    def execute(self, session_id: str, command: str) -> dict[str, Any]:
        """Resolve one attacker command and emit its telemetry."""
        self._require_ready()
        session = self.sessions.get(session_id)
        if session is None:
            raise KeyError(f"sesion desconocida: {session_id}")

        # The target is drawn once, here, and used twice: to size the
        # generative token budget before the model runs, and to pad afterwards.
        # Drawing it separately in each place would consume the RNG twice and
        # pad towards a different number than the one the budget was fitted to.
        drawn = self.normalizer.target_ms(command, session.session_id)

        result = self.terminal.resolve(session, command,  # type: ignore[union-attr]
                                       target_ms=drawn[0])

        # Everything above is internal cost; everything the attacker can
        # measure is decided here. `compute_ms` stays for diagnostics, but the
        # figure that matters -- and the one chapter 4 analyses -- is the
        # observed latency after normalisation.
        compute_ms = result.total_ms
        norm = self.normalizer.settle(command, session.session_id, compute_ms,
                                      route=result.route, drawn=drawn)
        observed_ms = compute_ms + norm.slept_ms

        from core.session import Turn  # local import keeps the module graph flat
        session.record(Turn(command=command, output=result.output,
                            route=result.route, latency_ms=observed_ms))

        if command.strip():
            self.alerts.command_executed(  # type: ignore[union-attr]
                session, command, result.output, result.route, observed_ms)
            emit_latency(
                session_id=session.session_id,
                command=command,
                route=result.route,
                total_ms=observed_ms,
                llm_ms=result.llm_ms,
                eval_tokens=result.eval_tokens,
                handler=result.handler,
                src_ip=session.src_ip,
                compute_ms=round(compute_ms, 3),
                **norm.as_telemetry(),
            )
            if observed_ms > config.LATENCY_TARGET_MS:
                self.alerts.latency_breach(  # type: ignore[union-attr]
                    session, command, observed_ms, config.LATENCY_TARGET_MS)
            if not result.llm_ok:
                self.alerts.inference_degraded(  # type: ignore[union-attr]
                    str(result.meta.get("error")))

        return {
            "output": result.output,
            "route": result.route,
            "handler": result.handler,
            "total_ms": round(observed_ms, 3),
            "compute_ms": round(compute_ms, 3),
            "llm_ms": round(result.llm_ms, 3),
            "eval_tokens": result.eval_tokens,
            # The generative cost split and the budget that shaped it: the
            # benchmark stratifies on these to show whether an overrun came
            # from prompt evaluation or from generation.
            "prompt_eval_ms": result.meta.get("prompt_eval_ms", 0.0),
            "eval_ms": result.meta.get("eval_ms", 0.0),
            "gen_max_tokens": result.meta.get("gen_max_tokens"),
            "gen_lean_context": result.meta.get("gen_lean_context"),
            "gen_feasible": result.meta.get("gen_feasible"),
            "gen_projected_ms": result.meta.get("gen_projected_ms"),
            "cwd": session.cwd,
            "prompt": self.prompt(session_id),
            "within_target": observed_ms <= config.LATENCY_TARGET_MS,
            "normalization": norm.as_telemetry(),
        }

    def close_session(self, session_id: str, reason: str = "client_disconnect") -> dict[str, Any] | None:
        session = self.sessions.close(session_id)
        if session is None:
            return None
        summary = session.summary()
        self.alerts.session_closed(session, reason)  # type: ignore[union-attr]
        return summary

    # -- introspection -----------------------------------------------------
    def stats(self) -> dict[str, Any]:
        active = self.sessions.active()
        return {
            "ready": self.ready,
            "model": self.llm.model,
            "llm_reachable": self.llm.is_ready(),
            "boot_ms": round(self.boot_ms, 1),
            "persona": {
                "hostname": self.persona.hostname if self.persona else None,
                "company": self.persona.company if self.persona else None,
                "source": self.persona.generated_by if self.persona else None,
            },
            "artifacts": {
                "fs_nodes": len(self.artifacts.fs.nodes) if self.artifacts else 0,
                "honeytokens": len(self.artifacts.honeytokens) if self.artifacts else 0,
            },
            "sessions_active": len(active),
            "commands_total": sum(len(s.transcript) for s in active),
            "latency_target_ms": config.LATENCY_TARGET_MS,
            "latency_normalization": {
                "enabled": self.normalizer.enabled,
                "generation_budget": self.gen_budget.as_dict(),
                **self.normalizer.stats.as_dict(),
            },
        }
