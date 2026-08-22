"""Alert Agent -- turns decoy interactions into SOC-grade events.

Every interaction with this system is, by construction, unauthorised: no
legitimate user or process has any reason to reach a decoy host. That is the
zero-false-positive property claimed in section 1.2, and it is why the events
this agent emits carry a fixed high confidence rather than a heuristic score.

Output is JSON Lines on disk (see core.telemetry), shaped for direct ingestion
by Wazuh's JSON decoder or Filebeat. Severity follows the ATT&CK mapping in
core.mitre, escalated by session-level behaviour: an attacker who chains
discovery into credential access is scored above one who runs `ls` and leaves.
"""
from __future__ import annotations

import logging
from typing import Any

from core import mitre
from core.session import Session
from core.telemetry import emit_event

log = logging.getLogger("agent.alert")

# Severity -> the level fields a SOC console expects.
_LEVELS = [
    (9, "critical", 14),
    (7, "high", 12),
    (5, "medium", 8),
    (0, "low", 5),
]


def _level_for(severity: int) -> tuple[str, int]:
    for threshold, label, wazuh_level in _LEVELS:
        if severity >= threshold:
            return label, wazuh_level
    return "low", 5


class AlertAgent:
    """Emits and escalates SOC events for one deployment."""

    def __init__(self, honeytoken_matcher: Any = None) -> None:
        # Callable taking a string, returning a list of honeytoken records.
        self._match_honeytokens = honeytoken_matcher

    # -- lifecycle events --------------------------------------------------
    def session_opened(self, session: Session) -> dict[str, Any]:
        return emit_event(
            "session.opened",
            severity="high",
            wazuh_level=12,
            confidence="confirmed",
            description="Conexion entrante al servicio trampa SSH",
            session_id=session.session_id,
            src_ip=session.src_ip,
            src_port=session.src_port,
            dst_service="ssh-decoy",
        )

    def credentials_captured(self, session: Session, username: str,
                             password: str, method: str = "password") -> dict[str, Any]:
        return emit_event(
            "auth.attempt",
            severity="high",
            wazuh_level=12,
            confidence="confirmed",
            description="Intento de autenticacion contra el senuelo SSH",
            session_id=session.session_id,
            src_ip=session.src_ip,
            src_port=session.src_port,
            username=username,
            password=password,
            auth_method=method,
            mitre={"technique_id": "T1110", "technique": "Brute Force",
                   "tactic": "Credential Access"},
        )

    def command_executed(self, session: Session, command: str, output: str,
                         route: str, latency_ms: float) -> dict[str, Any]:
        classification = mitre.classify(command)
        severity_score = int(classification["severity"])

        honeytokens = []
        if self._match_honeytokens:
            # Check both what the attacker typed and what they were shown: a
            # credential read out of a config file is the moment it becomes
            # actionable intelligence.
            honeytokens = self._match_honeytokens(command) + self._match_honeytokens(output or "")
        if honeytokens:
            severity_score = max(severity_score, 9)

        session.techniques_seen.update(
            t["technique_id"] for t in classification["techniques"]  # type: ignore[index]
        )
        session.max_severity = max(session.max_severity, severity_score)

        label, wazuh_level = _level_for(severity_score)
        return emit_event(
            "command.executed",
            severity=label,
            wazuh_level=wazuh_level,
            severity_score=severity_score,
            confidence="confirmed",
            description="Comando ejecutado por el atacante en el senuelo",
            session_id=session.session_id,
            src_ip=session.src_ip,
            username=session.username,
            command=command,
            cwd=session.cwd,
            response_route=route,
            latency_ms=round(latency_ms, 2),
            output_preview=(output or "")[:400],
            mitre=classification["techniques"],
            honeytokens=[h["honeytoken_id"] for h in honeytokens] or None,
            command_index=len(session.transcript) + 1,
        )

    def session_closed(self, session: Session, reason: str = "client_disconnect") -> dict[str, Any]:
        label, wazuh_level = _level_for(session.max_severity)
        return emit_event(
            "session.closed",
            severity=label,
            wazuh_level=wazuh_level,
            confidence="confirmed",
            description="Sesion de atacante finalizada; resumen de la interaccion",
            reason=reason,
            **session.summary(),
        )

    # -- health / operational ---------------------------------------------
    def inference_degraded(self, error: str) -> dict[str, Any]:
        """Operational alert, not an intrusion alert: the SOC needs to know the
        decoy is answering from its fallback path and may be fingerprintable."""
        return emit_event(
            "system.inference_degraded",
            severity="medium",
            wazuh_level=8,
            confidence="operational",
            description="El motor de inferencia local no responde; ruta generativa degradada",
            error=error,
        )

    def latency_breach(self, session: Session, command: str, latency_ms: float,
                       target_ms: float) -> dict[str, Any]:
        """A response slow enough to expose the decoy by timing alone."""
        return emit_event(
            "system.latency_breach",
            severity="medium",
            wazuh_level=8,
            confidence="operational",
            description="Latencia por encima del objetivo; riesgo de fingerprinting temporal",
            session_id=session.session_id,
            command=command,
            latency_ms=round(latency_ms, 2),
            target_ms=target_ms,
        )
