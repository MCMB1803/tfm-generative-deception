"""Validates the Wazuh rules against real events from the framework.

Writing correlation rules and asserting in the report that they "would fire" is
not a result. This feeds actual events -- taken from the framework's own event
log whenever one of the required type exists -- through `wazuh-logtest` inside
the running manager, and checks that each one triggers the rule id and alert
level the design claims it does.

    docker compose --profile siem up -d
    python siem/validate_rules.py

Writes benchmarks/results/SIEM_VALIDATION.md. Exit code 0 only if every case
matched, so the check can gate a build.

Why logtest instead of a dashboard screenshot: it is reproducible by a third
party, it produces text evidence that can go in an annex, and it verifies the
rule *and* the level rather than just showing that something appeared on a
screen.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

CONTAINER = os.getenv("WAZUH_CONTAINER", "wazuh_manager")
EVENT_LOG_IN_MANAGER = "/deception/logs/deception-events.jsonl"

_RULE_RE = re.compile(r"id:\s*'(\d+)'")
_LEVEL_RE = re.compile(r"[Ll]evel:\s*'?(\d+)'?")


@dataclass
class Case:
    """One event type and the rule the design says must fire for it."""

    name: str
    expect_rule: str
    expect_level: int
    why: str
    match: dict[str, Any] = field(default_factory=dict)
    synthetic: dict[str, Any] | None = None


# The rule for a sustained interactive session (100220) fires on frequency, not
# on a single event, so it is exercised separately by replaying a burst.
CASES = [
    Case("session.opened", "100201", 12,
         "Toda conexion al senuelo es no autorizada por construccion.",
         match={"event_type": "session.opened"}),
    Case("auth.attempt", "100202", 12,
         "Credenciales capturadas en claro.",
         match={"event_type": "auth.attempt"}),
    Case("command.executed (severidad baja)", "100210", 8,
         "Comando sin clasificacion de riesgo elevado.",
         match={"event_type": "command.executed", "severity": "low"}),
    Case("command.executed (severidad alta)", "100211", 12,
         "Reconocimiento avanzado segun la clasificacion ATT&CK.",
         match={"event_type": "command.executed", "severity": "high"}),
    Case("command.executed (severidad critica)", "100212", 14,
         "Acceso a credenciales o evasion.",
         # Sin honeytoken a proposito: un comando critico que ademas lee uno
         # dispara con razon la 100213, que es mas especifica y de mayor nivel.
         # Exigir aqui la 100212 sin excluirlo seria un fallo del caso de
         # prueba, no del conjunto de reglas.
         match={"event_type": "command.executed", "severity": "critical",
                "_no_honeytoken": True},
         synthetic={"event_type": "command.executed", "severity": "critical",
                    "wazuh_level": 14, "confidence": "confirmed",
                    "description": "Comando ejecutado por el atacante en el senuelo",
                    "session_id": "1111111111111111", "src_ip": "10.42.99.50",
                    "username": "root", "command": "cat /etc/shadow",
                    "cwd": "/root", "response_route": "deterministic"}),
    Case("honeytoken leido", "100213", 15,
         "La senal de mayor valor del sistema: un artefacto trampa exfiltrado.",
         match={"event_type": "command.executed", "_has_honeytoken": True}),
    Case("system.inference_degraded", "100230", 8,
         "El motor de inferencia no responde; el senuelo puede haberse vuelto detectable.",
         match={"event_type": "system.inference_degraded"},
         synthetic={"event_type": "system.inference_degraded", "severity": "medium",
                    "wazuh_level": 8, "confidence": "operational",
                    "description": "Motor de inferencia no disponible",
                    "error": "connection refused"}),
    Case("system.latency_breach", "100231", 7,
         "Respuesta por encima del objetivo: riesgo de fingerprinting temporal.",
         match={"event_type": "system.latency_breach"}),
    Case("escaneo autorizado descartado", "100290", 0,
         "Condicion de contorno de la afirmacion de cero falsos positivos: el "
         "escaner corporativo genera session.opened y no debe alertar.",
         match={"event_type": "session.opened"},
         synthetic={"event_type": "session.opened", "severity": "high",
                    "wazuh_level": 12, "confidence": "confirmed",
                    "description": "Conexion entrante al senuelo",
                    "session_id": "0000000000000000", "src_ip": "10.42.0.10",
                    "src_port": 44112}),
]


def install_rules() -> bool:
    """Copy the framework's rules into the manager and reload the analysis engine.

    Done here rather than with a bind mount because mounting anything inside
    /var/ossec/etc stops the container from installing its default ossec.conf
    on first boot, leaving the manager without a configuration at all.
    """
    steps = [
        ["cp", "/deception-rules/local_rules.xml", "/var/ossec/etc/rules/local_rules.xml"],
        ["chown", "wazuh:wazuh", "/var/ossec/etc/rules/local_rules.xml"],
    ]
    for step in steps:
        r = subprocess.run(["docker", "exec", CONTAINER] + step,
                           capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
        if r.returncode != 0:
            print(f"ERROR instalando las reglas: {r.stderr.strip()}", file=sys.stderr)
            return False

    r = subprocess.run(["docker", "exec", CONTAINER,
                        "/var/ossec/bin/wazuh-control", "restart"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, check=False)
    if "analysisd" in r.stdout and "Started" not in r.stdout and r.returncode != 0:
        print(f"ERROR reiniciando el manager: {r.stdout}{r.stderr}", file=sys.stderr)
        return False
    # Tras el reinicio, analysisd tarda unos segundos en aceptar conexiones en
    # su socket. Sin esta espera, logtest devuelve vacio y todas las reglas
    # parecen no dispararse, que es un falso negativo del arnes, no del SIEM.
    for attempt in range(30):
        probe = logtest(['{"product": "generative-deception-framework", '
                         '"event_type": "system.ready", "timestamp": "x"}'])
        if "Phase 3" in probe:
            print(f"Reglas instaladas y motor de analisis recargado "
                  f"(listo en {attempt + 1} intentos).")
            return True
        time.sleep(3)
    print("ERROR: analysisd no acepta conexiones tras el reinicio.", file=sys.stderr)
    return False


def read_events(path: str, limit: int = 5000) -> list[dict[str, Any]]:
    """Real events straight from the framework's log inside the manager."""
    out = subprocess.run(
        ["docker", "exec", CONTAINER, "sh", "-c", f"tail -n {limit} {path} 2>/dev/null"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    events = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def pick(events: list[dict[str, Any]], spec: dict[str, Any]) -> dict[str, Any] | None:
    for ev in events:
        ok = True
        for key, want in spec.items():
            if key == "_has_honeytoken":
                if not ev.get("honeytokens"):
                    ok = False
                    break
                continue
            if key == "_no_honeytoken":
                if ev.get("honeytokens"):
                    ok = False
                    break
                continue
            if ev.get(key) != want:
                ok = False
                break
        if ok:
            return ev
    return None


def logtest(lines: list[str]) -> str:
    """Run wazuh-logtest over one or more log lines in a single session.

    A single session matters for the frequency rule: the correlation state that
    counts repeated events lives in the running logtest session.
    """
    payload = "\n".join(lines) + "\n"
    out = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "/var/ossec/bin/wazuh-logtest", "-v"],
        input=payload, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180, check=False)
    return out.stdout + out.stderr


def last_verdict(output: str) -> tuple[str | None, int | None]:
    """Rule id and level of the final decision in a logtest output block."""
    # Take the last match: logtest prints the candidate chain and ends with the
    # rule that actually fired.
    rules = _RULE_RE.findall(output)
    levels = _LEVEL_RE.findall(output)
    return (rules[-1] if rules else None,
            int(levels[-1]) if levels else None)


def split_blocks(output: str) -> list[str]:
    """One block per input line fed to logtest."""
    parts = re.split(r"\n(?=\*\*Phase 1:)", output)
    return [p for p in parts if "Phase" in p]


def main() -> int:
    parser = argparse.ArgumentParser(description="Valida las reglas de Wazuh con eventos reales")
    parser.add_argument("--outdir", default="benchmarks/results")
    parser.add_argument("--events", default=EVENT_LOG_IN_MANAGER)
    parser.add_argument("--no-install", action="store_true",
                        help="no reinstalar las reglas antes de validar")
    args = parser.parse_args()

    probe = subprocess.run(["docker", "exec", CONTAINER, "true"],
                           capture_output=True, check=False)
    if probe.returncode != 0:
        print(f"ERROR: el contenedor '{CONTAINER}' no responde. Arranca el SIEM con:\n"
              f"  docker compose --profile siem up -d", file=sys.stderr)
        return 1

    if not args.no_install and not install_rules():
        return 1

    events = read_events(args.events)
    print(f"Eventos reales disponibles: {len(events)}")

    results = []
    for case in CASES:
        real = pick(events, case.match) if case.match else None
        # The exclusion case and the degraded-inference case need an event the
        # framework has not produced in this run; those are marked as synthetic
        # in the report rather than passed off as observed.
        force_synthetic = case.expect_rule == "100290"
        if case.synthetic is not None and (real is None or force_synthetic):
            event = dict(case.synthetic)
            event.setdefault("product", "generative-deception-framework")
            event.setdefault("timestamp",
                             datetime.now(timezone.utc).isoformat(timespec="milliseconds"))
            source = "sintetico"
        elif real is not None:
            event = real
            source = "real"
        else:
            results.append({"case": case, "source": "ausente", "rule": None,
                            "level": None, "ok": False,
                            "detail": "no se encontro ningun evento de este tipo"})
            print(f"  AUSENTE  {case.name}")
            continue

        out = logtest([json.dumps(event, ensure_ascii=False)])
        rule, level = last_verdict(out)
        ok = rule == case.expect_rule and level == case.expect_level
        results.append({"case": case, "source": source, "rule": rule, "level": level,
                        "ok": ok, "event": event,
                        "detail": "" if ok else f"disparo {rule} nivel {level}"})
        print(f"  {'OK      ' if ok else 'FALLO   '}{case.name}: "
              f"regla {rule} nivel {level} (esperado {case.expect_rule}/{case.expect_level})")

    # -- frequency rule: 10 commands in the same session within 300 s --------
    burst_source = pick(events, {"event_type": "command.executed"})
    freq = {"expected": "100220", "level": 13, "ok": False, "rule": None,
            "detail": "sin eventos command.executed para construir la rafaga"}
    if burst_source:
        burst = []
        for i in range(12):
            ev = dict(burst_source)
            ev["session_id"] = "ffffffffffffffff"
            ev["command_index"] = i
            burst.append(json.dumps(ev, ensure_ascii=False))
        out = logtest(burst)
        fired = _RULE_RE.findall(out)
        freq["rule"] = fired[-1] if fired else None
        freq["ok"] = "100220" in fired
        freq["detail"] = "" if freq["ok"] else f"reglas disparadas: {sorted(set(fired))}"
    print(f"  {'OK      ' if freq['ok'] else 'FALLO   '}sesion interactiva sostenida "
          f"(100220, por frecuencia)")

    os.makedirs(args.outdir, exist_ok=True)
    md = os.path.join(args.outdir, "SIEM_VALIDATION.md")
    write_report(results, freq, md, len(events))

    failed = [r for r in results if not r["ok"]] + ([] if freq["ok"] else [freq])
    print(f"\n{len(results) + 1 - len(failed)}/{len(results) + 1} reglas validadas")
    print(f"Escrito: {md}")
    return 1 if failed else 0


def write_report(results, freq, path: str, n_events: int) -> None:
    passed = sum(1 for r in results if r["ok"]) + (1 if freq["ok"] else 0)
    total = len(results) + 1
    lines = [
        "# Validacion de las reglas de correlacion en Wazuh",
        "",
        f"Generado automaticamente por `siem/validate_rules.py` el "
        f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}. "
        "**No editar a mano**: se regenera en cada ejecucion.",
        "",
        f"Resultado: **{passed}/{total}** reglas disparan el identificador y el nivel "
        f"que declara el diseno. Eventos reales disponibles en el log del "
        f"framework: **{n_events}**.",
        "",
        "Cada caso se comprueba pasando un evento por `wazuh-logtest` dentro del "
        "manager en ejecucion y leyendo la regla que finalmente dispara. Los "
        "eventos marcados como *real* proceden del log que el framework produjo "
        "durante las pruebas; los marcados como *sintetico* corresponden a "
        "condiciones que no se dieron en esta ejecucion y se construyen a mano, "
        "lo que se declara aqui en lugar de presentarlos como observados.",
        "",
        "| Caso | Origen | Regla esperada | Nivel | Disparo | Resultado |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        c = r["case"]
        got = f"{r['rule']} / {r['level']}" if r["rule"] else "—"
        lines.append(
            f"| {c.name} | {r['source']} | `{c.expect_rule}` | {c.expect_level} | "
            f"{got} | {'OK' if r['ok'] else '**FALLO**'} |")
    lines.append(
        f"| sesion interactiva sostenida | real (rafaga de 12) | `100220` | 13 | "
        f"{freq['rule'] or '—'} | {'OK' if freq['ok'] else '**FALLO**'} |")

    lines += ["", "## Por que cada regla existe", ""]
    for r in results:
        lines.append(f"* **{r['case'].expect_rule}** — {r['case'].name}: {r['case'].why}")
    lines.append("* **100220** — sesion interactiva sostenida: diez comandos en la "
                 "misma sesion en cinco minutos distinguen a un operador humano "
                 "de un escaner automatico.")

    failures = [r for r in results if not r["ok"]]
    if failures or not freq["ok"]:
        lines += ["", "## Fallos", ""]
        for r in failures:
            lines.append(f"* {r['case'].name}: {r['detail']}")
        if not freq["ok"]:
            lines.append(f"* sesion interactiva sostenida: {freq['detail']}")

    lines += [
        "",
        "## Alcance de esta validacion",
        "",
        "La regla **100212** no llega a dispararse con trafico real: en este "
        "framework todo comando de severidad critica accede a un fichero de "
        "credenciales, que es precisamente donde viven los honeytokens, de modo "
        "que la 100213 -- mas especifica y de mayor nivel -- la eclipsa siempre. "
        "Se valida con un evento sintetico, que demuestra que la regla es "
        "correcta cuando se alcanza, pero conviene saber que en explotacion "
        "normal no producira alertas propias.",
        "",
        "Se comprueba que el motor de analisis de Wazuh decodifica los eventos y "
        "dispara la regla correcta con el nivel correcto. **No** se comprueba el "
        "transporte desde el agente hasta el manager ni la visualizacion en el "
        "panel, que dependen del despliegue concreto y quedan fuera de lo que "
        "este contenedor puede acreditar.",
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
