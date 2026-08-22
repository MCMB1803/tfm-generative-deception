"""Per-container CPU and memory sampler.

Chapter 4 has to report what the framework actually costs to run, not just how
fast it answers. `docker stats` shows that live but keeps no history, so this
samples it on an interval and writes both the raw series and an aggregate.

Run it alongside the latency benchmark, so the resource figures describe the
machine under the same load that produced the timings:

    python benchmarks/resource_monitor.py --duration 300 &
    python benchmarks/latency_benchmark.py --repeat 5 --scenario both

The interesting number is not the mean but the peak: a honeypot that answers
in 50 ms on an idle host and swaps under three concurrent sessions has not
solved the latency problem, it has only measured it politely.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

# The stack's containers. Anything else running on the host is ignored: the
# report describes this framework's footprint, not the machine's.
CONTAINERS = ["ollama_llm", "deception_agent", "honeypot_ssh"]

_FORMAT = "{{.Name}};{{.CPUPerc}};{{.MemUsage}};{{.MemPerc}};{{.NetIO}};{{.BlockIO}}"


def _to_mib(text: str) -> float:
    """Parse a docker stats size ('123.4MiB', '1.5GiB') into MiB."""
    text = text.strip()
    units = {"B": 1 / (1024 * 1024), "KiB": 1 / 1024, "MiB": 1.0,
             "GiB": 1024.0, "TiB": 1024.0 * 1024}
    for suffix, factor in sorted(units.items(), key=lambda kv: -len(kv[0])):
        if text.endswith(suffix):
            try:
                return float(text[: -len(suffix)]) * factor
            except ValueError:
                return 0.0
    return 0.0


def sample() -> list[dict[str, Any]]:
    """One reading of every container in the stack."""
    try:
        out = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", _FORMAT],
            capture_output=True, text=True, timeout=30, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: no se pudo ejecutar 'docker stats': {exc}", file=sys.stderr)
        return []

    if out.returncode != 0:
        print(f"ERROR: docker stats devolvio {out.returncode}: {out.stderr.strip()}",
              file=sys.stderr)
        return []

    stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    rows = []
    for line in out.stdout.strip().splitlines():
        parts = line.split(";")
        if len(parts) < 4:
            continue
        name, cpu, mem_usage, mem_pct = parts[0], parts[1], parts[2], parts[3]
        if name not in CONTAINERS:
            continue
        used = mem_usage.split("/")[0]
        rows.append({
            "timestamp": stamp,
            "container": name,
            "cpu_pct": float(cpu.rstrip("%") or 0),
            "mem_mib": round(_to_mib(used), 2),
            "mem_pct": float(mem_pct.rstrip("%") or 0),
            "net_io": parts[4] if len(parts) > 4 else "",
            "block_io": parts[5] if len(parts) > 5 else "",
        })
    return rows


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_container: dict[str, Any] = {}
    for name in CONTAINERS:
        subset = [r for r in rows if r["container"] == name]
        if not subset:
            by_container[name] = {"samples": 0}
            continue
        cpu = [r["cpu_pct"] for r in subset]
        mem = [r["mem_mib"] for r in subset]
        by_container[name] = {
            "samples": len(subset),
            "cpu_mean_pct": round(statistics.mean(cpu), 2),
            "cpu_max_pct": round(max(cpu), 2),
            "cpu_stdev_pct": round(statistics.stdev(cpu), 2) if len(cpu) > 1 else 0.0,
            "mem_mean_mib": round(statistics.mean(mem), 1),
            "mem_max_mib": round(max(mem), 1),
        }
    totals = {}
    stamps = sorted({r["timestamp"] for r in rows})
    if stamps:
        # Sum across containers at each instant, then take the worst instant:
        # the peak that matters is the simultaneous one, not the sum of peaks
        # each container reached at some unrelated moment.
        per_instant_cpu, per_instant_mem = [], []
        for st in stamps:
            at = [r for r in rows if r["timestamp"] == st]
            per_instant_cpu.append(sum(r["cpu_pct"] for r in at))
            per_instant_mem.append(sum(r["mem_mib"] for r in at))
        totals = {
            "cpu_mean_pct": round(statistics.mean(per_instant_cpu), 2),
            "cpu_max_pct": round(max(per_instant_cpu), 2),
            "mem_mean_mib": round(statistics.mean(per_instant_mem), 1),
            "mem_max_mib": round(max(per_instant_mem), 1),
        }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "samples": len(rows),
        "instants": len(stamps),
        "by_container": by_container,
        "stack_total": totals,
    }


def write_markdown(summary: dict[str, Any], path: str) -> None:
    t = summary["stack_total"]
    lines = [
        "# Consumo de recursos por contenedor",
        "",
        f"Generado automaticamente por `benchmarks/resource_monitor.py` el "
        f"{summary['generated_at']}. **No editar a mano**: se regenera en cada ejecucion.",
        "",
        f"Instantes muestreados: **{summary['instants']}** "
        f"({summary['samples']} lecturas de contenedor).",
        "",
        "| Contenedor | Muestras | CPU media | CPU maxima | Desv. tip. CPU | RAM media | RAM maxima |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, a in summary["by_container"].items():
        if not a.get("samples"):
            lines.append(f"| `{name}` | 0 | — | — | — | — | — | ")
            continue
        lines.append(
            f"| `{name}` | {a['samples']} | {a['cpu_mean_pct']} % | {a['cpu_max_pct']} % | "
            f"{a['cpu_stdev_pct']} % | {a['mem_mean_mib']} MiB | {a['mem_max_mib']} MiB |")
    if t:
        lines.append(
            f"| **Pila completa** | {summary['instants']} | {t['cpu_mean_pct']} % | "
            f"{t['cpu_max_pct']} % | — | {t['mem_mean_mib']} MiB | {t['mem_max_mib']} MiB |")
    lines += [
        "",
        "El total de la pila se calcula sumando los contenedores **en cada instante** "
        "y tomando despues el peor instante, no sumando el maximo que alcanzo cada "
        "contenedor por separado: esos picos pueden no haber coincidido nunca.",
        "",
        "> El porcentaje de CPU que reporta Docker esta normalizado al total de "
        "nucleos: 100 % equivale a un nucleo saturado, no a la maquina entera.",
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Muestreo de CPU y memoria por contenedor")
    parser.add_argument("--duration", type=float, default=120,
                        help="segundos de muestreo (0 = hasta Ctrl+C)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="segundos entre muestras")
    parser.add_argument("--outdir", default="benchmarks/results")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    rows: list[dict[str, Any]] = []
    start = time.time()
    print(f"Muestreando cada {args.interval} s"
          + (f" durante {args.duration:.0f} s" if args.duration else " hasta Ctrl+C")
          + " ... (Ctrl+C para parar antes)")

    try:
        while True:
            batch = sample()
            if not batch and not rows:
                print("ERROR: ningun contenedor de la pila responde. "
                      "Levanta la pila con 'docker compose up -d'.", file=sys.stderr)
                return 1
            rows.extend(batch)
            elapsed = time.time() - start
            print(f"\r  {len(rows)} lecturas / {elapsed:.0f} s", end="", flush=True)
            if args.duration and elapsed >= args.duration:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nInterrumpido; se escribe lo muestreado hasta ahora.")

    print()
    if not rows:
        print("Sin muestras.", file=sys.stderr)
        return 1

    csv_path = os.path.join(args.outdir, "resources_samples.csv")
    json_path = os.path.join(args.outdir, "resources_summary.json")
    md_path = os.path.join(args.outdir, "RESOURCES.md")

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = summarise(rows)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    write_markdown(summary, md_path)

    t = summary["stack_total"]
    print(f"\nEscrito en {args.outdir}: resources_samples.csv, "
          f"resources_summary.json, RESOURCES.md")
    if t:
        print(f"Pila completa -> CPU media {t['cpu_mean_pct']} % "
              f"(pico {t['cpu_max_pct']} %), RAM media {t['mem_mean_mib']} MiB "
              f"(pico {t['mem_max_mib']} MiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
