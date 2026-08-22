"""Latency and fidelity benchmark.

Produces the measured numbers behind chapter 4 of the report. Nothing here is
estimated: it drives the real orchestrator over the real API, records every
timing, and writes both the raw samples and the aggregate table to disk.

Two scenarios:

  recon   -- the MITRE-aligned reconnaissance sequence declared in the TFM
             scope (T1082, T1083, T1087 and neighbours), one session,
             executed in order, so session coherence is exercised too.
  cold    -- the same commands each in a *fresh* session, which measures the
             cost of an attacker who connects, runs one command and leaves.

Usage (from the host, with the stack up):

    python benchmarks/latency_benchmark.py --repeat 5
    python benchmarks/latency_benchmark.py --api http://localhost:8000 --repeat 10

The orchestrator API is published on 127.0.0.1:8000 for exactly this
purpose (loopback only -- it is never reachable from the attacker network).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests

# (command, ATT&CK id, what a correct answer must contain)
RECON_SEQUENCE: list[tuple[str, str, list[str]]] = [
    ("whoami",                      "T1033",     ["root"]),
    ("id",                          "T1033",     ["uid=0", "root"]),
    ("hostname",                    "T1082",     []),
    ("uname -a",                    "T1082",     ["Linux", "x86_64"]),
    ("cat /etc/os-release",         "T1082",     ["Ubuntu", "22.04"]),
    ("pwd",                         "T1083",     ["/root"]),
    ("ls -la",                      "T1083",     ["total"]),
    ("ls -la /var/www",             "T1083",     []),
    ("cat /etc/passwd",             "T1087.001", ["root:x:0:0", "/bin/bash"]),
    ("cat /etc/shadow",             "T1087.001", ["root:$6$"]),
    ("cat /etc/group",              "T1087.001", ["sudo:x:27"]),
    ("ps aux",                      "T1057",     ["USER", "PID", "nginx"]),
    ("ip a",                        "T1016",     ["eth0", "inet"]),
    ("netstat -tulpn",              "T1016",     ["LISTEN"]),
    ("cat /etc/hosts",              "T1016",     ["127.0.0.1", "localhost"]),
    ("df -h",                       "T1082",     ["Filesystem", "/dev/sda"]),
    ("free -h",                     "T1082",     ["Mem:", "Swap:"]),
    ("history",                     "T1552.001", []),
    ("cat /root/.bash_history",     "T1552.001", []),
    ("ls -la /root/.ssh",           "T1552.004", ["id_rsa"]),
    ("cat /root/.ssh/id_rsa",       "T1552.004", ["PRIVATE KEY"]),
    ("cat /root/.my.cnf",           "T1552.001", ["password"]),
    ("crontab -l",                  "T1053.003", []),
    ("cat /etc/crontab",            "T1053.003", ["SHELL", "PATH"]),
    ("tail -20 /var/log/auth.log",  "T1005",     []),
    ("cat /etc/passwd | grep bash", "T1087.001", ["root"]),
    ("sudo -l",                     "T1548.003", ["may run"]),
    ("which nmap",                  "T1046",     []),
    ("uptime",                      "T1082",     ["load average"]),
    ("lscpu",                       "T1082",     ["Architecture"]),
]

# Commands deliberately outside the deterministic layer, so the generative
# route is measured too. Without this set the benchmark would report the
# latency of the fast path only, which would overstate the system's
# performance -- the LLM cost has to appear in the results.
#
# Fidelity assertions here are loose by necessity: the output is invented per
# run, so only structural markers can be asserted objectively. The realism of
# these outputs is assessed qualitatively in chapter 4, not scored here.
GENERATIVE_SEQUENCE: list[tuple[str, str, list[str]]] = [
    ("systemctl status nginx",              "T1057",     []),
    ("journalctl -u nginx -n 10",           "T1005",     []),
    ("dpkg -l",                             "T1082",     []),
    ("top -bn1",                            "T1057",     []),
    ("iptables -L -n",                      "T1016",     []),
    ("find /var/www -name '*.php'",         "T1083",     []),
    ("du -sh /var/log",                     "T1083",     []),
    ("stat /etc/passwd",                    "T1083",     []),
    ("curl -I http://127.0.0.1",            "T1105",     []),
    ("apt list --installed",                "T1082",     []),
]

SUITES = {"recon": RECON_SEQUENCE, "generative": GENERATIVE_SEQUENCE}


class BenchmarkClient:
    def __init__(self, api: str) -> None:
        self.api = api.rstrip("/")
        self.http = requests.Session()

    def wait_ready(self, timeout: float = 600) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = self.http.get(f"{self.api}/health", timeout=5)
                if r.status_code == 200 and r.json().get("ready"):
                    return True
            except requests.RequestException:
                pass
            print("  esperando al orquestador...", flush=True)
            time.sleep(5)
        return False

    def stats(self) -> dict[str, Any]:
        return self.http.get(f"{self.api}/stats", timeout=10).json()

    def open(self) -> str:
        r = self.http.post(f"{self.api}/session/open",
                           json={"src_ip": "10.42.99.99", "src_port": 54321}, timeout=30)
        r.raise_for_status()
        sid = r.json()["session_id"]
        self.http.post(f"{self.api}/session/auth",
                       json={"session_id": sid, "username": "root",
                             "password": "benchmark"}, timeout=30)
        return sid

    def run(self, sid: str, command: str) -> dict[str, Any]:
        # Measure end-to-end from the caller's side: this is what the attacker
        # experiences, and it includes the API hop the SSH decoy also pays.
        start = time.perf_counter()
        r = self.http.post(f"{self.api}/session/command",
                           json={"session_id": sid, "command": command}, timeout=120)
        wall_ms = (time.perf_counter() - start) * 1000
        r.raise_for_status()
        data = r.json()
        data["wall_ms"] = wall_ms
        return data

    def close(self, sid: str) -> None:
        try:
            self.http.post(f"{self.api}/session/close",
                           json={"session_id": sid, "reason": "benchmark"}, timeout=30)
        except requests.RequestException:
            pass


def check_fidelity(output: str, expected: list[str]) -> tuple[bool, list[str]]:
    """Substring assertions, not judgement calls: reproducible by a third party."""
    missing = [token for token in expected if token not in output]
    return (not missing), missing


def run_scenario(client: BenchmarkClient, scenario: str, repeat: int,
                 verbose: bool, suites: list[str]) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    sequence = [(suite, *entry) for suite in suites for entry in SUITES[suite]]

    for iteration in range(1, repeat + 1):
        print(f"[{scenario}] iteracion {iteration}/{repeat}", flush=True)
        sid = client.open() if scenario == "recon" else None

        for suite, command, technique, expected in sequence:
            if scenario == "cold":
                sid = client.open()
            try:
                result = client.run(sid, command)  # type: ignore[arg-type]
            except requests.RequestException as exc:
                print(f"  ! fallo en '{command}': {exc}")
                if scenario == "cold":
                    client.close(sid)  # type: ignore[arg-type]
                continue

            passed, missing = check_fidelity(result.get("output", ""), expected)
            samples.append({
                "scenario": scenario,
                "suite": suite,
                "iteration": iteration,
                "command": command,
                "technique": technique,
                "route": result.get("route"),
                "handler": result.get("handler"),
                "server_ms": result.get("total_ms", 0.0),
                "llm_ms": result.get("llm_ms", 0.0),
                "wall_ms": round(result["wall_ms"], 3),
                "eval_tokens": result.get("eval_tokens", 0),
                "within_target": result.get("within_target", False),
                "fidelity_pass": passed,
                "fidelity_missing": ";".join(missing),
                "output_bytes": len(result.get("output", "").encode()),
            })

            if verbose:
                status = "OK " if passed else "FAIL"
                print(f"  {status} {command:<32} {result.get('route','?'):<13} "
                      f"{result['wall_ms']:>8.1f} ms")

            if scenario == "cold":
                client.close(sid)  # type: ignore[arg-type]

        if scenario == "recon":
            client.close(sid)  # type: ignore[arg-type]

    return samples


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def summarise(samples: list[dict[str, Any]], target_ms: float) -> dict[str, Any]:
    def agg(subset: list[dict[str, Any]]) -> dict[str, Any]:
        if not subset:
            return {"n": 0}
        wall = [s["wall_ms"] for s in subset]
        return {
            "n": len(subset),
            "mean_ms": round(statistics.fmean(wall), 1),
            "median_ms": round(statistics.median(wall), 1),
            "stdev_ms": round(statistics.stdev(wall), 1) if len(wall) > 1 else 0.0,
            "min_ms": round(min(wall), 1),
            "max_ms": round(max(wall), 1),
            "p95_ms": round(percentile(wall, 95), 1),
            "p99_ms": round(percentile(wall, 99), 1),
            "within_target_pct": round(
                100 * sum(1 for s in subset if s["wall_ms"] <= target_ms) / len(subset), 1),
            "fidelity_pass_pct": round(
                100 * sum(1 for s in subset if s["fidelity_pass"]) / len(subset), 1),
        }

    deterministic = [s for s in samples if s["route"] == "deterministic"]
    generative = [s for s in samples if s["route"] == "generative"]

    by_command: dict[str, dict[str, Any]] = {}
    for command, technique, _ in RECON_SEQUENCE + GENERATIVE_SEQUENCE:
        subset = [s for s in samples if s["command"] == command]
        if subset:
            by_command[command] = {"technique": technique,
                                   "route": subset[0]["route"], **agg(subset)}

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target_ms": target_ms,
        "overall": agg(samples),
        "deterministic": agg(deterministic),
        "generative": agg(generative),
        "route_split": {
            "deterministic_pct": round(100 * len(deterministic) / len(samples), 1) if samples else 0,
            "generative_pct": round(100 * len(generative) / len(samples), 1) if samples else 0,
        },
        "by_command": by_command,
    }


def write_markdown(summary: dict[str, Any], samples: list[dict[str, Any]], path: str) -> None:
    o, d, g = summary["overall"], summary["deterministic"], summary["generative"]
    lines = [
        "# Resultados medidos de latencia y fidelidad",
        "",
        f"Generado automaticamente por `benchmarks/latency_benchmark.py` el "
        f"{summary['generated_at']}. **No editar a mano**: se regenera en cada ejecucion.",
        "",
        f"Objetivo de latencia: **{summary['target_ms']:.0f} ms**. "
        f"Muestras totales: **{o['n']}**.",
        "",
        "## 1. Resumen global",
        "",
        "| Ruta | n | Media | Mediana | Desv. tip. | Min | Max | p95 | p99 | Dentro de objetivo | Fidelidad |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for label, a in (("**Global**", o), ("Determinista", d), ("Generativa", g)):
        if a.get("n"):
            lines.append(
                f"| {label} | {a['n']} | {a['mean_ms']} ms | {a['median_ms']} ms | "
                f"{a['stdev_ms']} ms | {a['min_ms']} ms | {a['max_ms']} ms | "
                f"{a['p95_ms']} ms | {a['p99_ms']} ms | {a['within_target_pct']} % | "
                f"{a['fidelity_pass_pct']} % |")

    split = summary["route_split"]
    lines += [
        "",
        f"Reparto de rutas: **{split['deterministic_pct']} %** determinista, "
        f"**{split['generative_pct']} %** generativa.",
        "",
        "## 2. Detalle por comando",
        "",
        "| Comando | Tecnica ATT&CK | Ruta | n | Media | p95 | Dentro de objetivo | Fidelidad |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for command, a in summary["by_command"].items():
        lines.append(
            f"| `{command}` | {a['technique']} | {a['route']} | {a['n']} | "
            f"{a['mean_ms']} ms | {a['p95_ms']} ms | {a['within_target_pct']} % | "
            f"{a['fidelity_pass_pct']} % |")

    failures = [s for s in samples if not s["fidelity_pass"]]
    if failures:
        seen: set[tuple[str, str]] = set()
        lines += ["", "## 3. Fallos de fidelidad observados", "",
                  "| Comando | Tokens ausentes en la salida |", "|---|---|"]
        for s in failures:
            key = (s["command"], s["fidelity_missing"])
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"| `{s['command']}` | {s['fidelity_missing']} |")
    else:
        lines += ["", "## 3. Fallos de fidelidad observados", "",
                  "Ninguno: todas las salidas contienen los tokens esperados."]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark de latencia y fidelidad")
    parser.add_argument("--api", default=os.getenv("AGENT_API", "http://localhost:8000"))
    parser.add_argument("--repeat", type=int, default=3,
                        help="iteraciones completas de la secuencia")
    parser.add_argument("--scenario", choices=["recon", "cold", "both"], default="recon")
    parser.add_argument("--suite", choices=["recon", "generative", "both"], default="both",
                        help="bateria de comandos: reconocimiento (ruta determinista), "
                             "generativa (ruta LLM) o ambas")
    parser.add_argument("--outdir", default="benchmarks/results")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    client = BenchmarkClient(args.api)
    print(f"Conectando al orquestador en {args.api} ...")
    if not client.wait_ready():
        print("ERROR: el orquestador no esta listo.", file=sys.stderr)
        return 1

    stats = client.stats()
    target_ms = float(stats.get("latency_target_ms", 1000))
    print(f"Modelo: {stats.get('model')} | persona: {stats['persona']['hostname']} "
          f"({stats['persona']['source']}) | objetivo: {target_ms:.0f} ms\n")

    scenarios = ["recon", "cold"] if args.scenario == "both" else [args.scenario]
    suites = ["recon", "generative"] if args.suite == "both" else [args.suite]
    samples: list[dict[str, Any]] = []
    for scenario in scenarios:
        samples += run_scenario(client, scenario, args.repeat, not args.quiet, suites)

    if not samples:
        print("ERROR: no se recogio ninguna muestra.", file=sys.stderr)
        return 1

    summary = summarise(samples, target_ms)
    summary["environment"] = {
        "model": stats.get("model"),
        "persona": stats["persona"],
        "scenarios": scenarios,
        "suites": suites,
        "repeat": args.repeat,
    }

    os.makedirs(args.outdir, exist_ok=True)
    csv_path = os.path.join(args.outdir, "latency_samples.csv")
    json_path = os.path.join(args.outdir, "latency_summary.json")
    md_path = os.path.join(args.outdir, "RESULTS.md")

    with open(csv_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(samples[0].keys()))
        writer.writeheader()
        writer.writerows(samples)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    write_markdown(summary, samples, md_path)

    o = summary["overall"]
    print("\n" + "=" * 68)
    print(f"Muestras: {o['n']}   media {o['mean_ms']} ms   mediana {o['median_ms']} ms   "
          f"p95 {o['p95_ms']} ms")
    print(f"Dentro del objetivo ({target_ms:.0f} ms): {o['within_target_pct']} %   "
          f"Fidelidad: {o['fidelity_pass_pct']} %")
    print(f"Rutas: {summary['route_split']['deterministic_pct']} % determinista / "
          f"{summary['route_split']['generative_pct']} % generativa")
    print("=" * 68)
    print(f"\nEscrito:\n  {csv_path}\n  {json_path}\n  {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
