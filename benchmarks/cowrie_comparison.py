"""Measured comparison between the generative decoy and Cowrie.

Section 4.4 of the report claims the generative framework buys coverage and
coherence at the price of latency and compute. That is a trade-off, and a
trade-off has a magnitude -- so it has to be measured rather than asserted.

The comparison is only meaningful if both systems are interrogated by the same
instrument, so this harness drives them through `evaluation.targets.SSHTarget`,
the very client the adversary-emulation harness uses: same library, same pty,
same read loop, same output extraction. The arms differ in the port they answer
on and nothing else. A third arm, the real Debian host, is included whenever it
is up, because "how far is each honeypot from a real host" is the question the
reader actually has.

Four axes, one per claim the report makes:

  Coverage.  Fraction of the battery that receives a plausible answer rather
             than "command not found", an empty body, or an error. This is
             where a fixed catalogue is expected to run out.

             Read this one against the real host, never on its own. A genuine
             Debian answers well under 100 % of the battery, because half of
             these paths legitimately do not exist on it -- there is no
             /root/.my.cnf, no crontab, no nmap. A decoy that answers
             *everything* is therefore not winning: it is exhibiting a tell no
             real system has. The metric that matters is `divergencia`, the
             number of commands where an arm disagrees with the real host
             about whether there is anything to show.

  Coherence. Every command is issued twice in the same session; the two bodies
             must match byte for byte after volatile fields are masked. A
             honeypot that answers differently to two reads of the same file
             is one `cat` away from being identified.

  Timing.    Time to first byte of output, not time to quiescence. This
             distinction is not pedantry: the shared SSH client waits out a
             1.2 s silence window before it will call a response complete,
             because latency normalisation makes the decoy pause for most of a
             second mid-answer. Timing to quiescence therefore measures that
             window and reports ~1240 ms for every arm including a bare
             Debian, which is an artefact of the instrument rather than a
             property of any system under test. First byte is what an
             adversary actually perceives.

  Compute.   CPU and memory sampled from the Docker API while the battery
             runs, so the cost is attributed to the arm that incurred it.

Usage (stack up, Cowrie under its profile):

    docker compose --profile compare up -d cowrie
    python benchmarks/cowrie_comparison.py
    python benchmarks/cowrie_comparison.py --repeat 2 --outdir benchmarks/results
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "evaluation"))

from targets import (  # noqa: E402
    SSHTarget, TargetSpec, _split_prompt, _strip_echo,
)
from transcript import strip_ansi  # noqa: E402

# The same thirty-command reconnaissance battery the latency bench uses, so
# the two chapters report over the same stimulus.
BATTERY: list[tuple[str, str]] = [
    ("whoami", "T1033"), ("id", "T1033"), ("hostname", "T1082"),
    ("uname -a", "T1082"), ("cat /etc/os-release", "T1082"), ("pwd", "T1083"),
    ("ls -la", "T1083"), ("ls -la /var/www", "T1083"),
    ("cat /etc/passwd", "T1087.001"), ("cat /etc/shadow", "T1087.001"),
    ("cat /etc/group", "T1087.001"), ("ps aux", "T1057"), ("ip a", "T1016"),
    ("netstat -tulpn", "T1016"), ("cat /etc/hosts", "T1016"),
    ("df -h", "T1082"), ("free -h", "T1082"), ("history", "T1552.001"),
    ("cat /root/.bash_history", "T1552.001"),
    ("ls -la /root/.ssh", "T1552.004"),
    ("cat /root/.ssh/id_rsa", "T1552.004"),
    ("cat /root/.my.cnf", "T1552.001"), ("crontab -l", "T1053.003"),
    ("cat /etc/crontab", "T1053.003"),
    ("tail -20 /var/log/auth.log", "T1005"),
    ("cat /etc/passwd | grep bash", "T1087.001"),
    ("sudo -l", "T1548.003"), ("which nmap", "T1046"),
    ("uptime", "T1082"), ("lscpu", "T1082"),
]

# What counts as "the system did not answer this". Deliberately generous to
# the traditional honeypot: only unmistakable non-answers are failures.
_MISS = re.compile(
    r"command not found|not found|no such file or directory|"
    r"unknown command|invalid|permission denied|bash:.*:.*error",
    re.IGNORECASE)

# Fields that legitimately differ between two reads a second apart. Masked
# before the coherence comparison so a real host is not penalised for telling
# the truth about the clock.
_VOLATILE = [
    (re.compile(r"\b\d{2}:\d{2}:\d{2}\b"), "<TIME>"),
    (re.compile(r"\bup\s+[^,]+,"), "up <UPTIME>,"),
    (re.compile(r"load average:.*$", re.MULTILINE), "load average: <LA>"),
    (re.compile(r"\b\d+\s+days?\b"), "<DAYS>"),
]


def mask(text: str) -> str:
    for pat, rep in _VOLATILE:
        text = pat.sub(rep, text)
    return text.strip()


def is_miss(body: str) -> bool:
    return not body.strip() or bool(_MISS.search(body))


class DockerSampler:
    """Samples CPU and memory of one container while the battery runs."""

    def __init__(self, container: str, every: float = 4.0) -> None:
        self.container = container
        self.every = every
        self.cpu: list[float] = []
        self.mem: list[float] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _sample(self) -> None:
        while not self._stop.is_set():
            try:
                out = subprocess.run(
                    ["docker", "stats", "--no-stream", "--format",
                     "{{.CPUPerc}};{{.MemUsage}}", self.container],
                    capture_output=True, text=True, timeout=20)
                line = out.stdout.strip()
                if line and ";" in line:
                    cpu_s, mem_s = line.split(";", 1)
                    self.cpu.append(float(cpu_s.strip().rstrip("%")))
                    val = mem_s.split("/")[0].strip()
                    num = float(re.sub(r"[^\d.]", "", val) or 0)
                    if "GiB" in val:
                        num *= 1024
                    elif "KiB" in val:
                        num /= 1024
                    self.mem.append(num)
            except Exception:  # noqa: BLE001 - sampling must never break a run
                pass
            self._stop.wait(self.every)

    def __enter__(self) -> "DockerSampler":
        self._thread = threading.Thread(target=self._sample, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)

    def summary(self) -> dict:
        def stat(xs: list[float]) -> dict:
            if not xs:
                return {"n": 0, "media": None, "maximo": None}
            return {"n": len(xs), "media": round(statistics.mean(xs), 1),
                    "maximo": round(max(xs), 1)}
        return {"cpu_pct": stat(self.cpu), "mem_mib": stat(self.mem)}


def run_timed(target: SSHTarget, command: str) -> tuple[str, float, bool]:
    """Issue one command; return its body and the time to its first byte.

    The channel echoes the command line back before the answer starts, so the
    echo is consumed first and the clock stops on the first byte that arrives
    after it. Whatever is still in flight is then drained through the shared
    client's own read loop, so the session is left sitting at a prompt exactly
    as `SSHTarget.run` would leave it and the next command is unaffected.

    Returns (body, milliseconds, produced_output). When a command produces no
    output there is no first byte and the timing is meaningless, so the third
    element says so and the caller keeps it out of the latency statistics.
    """
    chan = target._chan  # noqa: SLF001 - same package, deliberate reuse
    if chan is None:
        raise RuntimeError("sesion no abierta")
    start = time.perf_counter()
    chan.send(command + "\n")

    buf, first = "", None
    echo_at: float | None = None
    last_data = time.perf_counter()
    deadline = start + 30.0
    while first is None and time.perf_counter() < deadline:
        # Plenty of commands in the battery legitimately produce no output at
        # all -- `crontab -l` on a host with no crontab, `history` on a fresh
        # session. Without this bound the loop would sit here until the 30 s
        # deadline for every one of them, so once the echo is in and the
        # channel has been quiet for the client's own idle window, stop and
        # report the wait rather than the arrival.
        if echo_at is not None and time.perf_counter() - last_data > target.idle:
            break
        try:
            chunk = chan.recv(65535)
        except Exception:  # noqa: BLE001 - a read timeout is the normal case
            continue
        if not chunk:
            break
        last_data = time.perf_counter()
        buf += strip_ansi(chunk.decode("utf-8", "replace"))
        if echo_at is None:
            idx = buf.find(command)
            nl = buf.find("\n", idx + len(command)) if idx >= 0 else -1
            if nl >= 0:
                echo_at = last_data
                if len(buf) > nl + 1:
                    first = last_data
        else:
            first = last_data
    ms = ((first or time.perf_counter()) - start) * 1000

    # Drain the remainder only if the prompt has not already arrived. For a
    # fast arm the whole answer, prompt included, lands in the first chunk and
    # is sitting in `buf`; calling the client's read loop again would then wait
    # for a prompt that is never coming and burn its full 60 s deadline on
    # every single command.
    _, seen_prompt = _split_prompt(buf)
    rest = "" if seen_prompt else strip_ansi(target._read())  # noqa: SLF001
    body, prompt = _split_prompt(buf + rest)
    if prompt:
        target.prompt = prompt
    return _strip_echo(body, command), ms, first is not None


def run_arm(name: str, spec: TargetSpec, repeat: int, verbose: bool) -> dict:
    """Run the battery against one arm, twice per command for coherence."""
    rows: list[dict] = []
    target = SSHTarget(spec)
    try:
        target.open()
    except Exception as exc:  # noqa: BLE001
        return {"arm": name, "error": f"{type(exc).__name__}: {exc}",
                "endpoint": f"{spec.host}:{spec.port}"}

    banner, version = target.banner, target.server_version
    try:
        for command, technique in BATTERY:
            bodies, times = [], []
            for _ in range(max(2, repeat)):
                try:
                    body, ms, got = run_timed(target, command)
                except Exception as exc:  # noqa: BLE001
                    body, ms, got = f"<error: {type(exc).__name__}>", float("nan"), False
                bodies.append(body)
                times.append(ms if got else float("nan"))
            coherent = len({mask(b) for b in bodies}) == 1
            rows.append({
                "comando": command, "tecnica": technique,
                "cubierto": not is_miss(bodies[0]),
                "coherente": coherent,
                "ms": [round(t, 1) for t in times],
                "bytes": len(bodies[0]),
            })
            if verbose:
                mark = "ok " if not is_miss(bodies[0]) else "MISS"
                coh = "=" if coherent else "!"
                print(f"  [{name:10}] {mark} {coh} {command:32} "
                      f"{times[0]:8.1f} ms", flush=True)
    finally:
        target.close()

    lat = [t for r in rows for t in r["ms"] if t == t]
    cubiertos = sum(1 for r in rows if r["cubierto"])
    coherentes = sum(1 for r in rows if r["coherente"])
    return {
        "arm": name,
        "endpoint": f"{spec.host}:{spec.port}",
        "server_version": version,
        "banner_lineas": len([x for x in banner.splitlines() if x.strip()]),
        "n_comandos": len(rows),
        "cobertura_pct": round(100 * cubiertos / len(rows), 1) if rows else 0.0,
        "coherencia_pct": round(100 * coherentes / len(rows), 1) if rows else 0.0,
        "latencia_ms": {
            "n": len(lat),
            "media": round(statistics.mean(lat), 1) if lat else None,
            "mediana": round(statistics.median(lat), 1) if lat else None,
            "p95": round(sorted(lat)[int(0.95 * (len(lat) - 1))], 1) if lat else None,
        },
        "detalle": rows,
    }


def write_report(report: dict, outdir: str) -> str:
    os.makedirs(outdir, exist_ok=True)
    arms = [a for a in report["arms"] if "error" not in a]

    # The real host is the reference, not the ceiling: divergence counts the
    # commands where an arm disagrees with it about whether there is anything
    # to show. Answering more than a real Debian is a tell, not a win.
    # Computed before the JSON is written so the figure is persisted with the
    # rest of the run rather than existing only in the Markdown.
    ref = next((a for a in arms if a["arm"] == "host-real"), None)
    if ref is not None:
        ref_cov = {r["comando"]: r["cubierto"] for r in ref["detalle"]}
        for a in arms:
            div = [r["comando"] for r in a["detalle"]
                   if ref_cov.get(r["comando"]) is not None
                   and r["cubierto"] != ref_cov[r["comando"]]]
            a["divergencia_n"] = len(div)
            a["divergencia"] = div

    with open(os.path.join(outdir, "comparison_cowrie.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    lines = [
        "# Comparativa con un honeypot tradicional (Cowrie)",
        "",
        f"Generado: {report['generated_at']}",
        "",
        "Los tres brazos se interrogan con el mismo cliente SSH, las mismas",
        "credenciales y la misma bateria de treinta comandos, de modo que las",
        "diferencias sean atribuibles al sistema y no al procedimiento.",
        "",
        "La latencia es **tiempo hasta el primer byte**, no hasta el silencio:",
        "el cliente compartido espera 1,2 s de quietud antes de dar por cerrada",
        "una respuesta, y medir hasta ahi devuelve ~1.240 ms para todos los",
        "brazos, incluido un Debian pelado. Esa cifra describe el instrumento,",
        "no el sistema.",
        "",
        "**La cobertura se lee contra el host real, nunca sola.** Un Debian",
        "genuino no responde al 100 % de la bateria porque la mitad de esas",
        "rutas no existen en el. Un senuelo que responda a todo no gana: exhibe",
        "un indicio que ningun sistema real presenta. La columna que importa es",
        "la divergencia respecto al host real.",
        "",
        "| Sistema | Version SSH | Cobertura | Divergencia | Coherencia | Mediana | p95 |",
        "|---|---|---|---|---|---|---|",
    ]
    for a in arms:
        lat = a["latencia_ms"]
        div = a.get("divergencia_n")
        div_s = "— (referencia)" if a["arm"] == "host-real" else (
            f"{div}/{a['n_comandos']}" if div is not None else "n/d")
        lines.append(
            f"| {a['arm']} | `{a['server_version'][:28]}` | "
            f"{a['cobertura_pct']} % | {div_s} | {a['coherencia_pct']} % | "
            f"{lat['mediana']} ms | {lat['p95']} ms |")
    lines += ["", "## Coste computacional durante la bateria", "",
              "| Contenedor | CPU media | CPU max | RAM media | RAM max |",
              "|---|---|---|---|---|"]
    for name, s in report.get("recursos", {}).items():
        c, m = s["cpu_pct"], s["mem_mib"]
        lines.append(f"| {name} | {c['media']} % | {c['maximo']} % | "
                     f"{m['media']} MiB | {m['maximo']} MiB |")

    dead = [a for a in report["arms"] if "error" in a]
    if dead:
        lines += ["", "## Brazos no alcanzables", ""]
        lines += [f"- **{a['arm']}** ({a['endpoint']}): {a['error']}" for a in dead]

    lines += ["", "## Detalle por brazo", ""]
    for a in arms:
        miss = [r["comando"] for r in a["detalle"] if not r["cubierto"]]
        inc = [r["comando"] for r in a["detalle"] if not r["coherente"]]
        div = a.get("divergencia", [])
        lines.append(f"**{a['arm']}** — sin respuesta ({len(miss)}): "
                     + (", ".join(f"`{m}`" for m in miss) if miss else "ninguno"))
        lines.append("")
        lines.append(f"**{a['arm']}** — incoherentes entre dos lecturas "
                     f"({len(inc)}): "
                     + (", ".join(f"`{m}`" for m in inc) if inc else "ninguno"))
        lines.append("")
        if a["arm"] != "host-real":
            lines.append(f"**{a['arm']}** — divergen del host real ({len(div)}): "
                         + (", ".join(f"`{m}`" for m in div) if div else "ninguno"))
            lines.append("")

    path = os.path.join(outdir, "COMPARISON.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def main() -> int:
    p = argparse.ArgumentParser(description="Comparativa senuelo generativo / Cowrie")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--decoy-port", type=int, default=2222)
    p.add_argument("--cowrie-port", type=int, default=2224)
    p.add_argument("--real-port", type=int, default=2223,
                   help="host real de control; se omite si no responde")
    p.add_argument("--username", default="root")
    p.add_argument("--password", default="honeypot")
    p.add_argument("--repeat", type=int, default=2,
                   help="lecturas por comando (minimo 2, para la coherencia)")
    p.add_argument("--outdir", default="benchmarks/results")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()
    verbose = not args.quiet

    arms = [
        ("marco-generativo", args.decoy_port, "honeypot_ssh"),
        ("cowrie", args.cowrie_port, "compare_cowrie"),
        ("host-real", args.real_port, "eval_real_host"),
    ]

    results, recursos = [], {}
    for name, port, container in arms:
        print(f"== {name} ({args.host}:{port}) ==", flush=True)
        spec = TargetSpec(name, args.host, port, args.username, args.password)
        with DockerSampler(container) as sampler:
            res = run_arm(name, spec, args.repeat, verbose)
        results.append(res)
        if "error" in res:
            print(f"  no alcanzable: {res['error']}", flush=True)
            continue
        recursos[container] = sampler.summary()
        print(f"  cobertura {res['cobertura_pct']} % | "
              f"coherencia {res['coherencia_pct']} % | "
              f"mediana {res['latencia_ms']['mediana']} ms", flush=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "bateria": len(BATTERY),
        "repeticiones": max(2, args.repeat),
        "arms": results,
        "recursos": recursos,
    }
    path = write_report(report, args.outdir)
    print(f"\nInforme: {path}")
    return 0 if any("error" not in a for a in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
