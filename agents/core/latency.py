"""Latency normalisation -- makes response time independent of the route.

The problem this module exists to solve
---------------------------------------
The framework resolves a command by one of two routes, and they cost wildly
different amounts of time: the deterministic route answers from the persona in
about 2 ms, the generative route pays for local inference and takes seconds.
Measured on the reference hardware the two populations were 2.4 ms +/- 1.6 and
2044.4 ms +/- 7.3 -- clean, narrow, and two thousand milliseconds apart.

No real host behaves like that. An attacker who simply times responses sorts
the commands into two buckets and learns something no honeypot should ever
reveal: that a language model sits behind some of them, and therefore that the
host is a decoy. Lowering the inference cost does not fix it. Even at 800 ms
the two buckets stay separable, because the tell is not the magnitude, it is
the *bimodality*.

The property this module enforces
---------------------------------
Response latency must be a function of the command -- which the attacker can
see -- and never of the route, which is an internal implementation detail:

    L  =  rtt(session)  +  exec_cost(command_class)  +  jitter

Every command is assigned a target drawn from that model before it is
resolved. Whichever route answers, the response is held until the target
elapses. Two commands of the same class then take indistinguishable amounts of
time regardless of how they were produced.

The metric that goes with it is therefore not "mean below 1000 ms" but "an
attacker cannot separate the two routes by time", which is testable: see
`benchmarks/stats.py` for the two-sample Kolmogorov-Smirnov test and the
AUC distinguisher used to verify it.

Honest limitation
-----------------
Padding can only ever *add* time. When the generative route overruns its
target the delay cannot be taken back, and that sample stays distinguishable.
Those events are counted (`overruns`) and reported rather than hidden: the
overrun rate is the real measure of whether normalisation is holding, and
driving it to zero is a tuning problem (MAX_TOKENS, model size, deadline).
"""
from __future__ import annotations

import hashlib
import math
import random
import re
import threading
import time
from dataclasses import dataclass, field

from core import config


# -- cost model --------------------------------------------------------------
# Median execution cost and log-normal spread per class of command, expressed
# in milliseconds, for a command run on a real Ubuntu server. These are the
# host-side costs only: network round-trip is added separately because it
# belongs to the session, not to the command.
#
# sigma is the standard deviation of the underlying normal, so it controls the
# right tail: a real `find /` is occasionally much slower than its median,
# while `whoami` never is.
CLASS_PROFILE: dict[str, tuple[float, float]] = {
    "builtin":    (1.5,   0.35),   # whoami, pwd, id, echo, cd
    "read_small": (4.0,   0.45),   # cat /etc/passwd, uname -a
    "list_dir":   (9.0,   0.55),   # ls, ls -la
    "proc_scan":  (45.0,  0.60),   # ps aux, ss, ip a, df, free -- reads /proc
    "net_probe":  (120.0, 0.75),   # ping, curl, wget, dig -- leaves the host
    "heavy":      (400.0, 0.90),   # find /, grep -r, du -sh, dpkg -l
    "unknown":    (60.0,  0.80),   # anything unrecognised
}

# First token of the command -> cost class. Matched on the binary name, which
# is what determines the cost on a real host.
_BINARY_CLASS: dict[str, str] = {
    # builtins and near-instant syscalls
    "whoami": "builtin", "pwd": "builtin", "id": "builtin", "echo": "builtin",
    "cd": "builtin", "hostname": "builtin", "date": "builtin", "uptime": "builtin",
    "history": "builtin", "which": "builtin", "clear": "builtin", "exit": "builtin",
    "export": "builtin", "alias": "builtin", "umask": "builtin", "tty": "builtin",
    # single small read
    "cat": "read_small", "head": "read_small", "tail": "read_small",
    "uname": "read_small", "file": "read_small", "stat": "read_small",
    "wc": "read_small", "readlink": "read_small", "basename": "read_small",
    "dirname": "read_small", "env": "read_small", "printenv": "read_small",
    "groups": "read_small", "w": "read_small", "who": "read_small",
    "last": "read_small", "lsb_release": "read_small",
    # directory listing
    "ls": "list_dir", "ll": "list_dir", "dir": "list_dir", "tree": "list_dir",
    "mkdir": "list_dir", "touch": "list_dir", "rm": "list_dir", "cp": "list_dir",
    "mv": "list_dir", "chmod": "list_dir", "chown": "list_dir", "ln": "list_dir",
    # /proc and system tables
    "ps": "proc_scan", "top": "proc_scan", "htop": "proc_scan", "free": "proc_scan",
    "df": "proc_scan", "mount": "proc_scan", "lsof": "proc_scan", "ss": "proc_scan",
    "netstat": "proc_scan", "ip": "proc_scan", "ifconfig": "proc_scan",
    "route": "proc_scan", "arp": "proc_scan", "systemctl": "proc_scan",
    "service": "proc_scan", "journalctl": "proc_scan", "lscpu": "proc_scan",
    "lsblk": "proc_scan", "vmstat": "proc_scan", "iostat": "proc_scan",
    "crontab": "proc_scan", "sudo": "proc_scan", "su": "proc_scan",
    # goes out to the network
    "ping": "net_probe", "curl": "net_probe", "wget": "net_probe",
    "dig": "net_probe", "nslookup": "net_probe", "host": "net_probe",
    "traceroute": "net_probe", "ssh": "net_probe", "scp": "net_probe",
    "nc": "net_probe", "telnet": "net_probe",
    # full traversals and package databases
    "find": "heavy", "grep": "heavy", "egrep": "heavy", "fgrep": "heavy",
    "du": "heavy", "locate": "heavy", "updatedb": "heavy", "dpkg": "heavy",
    "apt": "heavy", "apt-get": "heavy", "rpm": "heavy", "yum": "heavy",
    "tar": "heavy", "gzip": "heavy", "zip": "heavy", "unzip": "heavy",
    "pip": "heavy", "npm": "heavy", "docker": "heavy",
}

# A recursive traversal is heavy no matter which binary drives it.
_RECURSIVE = re.compile(r"(^|\s)-[a-zA-Z]*[rR]([a-zA-Z]*)?(\s|$)")


def classify(command: str) -> str:
    """Cost class of a command, from what it would actually do on a host."""
    command = command.strip()
    if not command:
        return "builtin"

    # The class is set by the first segment: `cat x | grep y` costs what the
    # read costs, because the filter runs on an already-small stream.
    head = command.split("|")[0].strip()
    tokens = head.split()
    if not tokens:
        return "builtin"

    binary = tokens[0].rsplit("/", 1)[-1]
    cls = _BINARY_CLASS.get(binary, "unknown")

    # Recursion promotes anything into the heavy class: `ls -R /` and
    # `grep -r / ` really are slow on a real filesystem.
    if cls in ("list_dir", "read_small") and _RECURSIVE.search(head):
        return "heavy"
    # A traversal rooted at / is slower still, but stays inside "heavy":
    # its sigma already covers that tail.
    return cls


@dataclass
class Normalization:
    """What normalisation did to one command."""

    target_ms: float
    elapsed_ms: float
    slept_ms: float
    overrun: bool
    cls: str

    def as_telemetry(self) -> dict[str, object]:
        return {
            "norm_target_ms": round(self.target_ms, 3),
            "norm_slept_ms": round(self.slept_ms, 3),
            "norm_overrun": self.overrun,
            "cmd_class": self.cls,
        }


@dataclass
class NormalizerStats:
    """Counters exposed on /stats so the overrun rate is never invisible."""

    commands: int = 0
    overruns: int = 0
    slept_total_ms: float = 0.0
    overrun_total_ms: float = 0.0
    by_route: dict[str, int] = field(default_factory=dict)
    overruns_by_route: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        pct = (100.0 * self.overruns / self.commands) if self.commands else 0.0
        return {
            "commands": self.commands,
            "overruns": self.overruns,
            "overrun_pct": round(pct, 2),
            "mean_slept_ms": round(self.slept_total_ms / self.commands, 2) if self.commands else 0.0,
            "mean_overrun_ms": round(self.overrun_total_ms / self.overruns, 2) if self.overruns else 0.0,
            "by_route": dict(self.by_route),
            "overruns_by_route": dict(self.overruns_by_route),
        }


class LatencyNormalizer:
    """Holds each response until its command-derived target has elapsed."""

    def __init__(self, seed: int | None = None) -> None:
        # Seeded so a benchmark run over a fixed command sequence is
        # reproducible; the draw still varies command to command, because a
        # host that answers `ls` in exactly the same time twice is itself a
        # tell.
        self._rng = random.Random(config.PERSONA_SEED if seed is None else seed)
        self._lock = threading.Lock()
        self.stats = NormalizerStats()

    @property
    def enabled(self) -> bool:
        return config.LATENCY_NORMALIZE

    # -- the model ---------------------------------------------------------
    def session_rtt_ms(self, session_id: str) -> float:
        """Round-trip time for this session.

        Constant within a session and derived from its id, because an attacker
        connects over one network path: an RTT that jumped around between
        commands of the same session would be its own anomaly.
        """
        digest = hashlib.sha256(f"{config.PERSONA_SEED}:{session_id}".encode()).digest()
        # Map the digest onto [0, 1) and push it through the log-normal
        # inverse so the spread looks like real internet RTT: mostly tens of
        # ms, occasionally much worse.
        u = int.from_bytes(digest[:8], "big") / float(1 << 64)
        u = min(max(u, 1e-6), 1 - 1e-6)
        z = _norm_ppf(u)
        rtt = config.LATENCY_RTT_MEDIAN_MS * math.exp(config.LATENCY_RTT_SIGMA * z)
        return min(rtt, config.LATENCY_RTT_MEDIAN_MS * 8)

    def target_ms(self, command: str, session_id: str) -> tuple[float, str]:
        """Draw this command's target latency. Route is deliberately not an
        input: that independence is the whole security property."""
        cls = classify(command)
        median, sigma = CLASS_PROFILE[cls]
        with self._lock:
            z = self._rng.gauss(0.0, 1.0)
        exec_ms = median * math.exp(sigma * z)
        # Clamp the tail: a single 30-second outlier would be as suspicious as
        # the bimodality it replaced.
        exec_ms = min(exec_ms, median * config.LATENCY_TAIL_CAP)
        return self.session_rtt_ms(session_id) + exec_ms, cls

    # -- the enforcement ---------------------------------------------------
    def settle(self, command: str, session_id: str, elapsed_ms: float,
               route: str = "") -> Normalization:
        """Sleep out the difference between elapsed time and the target.

        Called after the command has been resolved and before the answer goes
        back to the decoy. Blocking is correct here: the request already owns
        a worker thread, and a real host holds the connection open exactly the
        same way while it works.
        """
        target, cls = self.target_ms(command, session_id)

        if not self.enabled:
            return Normalization(target, elapsed_ms, 0.0, elapsed_ms > target, cls)

        deficit_ms = target - elapsed_ms
        slept = 0.0
        if deficit_ms > 0:
            time.sleep(deficit_ms / 1000.0)
            slept = deficit_ms
        overrun = deficit_ms < 0

        with self._lock:
            self.stats.commands += 1
            self.stats.slept_total_ms += slept
            if route:
                self.stats.by_route[route] = self.stats.by_route.get(route, 0) + 1
            if overrun:
                self.stats.overruns += 1
                self.stats.overrun_total_ms += -deficit_ms
                if route:
                    self.stats.overruns_by_route[route] = \
                        self.stats.overruns_by_route.get(route, 0) + 1

        return Normalization(target, elapsed_ms, slept, overrun, cls)


# -- helpers -----------------------------------------------------------------
def _norm_ppf(p: float) -> float:
    """Inverse standard normal CDF (Acklam's rational approximation).

    Hand-rolled to keep the agent image free of scipy/numpy: the container
    ships requests, fastapi and pydantic and nothing else.
    """
    a = (-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00)
    b = (-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01)
    c = (-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00)
    d = (7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00)
    plow, phigh = 0.02425, 1 - 0.02425

    if p < plow:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / \
               ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1)
    if p > phigh:
        q = math.sqrt(-2 * math.log(1 - p))
        return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / \
                ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1)
    q = p - 0.5
    r = q * q
    return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / \
           (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1)
