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

# A recursive traversal is heavy no matter which binary drives it -- but only
# for binaries where -r/-R actually means recursion. Matching the flag alone
# misfires badly: `uname -r` prints the kernel release and costs nothing.
_RECURSIVE_BINARIES = {"ls", "cp", "mv", "rm", "chmod", "chown", "chgrp",
                       "grep", "egrep", "fgrep", "scp", "rsync", "tree"}
_RECURSIVE_FLAG = re.compile(r"(?:^|\s)-[a-zA-Z]*[rR][a-zA-Z]*(?:\s|$)")


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

    # Recursion promotes into the heavy class: `ls -R /` and `grep -r /`
    # really do traverse the filesystem. Restricted to binaries where the flag
    # means recursion, so `uname -r` is not mistaken for a traversal.
    if binary in _RECURSIVE_BINARIES and _RECURSIVE_FLAG.search(head):
        return "heavy"
    # A traversal rooted at / is slower still, but stays inside "heavy":
    # its sigma already covers that tail.
    return cls


@dataclass
class GenerationPlan:
    """What the generative route may spend answering one command."""

    cls: str
    target_ms: float
    max_tokens: int
    context_turns: int
    context_chars: int
    lean: bool
    # False when prompt evaluation alone is projected to exceed the target, so
    # no token budget can make this command fit. Reported, never hidden: it is
    # the honest measure of where normalisation still cannot reach.
    feasible: bool
    projected_ms: float

    def as_telemetry(self) -> dict[str, object]:
        return {
            "gen_max_tokens": self.max_tokens,
            "gen_context_turns": self.context_turns,
            "gen_lean_context": self.lean,
            "gen_feasible": self.feasible,
            "gen_projected_ms": round(self.projected_ms, 1),
        }


class GenerationBudget:
    """Turns a latency target into a token budget, calibrated as it runs.

    Why this exists
    ---------------
    `LatencyNormalizer` can only add time. If the model is still generating
    when the target elapses the padding has nothing left to do, and that sample
    stays separable no matter how good the cost model is. The reference run
    measured exactly that: every `lsblk` and `vmstat 1 1` sample hit the 64
    token ceiling and overran, and the `proc_scan` class came out separable at
    AUC = 1.00 while the classes that fit came out indistinguishable.

    The model
    ---------
    Generation time splits into a fixed and a marginal term::

        llm_ms  ~=  prompt_eval(context)  +  tokens x ms_per_token

    Both are measured -- Ollama reports them on every response -- so the budget
    is fitted to the hardware it runs on rather than assuming the reference
    machine's numbers::

        tokens  =  (target x GEN_SAFETY - prompt_eval) / ms_per_token

    When that comes out below `GEN_MIN_TOKENS` the fixed term is the problem,
    not the marginal one, and no token budget can fix it. The lean context tier
    is tried first, because a shorter prompt is the only way to move the fixed
    term; if even that does not fit, the command is answered anyway at the
    floor and flagged `feasible=False` so the overrun is attributable instead
    of mysterious.

    What it costs
    -------------
    Fidelity, and the report must say so: fewer tokens means a shorter, flatter
    invented output, and a lean context means the model sees less of the
    session it is supposed to stay coherent with.
    """

    def __init__(self) -> None:
        self._ms_per_token = config.GEN_MS_PER_TOKEN
        # One estimate per context tier: a lean prompt is cheaper to evaluate
        # than a full one, and averaging the two together would make the lean
        # tier look useless exactly when it is needed.
        self._overhead_ms = {"full": config.GEN_PROMPT_OVERHEAD_MS,
                             "lean": config.GEN_PROMPT_OVERHEAD_MS / 2}
        self._samples = {"full": 0, "lean": 0}
        self._token_samples = 0
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return config.GEN_BUDGET

    # -- calibration -------------------------------------------------------
    def observe(self, *, eval_tokens: int, eval_ms: float,
                prompt_eval_ms: float, lean: bool) -> None:
        """Fold one real response into the running estimate of both terms."""
        tier = "lean" if lean else "full"
        alpha = config.GEN_EWMA_ALPHA
        with self._lock:
            if prompt_eval_ms > 0:
                self._overhead_ms[tier] = (
                    (1 - alpha) * self._overhead_ms[tier] + alpha * prompt_eval_ms)
                self._samples[tier] += 1
            # A response of one or two tokens is nearly all fixed cost, so its
            # implied per-token rate is noise. Only rates from a run long
            # enough to dominate the fixed term are worth learning from.
            if eval_tokens >= 8 and eval_ms > 0:
                rate = eval_ms / eval_tokens
                self._ms_per_token = (1 - alpha) * self._ms_per_token + alpha * rate
                self._token_samples += 1

    # -- the plan ----------------------------------------------------------
    def plan(self, command: str, target_ms: float) -> GenerationPlan:
        cls = classify(command)

        if not self.enabled:
            return GenerationPlan(cls, target_ms, config.MAX_TOKENS,
                                  config.SESSION_CONTEXT_TURNS,
                                  config.GEN_CONTEXT_CHARS, False, True, 0.0)

        with self._lock:
            rate = self._ms_per_token
            full_overhead = self._overhead_ms["full"]
            lean_overhead = self._overhead_ms["lean"]

        affordable_ms = target_ms * config.GEN_SAFETY

        # Full context first: the lean tier is a concession, not a default.
        tokens = int((affordable_ms - full_overhead) / rate)
        lean = False
        overhead = full_overhead
        if tokens < config.GEN_MIN_TOKENS:
            lean = True
            overhead = lean_overhead
            tokens = int((affordable_ms - lean_overhead) / rate)

        tokens = max(config.GEN_MIN_TOKENS, min(config.MAX_TOKENS, tokens))

        # Feasibility is judged on the plan that will actually run, not on the
        # arithmetic before the floor was applied: a budget clamped up to
        # GEN_MIN_TOKENS often still fits, and calling it infeasible would
        # inflate the count of commands the framework admits it cannot hide.
        projected_ms = overhead + tokens * rate
        turns = config.GEN_LEAN_CONTEXT_TURNS if lean else config.SESSION_CONTEXT_TURNS
        chars = config.GEN_LEAN_CONTEXT_CHARS if lean else config.GEN_CONTEXT_CHARS
        return GenerationPlan(cls, target_ms, tokens, turns, chars, lean,
                              projected_ms <= target_ms, projected_ms)

    def as_dict(self) -> dict[str, object]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "ms_per_token": round(self._ms_per_token, 2),
                "prompt_overhead_ms": {k: round(v, 1)
                                       for k, v in self._overhead_ms.items()},
                "calibration_samples": dict(self._samples),
                "rate_samples": self._token_samples,
            }


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
               route: str = "",
               drawn: tuple[float, str] | None = None) -> Normalization:
        """Sleep out the difference between elapsed time and the target.

        Called after the command has been resolved and before the answer goes
        back to the decoy. Blocking is correct here: the request already owns
        a worker thread, and a real host holds the connection open exactly the
        same way while it works.

        `drawn` passes in a target already taken for this command. The draw
        consumes the RNG, so taking it twice -- once to size the generation
        budget and once here -- would pad towards a different number than the
        one the budget was computed against, which is the one bug that would
        quietly reopen the channel this module exists to close.
        """
        target, cls = drawn if drawn is not None else self.target_ms(command, session_id)

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
