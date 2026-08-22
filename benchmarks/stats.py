"""Statistics for the timing-indistinguishability test.

Chapter 4 needs to answer one question with evidence: *can an attacker who
only measures response time tell the deterministic route from the generative
one?* "Mean below 1000 ms" does not answer it -- two populations can both sit
under the target and still be trivially separable, which is exactly the defect
this work set out to fix.

Two complementary statistics answer it properly:

Kolmogorov-Smirnov, two-sample
    Tests whether both samples could have come from the same distribution.
    D is the largest gap between the two empirical CDFs. A large D with a
    small p-value means the distributions differ; the result we want is the
    *failure* to reject, i.e. no detectable difference.

    Note the asymmetry, and state it in the report: KS can demonstrate that
    two distributions differ, but never proves them identical. A large p-value
    is evidence of indistinguishability at the given sample size, not proof.

AUC (area under the ROC curve)
    What KS misses: a statistician's verdict is not an attacker's capability.
    AUC is the probability that a randomly chosen generative sample takes
    longer than a randomly chosen deterministic one -- precisely the accuracy
    of the best possible single-threshold timing classifier. 0.5 means the
    attacker does no better than a coin toss; 1.0 means perfect separation.

    Computed from the Mann-Whitney U statistic, with ties counted as half so
    identical timings do not inflate the score.

Both are implemented here from scratch, without scipy or numpy, so the whole
evaluation runs with nothing but the standard library plus `requests`.
"""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class KSResult:
    d: float
    p_value: float
    n1: int
    n2: int

    @property
    def distinguishable(self) -> bool:
        """True when the two samples differ at the 5 % level."""
        return self.p_value < 0.05


@dataclass
class AUCResult:
    auc: float
    n1: int
    n2: int

    @property
    def advantage(self) -> float:
        """Attacker's advantage over guessing, in [0, 1].

        Folded around 0.5 because a classifier that is reliably *wrong* is
        just as useful to the attacker as one that is reliably right.
        """
        return abs(self.auc - 0.5) * 2


def ks_two_sample(a: list[float], b: list[float]) -> KSResult:
    """Two-sample Kolmogorov-Smirnov test.

    D is the supremum distance between the empirical CDFs, evaluated by
    walking both sorted samples once.
    """
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return KSResult(0.0, 1.0, n1, n2)

    xs, ys = sorted(a), sorted(b)
    i = j = 0
    d = 0.0
    while i < n1 and j < n2:
        # Step to the next distinct value present in either sample, consume
        # every tie of it in both, and only then compare the CDFs: a value
        # shared by both samples must move both steps before it is measured.
        value = xs[i] if xs[i] <= ys[j] else ys[j]
        while i < n1 and xs[i] == value:
            i += 1
        while j < n2 and ys[j] == value:
            j += 1
        d = max(d, abs(i / n1 - j / n2))

    # One sample exhausted: its CDF is pinned at 1 while the other climbs, so
    # the largest remaining gap is at the exhaustion point.
    d = max(d, abs(i / n1 - j / n2))
    return KSResult(d, _ks_p_value(d, n1, n2), n1, n2)


def _ks_p_value(d: float, n1: int, n2: int) -> float:
    """Asymptotic p-value for the two-sample KS statistic.

    Uses the Kolmogorov distribution Q(lambda) = 2 * sum (-1)^(k-1) e^(-2k^2 lambda^2)
    with the Stephens small-sample correction on the effective size.
    """
    if d <= 0:
        return 1.0
    ne = math.sqrt(n1 * n2 / (n1 + n2))
    lam = (ne + 0.12 + 0.11 / ne) * d

    total = 0.0
    for k in range(1, 101):
        term = 2 * ((-1) ** (k - 1)) * math.exp(-2.0 * k * k * lam * lam)
        total += term
        if abs(term) < 1e-12:
            break
    return min(max(total, 0.0), 1.0)


def auc_mann_whitney(a: list[float], b: list[float]) -> AUCResult:
    """AUC of the best single-threshold classifier separating `a` from `b`.

    `a` is the negative class (deterministic), `b` the positive one
    (generative). Ranks are averaged over ties.
    """
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return AUCResult(0.5, n1, n2)

    combined = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    ranks = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        # Midrank for the whole tied block: without this, identical timings
        # would be ordered arbitrarily and the AUC would depend on sort order.
        mid = (i + j + 2) / 2.0
        for k in range(i, j + 1):
            ranks[k] = mid
        i = j + 1

    rank_sum_b = sum(r for r, (_, label) in zip(ranks, combined) if label == 1)
    u = rank_sum_b - n2 * (n2 + 1) / 2.0
    return AUCResult(u / (n1 * n2), n1, n2)


def bimodality_coefficient(values: list[float]) -> float:
    """Sarle's bimodality coefficient: (skew^2 + 1) / kurtosis.

    Above roughly 0.555 -- the value for a uniform distribution -- the sample
    is more consistent with two modes than with one. Reported as a direct,
    single-number description of the defect being fixed, independent of any
    route labelling: it looks at the pooled latencies the attacker actually
    sees.
    """
    n = len(values)
    if n < 4:
        return 0.0
    mean = sum(values) / n
    m2 = sum((v - mean) ** 2 for v in values) / n
    if m2 == 0:
        return 0.0
    m3 = sum((v - mean) ** 3 for v in values) / n
    m4 = sum((v - mean) ** 4 for v in values) / n
    skew = m3 / (m2 ** 1.5)
    kurt = m4 / (m2 ** 2)

    # Sample-corrected form, which matters at the sample sizes a benchmark run
    # produces (tens, not thousands).
    g1 = skew * math.sqrt(n * (n - 1)) / (n - 2)
    g2 = ((n - 1) * ((n + 1) * (kurt - 3) + 6)) / ((n - 2) * (n - 3))
    denom = g2 + 3 * ((n - 1) ** 2) / ((n - 2) * (n - 3))
    if denom == 0:
        return 0.0
    return (g1 * g1 + 1) / denom


def verdict(ks: KSResult, auc: AUCResult) -> tuple[str, str]:
    """Plain-language reading of both statistics, for RESULTS.md.

    Deliberately conservative: anything short of clean indistinguishability is
    reported as a partial result, never rounded up to a pass.
    """
    if ks.n1 < 8 or auc.n1 < 8 or ks.n2 < 8 or auc.n2 < 8:
        return ("INSUFICIENTE",
                "Menos de 8 muestras por ruta: el contraste no tiene potencia. "
                "Repetir con --repeat mayor antes de interpretar nada.")
    if not ks.distinguishable and auc.advantage < 0.20:
        return ("INDISTINGUIBLE",
                "No se detecta diferencia entre las dos rutas (KS no significativo) "
                "y un clasificador temporal apenas supera el azar.")
    if not ks.distinguishable:
        return ("PARCIAL",
                "KS no detecta diferencia, pero el AUC muestra que un clasificador "
                "temporal todavia obtiene ventaja. Normalizacion incompleta.")
    return ("SEPARABLE",
            "Las dos rutas siguen distribuciones distintas y son separables por "
            "tiempo: la normalizacion no cumple su objetivo con esta configuracion.")
