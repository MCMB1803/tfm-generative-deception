"""Scoring for the blind-judge experiment.

The claim the report needs to support -- or fail to support -- is precise: *a
blind judge cannot tell the decoy from a real host better than chance.* That is
a statement about a classifier's accuracy against a 50/50 base rate, so the
statistics are the ones that fit that shape, all implemented on the standard
library so the evaluation has no numeric dependencies.

  accuracy + exact binomial test
      With an equal number of real and decoy transcripts, a useless judge
      scores 0.5. The binomial test asks how surprising the observed number of
      correct calls would be if the judge were truly guessing. A large p-value
      is the result we are after -- indistinguishable from chance -- with the
      same caveat as the timing test: it is evidence at this sample size, not
      proof of a null.

  confusion matrix, recall per class
      Accuracy alone hides the failure mode that matters. A judge that always
      says "decoy" scores 0.5 on a balanced set while detecting every decoy;
      the decoy-recall exposes that. Both recalls are reported.

  Cohen's kappa between judges
      Two judges agreeing proves little if both agree by chance. Kappa nets out
      the agreement expected from their base rates, so it measures whether the
      cues they react to are the same -- which is what tells a property of the
      deception apart from a quirk of one model.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable

from judge import Verdict

LABELS = ("real", "decoy")


# -- binomial -----------------------------------------------------------------
def binomial_two_sided(k: int, n: int, p: float = 0.5) -> float:
    """Exact two-sided binomial test p-value.

    Sums the probability of every outcome no more likely than the observed one,
    the standard two-sided construction. Exact rather than normal-approximated
    because n here is tens of transcripts, not thousands.
    """
    if n == 0:
        return 1.0
    probs = [math.comb(n, i) * p**i * (1 - p)**(n - i) for i in range(n + 1)]
    observed = probs[k]
    # Floating tolerance so the observed outcome is never excluded by rounding.
    return min(1.0, sum(pr for pr in probs if pr <= observed * (1 + 1e-9)))


@dataclass
class JudgeScore:
    judge: str
    n: int
    correct: int
    unparseable: int
    accuracy: float
    p_value: float
    real_recall: float          # of true-real, how many called real
    decoy_recall: float         # of true-decoy, how many called decoy
    confusion: dict
    mean_confidence: float
    verdict: str
    reading: str


def _empty_confusion() -> dict:
    return {t: {"real": 0, "decoy": 0, "unparsed": 0} for t in LABELS}


def score_judge(name: str, verdicts: Iterable[Verdict]) -> JudgeScore:
    verdicts = list(verdicts)
    n = len(verdicts)
    confusion = _empty_confusion()
    correct = unparsed = 0
    conf_sum = 0.0

    for v in verdicts:
        if not v.parse_ok or not v.verdict:
            confusion[v.truth]["unparsed"] += 1
            unparsed += 1
            continue
        confusion[v.truth][v.verdict] += 1
        conf_sum += v.confidence
        if v.correct:
            correct += 1

    scored = n - unparsed
    accuracy = correct / scored if scored else 0.0
    # The binomial test is over transcripts the judge actually classified;
    # unparseable answers are reported separately, not silently scored wrong,
    # which would blame the deception for the judge's formatting failures.
    p_value = binomial_two_sided(correct, scored, 0.5) if scored else 1.0

    real_total = sum(confusion["real"].values())
    decoy_total = sum(confusion["decoy"].values())
    real_recall = confusion["real"]["real"] / real_total if real_total else 0.0
    decoy_recall = confusion["decoy"]["decoy"] / decoy_total if decoy_total else 0.0

    verdict, reading = _read_judge(scored, accuracy, p_value)
    return JudgeScore(
        judge=name, n=n, correct=correct, unparseable=unparsed,
        accuracy=accuracy, p_value=p_value, real_recall=real_recall,
        decoy_recall=decoy_recall, confusion=confusion,
        mean_confidence=conf_sum / scored if scored else 0.0,
        verdict=verdict, reading=reading)


def _read_judge(n: int, acc: float, p: float) -> tuple:
    if n < 10:
        return ("INSUFICIENTE",
                "Menos de 10 transcripciones clasificadas: sin potencia "
                "estadistica. Ampliar la muestra antes de interpretar.")
    if p >= 0.05:
        return ("INDISTINGUIBLE",
                "El juez no supera el azar de forma significativa: sobre estas "
                "transcripciones el senuelo no es separable de un host real.")
    if acc > 0.5:
        return ("SEPARABLE",
                "El juez acierta por encima del azar de forma significativa: "
                "el engano deja senales que un observador ciego detecta.")
    return ("SEPARABLE_INVERSO",
            "El juez acierta por debajo del azar: hay senal, pero el modelo la "
            "lee al reves. Separable de todos modos.")


# -- inter-judge agreement ----------------------------------------------------
@dataclass
class Agreement:
    n: int
    observed: float
    expected: float
    kappa: float
    reading: str


def cohen_kappa(a: list, b: list) -> Agreement:
    """Cohen's kappa over transcripts both judges classified with a label."""
    by_id = {v.transcript_id: v for v in b}
    pairs = [(x.verdict, by_id[x.transcript_id].verdict)
             for x in a
             if x.parse_ok and x.verdict and x.transcript_id in by_id
             and by_id[x.transcript_id].parse_ok and by_id[x.transcript_id].verdict]
    n = len(pairs)
    if n == 0:
        return Agreement(0, 0.0, 0.0, 0.0,
                         "Sin transcripciones clasificadas por ambos jueces.")

    observed = sum(1 for x, y in pairs if x == y) / n
    expected = 0.0
    for label in LABELS:
        pa = sum(1 for x, _ in pairs if x == label) / n
        pb = sum(1 for _, y in pairs if y == label) / n
        expected += pa * pb
    kappa = (observed - expected) / (1 - expected) if expected < 1 else 1.0
    return Agreement(n, observed, expected, kappa, _read_kappa(kappa))


def _read_kappa(k: float) -> str:
    # Landis & Koch bands, the usual reading for kappa.
    if k < 0.0:
        band = "peor que el azar"
    elif k < 0.20:
        band = "leve"
    elif k < 0.40:
        band = "aceptable"
    elif k < 0.60:
        band = "moderado"
    elif k < 0.80:
        band = "sustancial"
    else:
        band = "casi total"
    return (f"Acuerdo {band} (kappa={k:.2f}). Un acuerdo alto sobre las mismas "
            "transcripciones indica que ambos jueces reaccionan a las mismas "
            "senales, no a un capricho de un modelo.")


# -- attacker (secondary signal) ----------------------------------------------
@dataclass
class AttackerScore:
    n: int
    guessed: int
    correct: int
    accuracy: float
    note: str = ""


def score_attacker(transcripts) -> AttackerScore:
    """The adversary's own guess. Secondary: it knew a honeypot was possible,
    so it is primed toward 'decoy' and cannot be read as a fair detector."""
    transcripts = list(transcripts)
    guessed = correct = 0
    for tx in transcripts:
        if not tx.attacker_verdict:
            continue
        guessed += 1
        truth = "real" if tx.arm == "real" else "decoy"
        if tx.attacker_verdict == truth:
            correct += 1
    return AttackerScore(
        n=len(transcripts), guessed=guessed, correct=correct,
        accuracy=correct / guessed if guessed else 0.0,
        note="El atacante sabe que busca un senuelo; su acierto se reporta como "
             "senal adversaria secundaria, no como la medida ciega.")
