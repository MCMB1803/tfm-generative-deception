"""Adversary-emulation harness: the measured answer to "is the decoy credible?"

This is the driver behind the credibility chapter. It runs the whole loop the
report's methodology describes, end to end, producing numbers rather than
opinions:

  1. Collect. An adaptive LLM attacker is turned loose, in turn, on each arm:
     the framework decoy and a real Linux host as the control. Same attacker,
     same instrument, same turn budget. Every session is recorded as a
     Transcript that separates what crossed the wire from how it was produced.

  2. Judge blind. The transcripts are pooled, shuffled, and stripped of every
     arm label, then handed one at a time to two independent judges -- a larger
     primary model and the decoy's own small model as a contrast. Neither judge
     is told a honeypot is in the sample or which arm it is looking at.

  3. Score. Accuracy against the 50/50 base rate with an exact binomial test,
     per-class recall, a confusion matrix, and Cohen's kappa between the two
     judges. The attacker's own guess is kept as a secondary, adversarial
     signal, clearly labelled as not the blind measurement.

Every model call goes through the harness's own Ollama client, never the
decoy's, so the evaluator is not wired to the thing it evaluates. Nothing is
estimated: the artefacts under `evaluation/results/` are what a third party
regenerates by pointing this at the same two arms.

Reproducibility. The shuffle is seeded (`--seed`, default 1803, matching the
persona seed) so the blind ordering is fixed; the attacker and judges still run
with the models' own sampling, so transcripts and verdicts vary between runs
and are reported over N sessions, exactly as the latency chapter reports
distributions rather than point values.

Usage (stack up, judge model pulled):

    python evaluation/run_deception_eval.py --sessions 8
    python evaluation/run_deception_eval.py --sessions 12 --judge-model qwen2.5:7b \\
        --decoy-port 2222 --real-port 2223
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attacker import Attacker, AttackerConfig
from judge import Judge
from metrics import cohen_kappa, score_attacker, score_judge
from ollama import Ollama
from report import write_report
from targets import SSHTarget, TargetSpec
from transcript import Transcript, write_jsonl

ARMS = ("framework", "real")


def _stamp(offset: int) -> str:
    # No wall-clock in ids: the run is timestamped once, centrally, and each
    # transcript is numbered, so a rerun with the same seed is diffable.
    return f"tx-{offset:03d}"


def collect(attacker: Attacker, specs: dict, sessions: int,
            verbose: bool) -> list:
    """Run the attacker against every arm, `sessions` times each."""
    transcripts: list = []
    counter = 0
    for arm in ARMS:
        spec = specs[arm]
        for s in range(sessions):
            target = SSHTarget(spec)
            tx = attacker.run(target, _stamp(counter), arm)
            transcripts.append(tx)
            counter += 1
            if verbose:
                status = tx.error or (f"{len(tx.turns)} turnos, "
                                      f"atacante dice: {tx.attacker_verdict or '?'}")
                print(f"  [{arm:9}] sesion {s + 1}/{sessions}: {status}", flush=True)
    return transcripts


def judge_blind(judges: list, transcripts: list, seed: int,
                verbose: bool) -> dict:
    """Shuffle, strip labels, classify each transcript with every judge."""
    order = list(transcripts)
    random.Random(seed).shuffle(order)
    # Only transcripts with real content are judged: a failed connection has
    # nothing to classify and would count as neither a hit nor a miss.
    order = [t for t in order if t.turns and not t.error]

    verdicts: dict = {j.name: [] for j in judges}
    for idx, tx in enumerate(order, 1):
        for j in judges:
            verdicts[j.name].append(j.classify(tx))
        if verbose:
            print(f"  juez: {idx}/{len(order)} transcripciones", flush=True)
    return verdicts


def build_report(transcripts, verdicts, judges, cfg) -> dict:
    scores = {name: score_judge(name, vs) for name, vs in verdicts.items()}
    judged = [t for t in transcripts if t.turns and not t.error]
    kappa = None
    if len(judges) == 2:
        a, b = judges[0].name, judges[1].name
        kappa = cohen_kappa(verdicts[a], verdicts[b])
    attacker = score_attacker(judged)
    counts = {arm: sum(1 for t in judged if t.arm == arm) for arm in ARMS}
    return {
        "generated_at": cfg["generated_at"],
        "config": cfg,
        "arm_counts": counts,
        "n_collected": len(transcripts),
        "n_judged": len(judged),
        "n_dead": len(transcripts) - len(judged),
        "judges": {name: score for name, score in scores.items()},
        "primary_judge": judges[0].name,
        "kappa": kappa,
        "attacker": attacker,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Emulacion de adversarios y juez ciego")
    p.add_argument("--sessions", type=int, default=8,
                   help="sesiones del atacante por arm (real y senuelo)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--decoy-port", type=int, default=2222)
    p.add_argument("--real-port", type=int, default=2223)
    p.add_argument("--username", default="root")
    p.add_argument("--password", default="honeypot")
    p.add_argument("--ollama", default=os.getenv("EVAL_OLLAMA",
                                                 "http://127.0.0.1:11434"))
    p.add_argument("--attacker-model", default="llama3.2:3b",
                   help="atacante: familia distinta a la del senuelo y a la "
                        "del juez, para que ninguna reconozca su propia salida")
    p.add_argument("--judge-model", default="qwen2.5:7b",
                   help="juez principal, independiente del generador")
    p.add_argument("--second-judge-model", default="qwen2.5-coder:0.5b",
                   help="segundo juez (el propio generador), para contraste")
    p.add_argument("--max-turns", type=int, default=12)
    p.add_argument("--min-turns", type=int, default=5,
                   help="comandos que el atacante debe ejecutar antes de poder "
                        "emitir veredicto; evita sesiones vacias e injuzgables")
    p.add_argument("--seed", type=int, default=1803)
    p.add_argument("--outdir", default="evaluation/results")
    p.add_argument("--pull", action="store_true",
                   help="descargar los modelos que falten antes de empezar")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()
    verbose = not args.quiet

    attacker_llm = Ollama(args.ollama, args.attacker_model)
    judge_llms = [Ollama(args.ollama, args.judge_model)]
    if args.second_judge_model and args.second_judge_model != args.judge_model:
        judge_llms.append(Ollama(args.ollama, args.second_judge_model))

    # Fail loudly and early if a model is missing: a silent fallback would make
    # the judge answer nonsense and taint every number downstream.
    missing = []
    for llm in [attacker_llm, *judge_llms]:
        if not llm.has_model():
            if args.pull:
                print(f"Descargando {llm.model}...", flush=True)
                if not llm.pull(lambda s: None):
                    missing.append(llm.model)
            else:
                missing.append(llm.model)
    if missing:
        print("Modelos no disponibles en Ollama: " + ", ".join(sorted(set(missing))),
              file=sys.stderr)
        print("Descarguelos con --pull o `ollama pull <modelo>`.", file=sys.stderr)
        return 2

    specs = {
        "framework": TargetSpec("framework", args.host, args.decoy_port,
                                args.username, args.password),
        "real": TargetSpec("real", args.host, args.real_port,
                           args.username, args.password),
    }

    attacker = Attacker(attacker_llm, AttackerConfig(max_turns=args.max_turns,
                                                     min_turns=args.min_turns))
    judges = [Judge(llm) for llm in judge_llms]

    print(f"== Recoleccion: {args.sessions} sesiones x {len(ARMS)} arms ==", flush=True)
    transcripts = collect(attacker, specs, args.sessions, verbose)

    print("== Clasificacion ciega ==", flush=True)
    verdicts = judge_blind(judges, transcripts, args.seed, verbose)

    cfg = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sessions_per_arm": args.sessions,
        "attacker_model": args.attacker_model,
        "judge_model": args.judge_model,
        "second_judge_model": args.second_judge_model if len(judge_llms) == 2 else None,
        "max_turns": args.max_turns,
        "min_turns": args.min_turns,
        "seed": args.seed,
        "arms": {"framework": f"{args.host}:{args.decoy_port}",
                 "real": f"{args.host}:{args.real_port}"},
    }
    report = build_report(transcripts, verdicts, judges, cfg)

    os.makedirs(args.outdir, exist_ok=True)
    write_jsonl(os.path.join(args.outdir, "transcripts.jsonl"), transcripts)
    with open(os.path.join(args.outdir, "verdicts.jsonl"), "w",
              encoding="utf-8") as fh:
        for name, vs in verdicts.items():
            for v in vs:
                fh.write(json.dumps(v.__dict__, ensure_ascii=False) + "\n")
    write_report(report, os.path.join(args.outdir, "DECEPTION_EVAL.md"))

    print(f"\nEscrito en {args.outdir}/  "
          f"({report['n_judged']} transcripciones juzgadas, "
          f"{report['n_dead']} sesiones muertas).", flush=True)
    for name, score in report["judges"].items():
        print(f"  juez {name}: acierto {score.accuracy:.1%} "
              f"(p={score.p_value:.3f}) -> {score.verdict}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
