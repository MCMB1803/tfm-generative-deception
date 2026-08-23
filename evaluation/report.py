"""Renders the credibility results into the Markdown the report cites.

Same contract as the latency benchmark's RESULTS.md: this file is regenerated
on every run and must never be hand-edited, so a number in the report can
always be traced back to an execution that produced it.
"""
from __future__ import annotations


def _pct(x: float) -> str:
    return f"{x * 100:.1f} %"


def _confusion_table(conf: dict) -> list:
    lines = [
        "| Verdad \\ Juez | dice real | dice decoy | ilegible |",
        "|---|---|---|---|",
    ]
    for truth in ("real", "decoy"):
        row = conf[truth]
        lines.append(f"| **{truth}** | {row['real']} | {row['decoy']} | "
                     f"{row['unparsed']} |")
    return lines


def write_report(report: dict, path: str) -> None:
    cfg = report["config"]
    lines: list = []
    a = lines.append

    a("# Emulacion de adversarios y juez ciego")
    a("")
    a(f"Generado automaticamente por `evaluation/run_deception_eval.py` el "
      f"{report['generated_at']}. **No editar a mano**: se regenera en cada "
      f"ejecucion.")
    a("")
    a("La pregunta de este capitulo no es si el senuelo responde rapido, sino "
      "si **es creible**: puesto a un observador que no sabe cual es cual, "
      "¿distingue el senuelo de un host real? Se mide con un juez ciego sobre "
      "transcripciones reales de un atacante LLM adaptativo, contra un host "
      "Linux real como control.")
    a("")

    # -- configuration --------------------------------------------------------
    a("## 1. Montaje")
    a("")
    a("| Parametro | Valor |")
    a("|---|---|")
    a(f"| Sesiones por arm | {cfg['sessions_per_arm']} |")
    a(f"| Arm senuelo | `{cfg['arms']['framework']}` |")
    a(f"| Arm real (control) | `{cfg['arms']['real']}` |")
    a(f"| Atacante | `{cfg['attacker_model']}` |")
    a(f"| Juez principal | `{cfg['judge_model']}` |")
    a(f"| Segundo juez | `{cfg['second_judge_model'] or '—'}` |")
    a(f"| Turnos maximos por sesion | {cfg['max_turns']} |")
    a(f"| Semilla de barajado ciego | {cfg['seed']} |")
    a("")
    a(f"Transcripciones recogidas: **{report['n_collected']}** "
      f"({report['arm_counts'].get('framework', 0)} senuelo, "
      f"{report['arm_counts'].get('real', 0)} real). "
      f"Juzgadas: **{report['n_judged']}**. "
      f"Sesiones muertas (sin turnos o con error de conexion): "
      f"**{report['n_dead']}**.")
    a("")

    # -- headline -------------------------------------------------------------
    a("## 2. Resultado del juez ciego")
    a("")
    a("El juez ve una sola transcripcion, sin etiqueta de arm ni puerto, y no "
      "se le dice que hay un honeypot en la muestra: solo se le pide separar "
      "una sesion real de una generada. Con la muestra equilibrada al 50 %, un "
      "juez inutil acierta el 50 %. **El resultado buscado es que no supere el "
      "azar.**")
    a("")
    a("| Juez | n | Aciertos | Acierto | p (binomial vs azar) | Recall real | "
      "Recall decoy | Veredicto |")
    a("|---|---|---|---|---|---|---|---|")
    for name, s in report["judges"].items():
        tag = " (principal)" if name == report["primary_judge"] else ""
        a(f"| `{name}`{tag} | {s.n - s.unparseable} | {s.correct} | "
          f"{_pct(s.accuracy)} | {s.p_value:.4f} | {_pct(s.real_recall)} | "
          f"{_pct(s.decoy_recall)} | **{s.verdict}** |")
    a("")
    for name, s in report["judges"].items():
        a(f"- **`{name}`** — {s.reading}")
        if s.unparseable:
            a(f"  - {s.unparseable} respuestas ilegibles, excluidas del "
              f"contraste (no contadas como error del engano).")
    a("")

    # -- confusion ------------------------------------------------------------
    a("## 3. Matrices de confusion")
    a("")
    a("La exactitud sola esconde el modo de fallo que importa: un juez que "
      "siempre dice \"decoy\" acierta el 50 % en muestra equilibrada mientras "
      "detecta todos los senuelos. Las matrices lo hacen visible.")
    a("")
    for name, s in report["judges"].items():
        a(f"### `{name}`")
        a("")
        lines.extend(_confusion_table(s.confusion))
        a("")
        a(f"Confianza media declarada por el juez: {_pct(s.mean_confidence)}.")
        a("")

    # -- kappa ----------------------------------------------------------------
    if report.get("kappa") is not None:
        k = report["kappa"]
        a("## 4. Acuerdo entre jueces (Cohen kappa)")
        a("")
        a("| Estadistico | Valor |")
        a("|---|---|")
        a(f"| Transcripciones clasificadas por ambos | {k.n} |")
        a(f"| Acuerdo observado | {_pct(k.observed)} |")
        a(f"| Acuerdo esperado por azar | {_pct(k.expected)} |")
        a(f"| Cohen kappa | {k.kappa:.3f} |")
        a("")
        a(k.reading)
        a("")

    # -- attacker -------------------------------------------------------------
    at = report["attacker"]
    a("## 5. Autoevaluacion del atacante (senal secundaria)")
    a("")
    a("| | |")
    a("|---|---|")
    a(f"| Sesiones con veredicto propio | {at.guessed} / {at.n} |")
    a(f"| Aciertos del atacante | {at.correct} |")
    a(f"| Acierto del atacante | {_pct(at.accuracy)} |")
    a("")
    a("> " + at.note)
    a("")

    # -- caveat ---------------------------------------------------------------
    a("## 6. Lectura")
    a("")
    a("El contraste binomial, como el KS del capitulo de latencia, puede "
      "demostrar que un juez **separa** las dos poblaciones, pero un p-valor "
      "alto es evidencia de indistinguibilidad al tamano de muestra empleado, "
      "no una prueba de que el engano sea perfecto. La medida se fortalece "
      "ampliando `--sessions` y contrastando los dos jueces: si ambos, de "
      "tamanos muy distintos, coinciden en no superar el azar, la conclusion "
      "descansa sobre algo mas que un modelo concreto.")
    a("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
