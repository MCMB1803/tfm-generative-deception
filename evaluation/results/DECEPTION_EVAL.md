# Emulacion de adversarios y juez ciego

Generado automaticamente por `evaluation/run_deception_eval.py` el 2026-08-23T23:51:38.325845+00:00. **No editar a mano**: se regenera en cada ejecucion.

La pregunta de este capitulo no es si el senuelo responde rapido, sino si **es creible**: puesto a un observador que no sabe cual es cual, ¿distingue el senuelo de un host real? Se mide con un juez ciego sobre transcripciones reales de un atacante LLM adaptativo, contra un host Linux real como control.

## 1. Montaje

| Parametro | Valor |
|---|---|
| Sesiones por arm | 8 |
| Arm senuelo | `127.0.0.1:2222` |
| Arm real (control) | `127.0.0.1:2223` |
| Atacante | `llama3.2:3b` |
| Juez principal | `qwen2.5:7b` |
| Segundo juez | `qwen2.5-coder:0.5b` |
| Turnos maximos por sesion | 12 |
| Semilla de barajado ciego | 1803 |

Transcripciones recogidas: **16** (8 senuelo, 8 real). Juzgadas: **16**. Sesiones muertas (sin turnos o con error de conexion): **0**.

## 2. Resultado del juez ciego

El juez ve una sola transcripcion, sin etiqueta de arm ni puerto, y no se le dice que hay un honeypot en la muestra: solo se le pide separar una sesion real de una generada. Con la muestra equilibrada al 50 %, un juez inutil acierta el 50 %. **El resultado buscado es que no supere el azar.**

| Juez | n | Aciertos | Acierto | p (binomial vs azar) | Recall real | Recall decoy | Veredicto |
|---|---|---|---|---|---|---|---|
| `qwen2.5:7b` (principal) | 15 | 7 | 46.7 % | 1.0000 | 12.5 % | 75.0 % | **INDISTINGUIBLE** |
| `qwen2.5-coder:0.5b` | 16 | 9 | 56.2 % | 0.8036 | 100.0 % | 12.5 % | **INDISTINGUIBLE** |

- **`qwen2.5:7b`** — El juez no supera el azar de forma significativa: sobre estas transcripciones el senuelo no es separable de un host real.
  - 1 respuestas ilegibles, excluidas del contraste (no contadas como error del engano).
- **`qwen2.5-coder:0.5b`** — El juez no supera el azar de forma significativa: sobre estas transcripciones el senuelo no es separable de un host real.

## 3. Matrices de confusion

La exactitud sola esconde el modo de fallo que importa: un juez que siempre dice "decoy" acierta el 50 % en muestra equilibrada mientras detecta todos los senuelos. Las matrices lo hacen visible.

### `qwen2.5:7b`

| Verdad \ Juez | dice real | dice decoy | ilegible |
|---|---|---|---|
| **real** | 1 | 7 | 0 |
| **decoy** | 1 | 6 | 1 |

Confianza media declarada por el juez: 83.7 %.

### `qwen2.5-coder:0.5b`

| Verdad \ Juez | dice real | dice decoy | ilegible |
|---|---|---|---|
| **real** | 8 | 0 | 0 |
| **decoy** | 7 | 1 | 0 |

Confianza media declarada por el juez: 96.3 %.

## 4. Acuerdo entre jueces (Cohen kappa)

| Estadistico | Valor |
|---|---|
| Transcripciones clasificadas por ambos | 15 |
| Acuerdo observado | 20.0 % |
| Acuerdo esperado por azar | 18.2 % |
| Cohen kappa | 0.022 |

Acuerdo leve (kappa=0.02). Un acuerdo alto sobre las mismas transcripciones indica que ambos jueces reaccionan a las mismas senales, no a un capricho de un modelo.

## 5. Autoevaluacion del atacante (senal secundaria)

| | |
|---|---|
| Sesiones con veredicto propio | 1 / 16 |
| Aciertos del atacante | 1 |
| Acierto del atacante | 100.0 % |

> El atacante sabe que busca un senuelo; su acierto se reporta como senal adversaria secundaria, no como la medida ciega.

## 6. Lectura

El contraste binomial, como el KS del capitulo de latencia, puede demostrar que un juez **separa** las dos poblaciones, pero un p-valor alto es evidencia de indistinguibilidad al tamano de muestra empleado, no una prueba de que el engano sea perfecto. La medida se fortalece ampliando `--sessions` y contrastando los dos jueces: si ambos, de tamanos muy distintos, coinciden en no superar el azar, la conclusion descansa sobre algo mas que un modelo concreto.

