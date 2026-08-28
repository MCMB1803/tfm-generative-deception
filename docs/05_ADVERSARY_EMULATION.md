# 05. Emulación de Adversarios y Evaluación Ciega de Credibilidad

> **Este documento define *cómo* se mide la credibilidad. No contiene resultados.**
> Las cifras se generan automáticamente en `evaluation/results/DECEPTION_EVAL.md`
> al ejecutar el arnés, y no se transcriben a mano a ningún otro sitio. Todo
> número citado en la memoria debe proceder de una ejecución concreta de este
> arnés, con sus modelos y su hardware documentados.

---

## 1. La pregunta que responde este capítulo

El capítulo de latencia ([`03`](03_TEST_MATRIX_AND_LATENCY_EVALUATION.md)) responde
a *si el señuelo es rápido* y *si un atacante puede separar las dos rutas por
tiempo*. Ninguna de las dos cosas dice si el contenido de las respuestas **es
creíble**: un host puede responder rápido, de forma temporalmente indistinguible,
y aun así delatarse porque su `/etc/passwd` no cuadra con sus procesos, o porque
un `ls -l` tiene un formato que ningún `coreutils` real produce.

La hipótesis que se valida aquí es:

| ID | Hipótesis | Criterio de aceptación | Instrumento |
|---|---|---|---|
| **H6** | Un observador ciego no distingue el señuelo de un host real mejor que el azar. | Acierto de un juez ciego no significativamente por encima del 50 % (test binomial, muestra equilibrada). | `evaluation/run_deception_eval.py` |

El criterio es deliberadamente el mismo tipo de afirmación que el de
indistinguibilidad temporal: no «la media supera un umbral», sino «un
clasificador no separa las dos poblaciones», contrastado con un test estadístico
sobre una muestra equilibrada.

---

## 2. Diseño experimental

Tres piezas, ninguna de las cuales puede juzgarse a sí misma.

### 2.1. Dos brazos: el señuelo y un control real

El señuelo no se evalúa en el vacío, sino **contra un host Linux real** que actúa
como control. Ambos se publican por SSH, cada uno en su puerto de loopback, y se
interrogan con el mismo instrumento:

```text
attacker --SSH:2222--> ssh-decoy      (framework, el sistema bajo prueba)
attacker --SSH:2223--> real-host      (Debian 12 + sshd real, control)
```

El control (`evaluation/real_host/`, servicio `real-host` bajo el perfil `eval`)
es un Debian **sin adornos**: sin historial plantado, sin ficheros de negocio
sintéticos, sin honeytokens. Todo lo que el atacante ve en ese brazo lo produce
el `coreutils` real, el `/proc` real y el `sshd` real. Un sistema recién
instalado y sin historial es un host real perfectamente ordinario, y usar uno
vanilla mantiene honesta la comparación: si el juez separa los brazos, separa
«generado» de «real», no «decorado» de «desnudo».

### 2.2. El atacante: un LLM adaptativo

Un modelo con root sobre SSH y un solo objetivo —decidir si el host es real o un
señuelo— elige cada comando en función de la salida del anterior. Esta
adaptación es justamente lo que una lista fija de comandos no puede emular: un
`/etc/passwd` sospechoso merece un seguimiento, un `ls` aburrido pasa página.

El arnés mantiene las barreras: presupuesto fijo de turnos, salida estructurada
(un turno es un comando, nunca texto libre) y una **lista de denegación** que
separa nombres de comando de subcadenas —bloquear `passwd` como subcadena
rechazaría `cat /etc/passwd`, el comando de reconocimiento más importante de la
batería; solo `passwd` **invocado como comando** es peligroso—. Se inspecciona
además el primer token de cada etapa de una tubería o encadenamiento, de modo
que `whoami; rm -rf /` se bloquea aunque su primer token sea inofensivo. El
control real debe volver intacto de cada ejecución.

**Suelo de evidencia: `--min-turns`.** La primera ejecución de referencia falló
por un motivo que conviene dejar documentado, porque no es un fallo de código
sino de método. Con `qwen2.5-coder:0.5b` al mando, **doce de dieciséis sesiones
terminaron con cero comandos ejecutados**: el modelo respondía `done: true,
verdict: "real"` en su primera réplica, antes de tocar el host. El juez recibía
entonces transcripciones vacías, y el resultado —50 % de acierto sobre n=4— no
medía credibilidad alguna.

De ahí dos correcciones. La primera es un **suelo de evidencia**: el arnés
rechaza el veredicto mientras el atacante no haya ejecutado al menos
`--min-turns` comandos (cinco por defecto), y le devuelve el turno pidiéndole
otro comando. Es un mínimo de trabajo, no un empujón hacia una conclusión: al
modelo se le dice que siga mirando, nunca qué debe encontrar. La segunda es
cambiar el atacante por **`llama3.2:3b`**, de una familia distinta a la del
señuelo (`qwen2.5-coder`) y a la del juez (`qwen2.5`), de modo que ninguno de
los tres papeles pueda reconocer su propia salida. `tests/test_evaluation.py`
fija el suelo con un modelo simulado que insiste en concluir en el turno cero.

El veredicto que el propio atacante emite al final se **registra pero no es el
resultado principal**: el atacante sabe que busca un honeypot, así que está
sesgado a gritar «señuelo». Se reporta como señal adversaria secundaria.

### 2.3. El juez ciego: la medida justa

La medida principal la da un juez que lee **una sola transcripción**, sin saber
de qué brazo procede ni que hay un honeypot en la muestra. Solo se le pide
separar una sesión real de una generada.

Tres garantías, impuestas por la estructura del código y no por convención:

- **Ceguera de brazo.** El juez recibe `Transcript.blind_text()`, que se
  construye solo a partir de lo que cruzó el cable (versión SSH, banner, prompt,
  comandos, salida) y depura el endpoint de captura: los dos brazos escuchan
  necesariamente en puertos distintos, y un `2223` suelto en el texto decidiría
  el veredicto por sí solo. La etiqueta de brazo, el puerto y la justificación
  del atacante existen en el objeto, pero no en lo que el juez ve. Una fuga
  tendría que ser una edición de esa función, no un descuido en otro sitio.
- **Sin cebo de honeypot.** No se le dice que hay un señuelo en la muestra.
  Cebarlo para cazar honeypots inflaría el recall de señuelo a costa de marcar
  hosts reales, y la matriz de confusión mentiría.
- **Clasificación independiente.** El juez nunca ve dos transcripciones a la vez;
  no puede calibrar «esta es más real que aquella» y colar la tasa base por la
  puerta de atrás.

**Dos jueces, no uno.** El juez principal es un modelo mayor e independiente del
generador (por defecto `qwen2.5:7b`); el segundo es el propio modelo del señuelo
(`qwen2.5-coder:0.5b`). Que el generador se juzgue a sí mismo no sería evidencia,
así que su veredicto se reporta como contraste, no como medida. El **acuerdo
entre ambos** (Cohen κ) es en sí un resultado: si dos modelos de tamaños muy
distintos coinciden en no superar el azar, la conclusión descansa sobre una
propiedad del engaño y no sobre el capricho de un modelo.

---

## 3. Estadística

Todo sobre la biblioteca estándar, sin numpy ni scipy, coherente con el resto
del proyecto (`evaluation/metrics.py`).

| Estadístico | Qué mide | Lectura buscada |
|---|---|---|
| Acierto + **test binomial exacto** vs 0,5 | Con muestra equilibrada, un juez inútil acierta el 50 %. El binomial mide cómo de sorprendente sería el número de aciertos observado bajo puro azar. | p-valor alto: indistinguible del azar. |
| **Matriz de confusión** y recall por clase | El acierto solo esconde el modo de fallo que importa: un juez que siempre dice «señuelo» acierta el 50 % en muestra equilibrada mientras detecta todos los señuelos. | Recalls equilibrados, no un 100/0. |
| **Cohen κ** entre jueces | Dos jueces coincidiendo prueban poco si coinciden por azar; κ descuenta el acuerdo esperado por las tasas base. | κ alto sobre las mismas transcripciones: reaccionan a las mismas señales. |

Se reporta la misma asimetría que en el capítulo de latencia: **el binomial puede
demostrar que un juez separa las dos poblaciones, pero un p-valor alto es
evidencia de indistinguibilidad al tamaño de muestra empleado, no una prueba de
que el engaño sea perfecto.** La medida se fortalece ampliando `--sessions` y
contrastando los dos jueces.

Las respuestas ilegibles del juez (un modelo pequeño que envuelve el JSON en
prosa) se **excluyen** del contraste y se cuentan aparte; nunca se puntúan como
error, porque hacerlo culparía al engaño de un fallo de formato del juez.

---

## 4. Reproducción

Requiere la pila levantada, el control real bajo el perfil `eval`, y el modelo
juez descargado en Ollama.

```bash
# 1. Levantar el control real junto a la pila
docker compose --profile eval up -d --build real-host

# 2. Descargar el juez principal (una vez; ~5 GB)
docker exec ollama_llm ollama pull qwen2.5:7b

# 3. Ejecutar el arnés desde el host (necesita paramiko y requests)
pip install -r evaluation/requirements.txt
python evaluation/run_deception_eval.py --sessions 8
```

Escribe en `evaluation/results/`:

| Fichero | Contenido |
|---|---|
| `transcripts.jsonl` | Una línea por sesión: brazo, endpoint, turnos, veredicto del atacante. |
| `verdicts.jsonl` | Un veredicto por (juez × transcripción), con la verdad de terreno. |
| `DECEPTION_EVAL.md` | Tablas maquetadas para la memoria. **Se regenera: no editar a mano.** |

### Opciones

| Opción | Def. | Qué controla |
|---|---|---|
| `--sessions` | 8 | Sesiones del atacante por brazo (real y señuelo). Total = 2 × sesiones. |
| `--judge-model` | `qwen2.5:7b` | Juez principal, independiente del generador. |
| `--second-judge-model` | `qwen2.5-coder:0.5b` | Segundo juez (el propio generador), para contraste. |
| `--attacker-model` | `llama3.2:3b` | Modelo que conduce el ataque. Familia distinta a la del señuelo y a la del juez. |
| `--min-turns` | `5` | Comandos que el atacante debe ejecutar antes de poder emitir veredicto. Evita sesiones vacías e injuzgables. |
| `--max-turns` | 12 | Presupuesto de comandos por sesión. |
| `--seed` | 1803 | Semilla del barajado ciego (fija el orden, no el muestreo de los modelos). |
| `--decoy-port` / `--real-port` | 2222 / 2223 | Puertos de los dos brazos. |
| `--pull` | — | Descargar los modelos que falten antes de empezar. |

Con la semilla fija el **orden** de clasificación ciega es reproducible; el
atacante y los jueces siguen corriendo con el muestreo propio de los modelos, de
modo que transcripciones y veredictos varían entre ejecuciones y se reportan
sobre N sesiones, igual que el capítulo de latencia reporta distribuciones y no
valores puntuales.

---

## 5. Pruebas offline

`tests/test_evaluation.py` ejercita, sin Docker ni Ollama ni red, lo que debe
ser correcto pase lo que pase el modelo: que el render ciego no filtre el brazo
ni el puerto, que la depuración conserve un número que no sea el puerto del
endpoint (un tamaño de fichero en un `ls -l`), la estadística (binomial, κ,
recalls, exclusión de ilegibles) y la barrera de seguridad del atacante. Las
partes conducidas por modelo se validan en una ejecución real contra los dos
brazos.

```bash
python tests/test_evaluation.py     # sin dependencias
```

---

## 6. Limitaciones

- **El control es un host recién instalado.** Es un host real legítimo, pero sin
  historial de uso; un trabajo futuro compararía también contra un host con
  historial genuino, para separar «generado vs real» de «nuevo vs usado».
- **El juez es un LLM.** Un juez humano experto es el patrón oro; el juez LLM es
  reproducible y barato, y el contraste de dos modelos acota su idiosincrasia,
  pero no la elimina.
- **Cowrie queda para la comparativa siguiente.** El mismo arnés admite un tercer
  brazo (`--*-port`) sin cambios de código: apuntar el atacante a un Cowrie
  desplegado y volver a puntuar es la fase de comparación con el estado del arte.
