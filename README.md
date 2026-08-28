# Generative Deception Framework (TFM · UCM)

Señuelo SSH de ciberengaño dinámico guiado por una arquitectura multi-agente y un modelo de lenguaje local (Ollama), para la detección temprana de intrusiones en entornos corporativos.

**Este README es la guía de reproducción.** Contiene los pasos exactos para levantar el sistema, re-ejecutar el banco de pruebas y obtener las cifras de la memoria, junto con el entorno de referencia en que se midieron y las condiciones bajo las que son —y no son— reproducibles.

---

## Índice

- [Generative Deception Framework (TFM · UCM)](#generative-deception-framework-tfm--ucm)
  - [Índice](#índice)
  - [1. Qué hace el sistema](#1-qué-hace-el-sistema)
    - [La decisión de diseño central: resolución híbrida](#la-decisión-de-diseño-central-resolución-híbrida)
  - [2. Arquitectura](#2-arquitectura)
  - [3. Reproducción rápida](#3-reproducción-rápida)
    - [Requisitos](#requisitos)
    - [Levantar la pila](#levantar-la-pila)
    - [Comprobar que está en pie](#comprobar-que-está-en-pie)
    - [Pruebas offline (no necesitan Docker ni Ollama)](#pruebas-offline-no-necesitan-docker-ni-ollama)
  - [4. Entorno de referencia](#4-entorno-de-referencia)
    - [El tamaño del modelo es una decisión, no un ajuste](#el-tamaño-del-modelo-es-una-decisión-no-un-ajuste)
  - [5. Fijar las versiones](#5-fijar-las-versiones)
  - [6. Re-ejecutar el banco de pruebas](#6-re-ejecutar-el-banco-de-pruebas)
    - [Opciones](#opciones)
  - [7. Qué es reproducible y qué no](#7-qué-es-reproducible-y-qué-no)
  - [8. Resultados de referencia](#8-resultados-de-referencia)
  - [9. Telemetría para el SOC](#9-telemetría-para-el-soc)
  - [10. Estructura del repositorio](#10-estructura-del-repositorio)
  - [11. Estado del proyecto](#11-estado-del-proyecto)
  - [12. Emulación de adversarios y credibilidad](#12-emulación-de-adversarios-y-credibilidad)
    - [Resultados del juez ciego](#resultados-del-juez-ciego)
    - [Suite offline](#suite-offline)
  - [13. Comparativa con un honeypot tradicional](#13-comparativa-con-un-honeypot-tradicional)
    - [Resultados de la comparativa](#resultados-de-la-comparativa)
  - [14. Trazabilidad: qué respalda cada apartado de la memoria](#14-trazabilidad-qué-respalda-cada-apartado-de-la-memoria)
    - [Qué queda fuera, declarado](#qué-queda-fuera-declarado)
  - [15. Demostración en vivo](#15-demostración-en-vivo)
    - [Antes de empezar (hazlo el día antes, no delante del tribunal)](#antes-de-empezar-hazlo-el-día-antes-no-delante-del-tribunal)
    - [El guion](#el-guion)
    - [El lado del defensor (la mitad que se olvida enseñar)](#el-lado-del-defensor-la-mitad-que-se-olvida-enseñar)
    - [Si hay tiempo: las tres piezas de evaluación](#si-hay-tiempo-las-tres-piezas-de-evaluación)
    - [Al terminar](#al-terminar)
    - [Fallos que pueden ocurrir](#fallos-que-pueden-ocurrir)
  - [Créditos](#créditos)
  - [Aviso](#aviso)

---

## 1. Qué hace el sistema

Implementación práctica del Trabajo Fin de Máster (**Máster en Ciberseguridad — Universidad Complutense de Madrid**). El objetivo es desplegar una solución de defensa activa capaz de superar las limitaciones de los *honeypots* estáticos, que un atacante identifica en segundos por su falta de historial, sus servicios inertes y sus respuestas incoherentes.

El sistema despliega un señuelo SSH que mantiene una **identidad de host coherente**, la puebla con **artefactos sintéticos** (historiales de shell, ficheros de negocio, credenciales trampa, logs que siguen creciendo) y resuelve la interacción con el atacante mediante **cuatro agentes especializados** apoyados en un LLM cuantizado ejecutado en local, sin ninguna dependencia de APIs externas.

### La decisión de diseño central: resolución híbrida

Cada comando toma una de dos rutas:

| Ruta | Qué resuelve | Coste | Propiedad que aporta |
|---|---|---|---|
| **Determinista** | Reconocimiento (`whoami`, `uname`, `cat /etc/passwd`, `ls`, `ps`, `ip a`…) resuelto desde la persona y el sistema de ficheros de artefactos. | microsegundos | Coherencia exacta y estable durante toda la sesión. |
| **Generativa** | Todo lo demás, enviado al LLM local con la persona y los últimos turnos como contexto. | inferencia | Cobertura ilimitada de comandos, sin respuestas pregrabadas. |

Enviar todos los comandos al modelo sería más simple y peor: gastaría el presupuesto de latencia en trivialidades y devolvería un `/etc/passwd` distinto cada vez, que es justamente la incoherencia que delata la trampa. No enviar ninguno reconstruiría un honeypot estático. La división compra las dos propiedades a la vez.

Esta división es también la causa del principal problema abierto del proyecto: ver [§7](#7-qué-es-reproducible-y-qué-no).

---

## 2. Arquitectura

```text
[ Atacante ]  --SSH:2222-->  ssh-decoy  --HTTP-->  deception-agent  --HTTP-->  ollama-llm
                             (paramiko)            (4 agentes)                 (qwen2.5-coder:0.5b)
                              EXPUESTO              INTERNO                     INTERNO
                                                        │
                                                        ▼  JSON Lines -> SIEM
```

Solo `ssh-decoy` se publica al exterior. El orquestador y el motor de inferencia se publican **únicamente en loopback** (`127.0.0.1`), para que el banco de pruebas pueda medirlos sin que sean alcanzables desde la red del atacante.

| Agente | Cuándo | Responsabilidad | Fichero |
|---|---|---|---|
| **Persona** | Arranque | Quién dice ser el host: empresa, usuarios, `/etc/passwd`, red, procesos. | `agents/roles/persona.py` |
| **Artefactos** | Arranque + hilo continuo | Qué hay en el host: ficheros, honeytokens, `.bash_history`, tráfico de logs simulado. | `agents/roles/artifacts.py` |
| **Terminal** | Por comando | Qué responde el host, por la ruta determinista o la generativa. | `agents/roles/terminal.py` |
| **Alertas** | Por evento | Qué se le cuenta al SOC: técnica ATT&CK, severidad, telemetría JSON Lines. | `agents/roles/alerting.py` |

Detalle completo en [`docs/01_ARCHITECTURE_AND_TECHNICAL_DESIGN.md`](docs/01_ARCHITECTURE_AND_TECHNICAL_DESIGN.md).

---

## 3. Reproducción rápida

### Requisitos

| | Mínimo | Usado en la medición de referencia |
|---|---|---|
| Docker Engine | 20.10+ | 25.0.3 (Docker Desktop) |
| Docker Compose | v2 | v2.24.6 |
| RAM | 8 GB | 31,7 GB |
| Disco | 10 GB | — |
| Python (solo en el host, para las pruebas) | 3.10+ | 3.11.9 |

### Levantar la pila

```bash
git clone https://github.com/MCMB1803/tfm-generative-deception.git
cd tfm-generative-deception
cp .env.example .env
docker compose up -d --build
```

Un solo comando. El orden de arranque se resuelve con condiciones de salud: `ollama-llm` → `model-puller` (descarga el modelo y termina) → `deception-agent` → `ssh-decoy`. La primera ejecución tarda unos minutos mientras baja el modelo (~400 MB).

### Comprobar que está en pie

```bash
docker compose ps                                          # los 3 servicios "healthy"/"running"
curl -s http://127.0.0.1:8000/health                       # {"status":"ok","ready":true}
curl -s http://127.0.0.1:8000/stats | python -m json.tool   # modelo, persona, contadores
ssh root@localhost -p 2222                                  # cualquier contraseña vale
```

Guía completa y troubleshooting en [`docs/02_DEPLOYMENT_AND_TROUBLESHOOTING_GUIDE.md`](docs/02_DEPLOYMENT_AND_TROUBLESHOOTING_GUIDE.md).

### Pruebas offline (no necesitan Docker ni Ollama)

```bash
python tests/test_core.py          # 102/102  nucleo del orquestador
python tests/test_evaluation.py    # 56/56    arnes de evaluacion ciega
pip install pytest && pytest tests/test_comparison.py -q   # 19 passed
```

Las dos primeras sustituyen el cliente LLM por un doble de prueba y **no requieren instalar nada**: código de salida 0 y el recuento impreso al final. `test_core.py` ejercita la capa determinista —coherencia de la persona entre llamadas, sistema de ficheros virtual, mapeo ATT&CK, higiene de la salida, binarios ausentes—, el presupuesto de generación y **el equilibrio real de la suite `paired`**: resuelve sus 18 comandos y comprueba que cada uno toma la ruta y la clase que declara, que es el defecto de método que estropeó la primera ejecución de referencia y que no necesitaba Docker para detectarse. `test_evaluation.py` cubre el render ciego, la estadística y la barrera de seguridad del atacante; `test_comparison.py`, el *scoring* de la comparativa con Cowrie (es la única que usa `pytest`).

---

## 4. Entorno de referencia

Toda cifra de latencia depende del hardware. Las de [§8](#8-resultados-de-referencia) se midieron en:

| | |
|---|---|
| CPU | Intel Core i7-13700 (13.ª gen.), 16 núcleos / 24 hilos |
| RAM | 31,7 GB |
| GPU | Intel UHD Graphics integrada — **sin CUDA: la inferencia corre en CPU** |
| SO | Windows 11 Pro 22631 |
| Contenedores | Docker Desktop 25.0.3, Compose v2.24.6 |
| Modelo | `qwen2.5-coder:0.5b` |
| Parámetros | `MAX_TOKENS=64`, `TEMPERATURE=0.3`, `SESSION_CONTEXT_TURNS=6`, `PERSONA_SEED=1803`, `LATENCY_NORMALIZE=true` |

Que no haya GPU no es un defecto que ocultar: es la condición realista de un despliegue en un servidor corporativo cualquiera, y las cifras deben leerse así. En una máquina con CUDA la ruta generativa será sustancialmente más rápida y **los resultados de [§8](#8-resultados-de-referencia) no se reproducirán**; lo que debe reproducirse es la *metodología*, no el número absoluto.

### El tamaño del modelo es una decisión, no un ajuste

El proyecto se desarrolló con `qwen2.5-coder:3b` y se midió con `qwen2.5-coder:0.5b`. El cambio no fue una optimización menor: es el compromiso central del trabajo y la memoria debe presentarlo como tal.

| | `qwen2.5-coder:0.5b` **(por defecto)** | `qwen2.5-coder:3b` |
|---|---|---|
| Parámetros / peso en disco | 0,5 · 10⁹ — ~400 MB | 3 · 10⁹ — ~2 GB |
| Velocidad en la CPU de referencia | ~11 ms/token | ~45 ms/token |
| Ruta generativa, sin normalizar | dentro de la banda de 1 s | ~2.044 ms ± 7,3 |
| Indistinguibilidad temporal ([§8](#8-resultados-de-referencia)) | alcanzable | **inalcanzable** |
| Calidad de la salida inventada | pobre: formatos poco verosímiles, más rupturas de personaje | notablemente mejor |

El argumento es el siguiente. La ruta determinista resuelve en ~2 ms. La normalización de latencia solo puede **añadir** tiempo, nunca quitarlo, de modo que la banda temporal común la fija el componente lento. Con el 3b la ruta generativa medía **2.044,4 ms ± 7,3** frente a **2,4 ms ± 1,6** de la determinista (`agents/core/latency.py`): dos poblaciones limpias separadas por dos segundos, que ninguna cantidad de relleno puede juntar dentro de un objetivo de 1.000 ms. Con el 0.5b sí caben las dos.

Lo que se paga es **credibilidad del contenido**, y se paga donde se ve: la divergencia frente al host real es de 8 sobre 30 comandos ([§13](#13-comparativa-con-un-honeypot-tradicional)) y el juez ciego principal resultó degenerado ([§12](#12-emulación-de-adversarios-y-credibilidad)). La conclusión defendible es que **el trabajo compra indistinguibilidad temporal a costa de fidelidad generativa**, no que consiga ambas.

Para medir el otro extremo, basta cambiar una línea de `.env` y volver a lanzar el banco:

```bash
MODEL_NAME=qwen2.5-coder:3b
MAX_TOKENS=64
LATENCY_NORMALIZE=false      # la banda de 1.000 ms es inalcanzable con el 3b
```

Esa ejecución es la **línea base sin normalizar** del capítulo 4 y produce la bimodalidad que [§7](#7-qué-es-reproducible-y-qué-no) describe. Debe reportarse junto a la del 0.5b, no en su lugar: la comparación entre ambas *es* el resultado.

---

## 5. Fijar las versiones

Por defecto el proyecto usa etiquetas móviles (`ollama/ollama:latest`, `qwen2.5-coder:0.5b`). Es cómodo para desarrollar y **malo para reproducir**: dentro de seis meses esas etiquetas apuntan a otro artefacto. Antes de la ejecución que vaya a citarse en la memoria, registra los identificadores exactos:

```bash
# Digest de la imagen de Ollama
docker image inspect ollama/ollama:latest --format "{{index .RepoDigests 0}}"

# Identificador del modelo descargado
docker exec ollama_llm ollama list
docker exec ollama_llm ollama show qwen2.5-coder:0.5b --modelfile | head -5

# Versiones del entorno
docker version --format "{{.Server.Version}}"
docker compose version
```

Anota la salida junto a los resultados. Para clavar la imagen, sustituye en `docker-compose.yml` `ollama/ollama:latest` por `ollama/ollama@sha256:<digest>`.

---

## 6. Re-ejecutar el banco de pruebas

Con la pila levantada y `requests` disponible en el host (`pip install requests`):

```bash
python benchmarks/latency_benchmark.py --repeat 5 --scenario both
```

El banco conduce el orquestador real a través de la API real, cronometra cada comando y escribe en `benchmarks/results/`:

| Fichero | Contenido |
|---|---|
| `latency_samples.csv` | Una fila por comando ejecutado: latencia, ruta, técnica ATT&CK, fidelidad. |
| `latency_summary.json` | Agregados por ruta, por escenario y por comando. |
| `RESULTS.md` | Tablas ya maquetadas para la memoria. **Se regenera: no editar a mano.** |

### Opciones

| Opción | Valores | Qué controla |
|---|---|---|
| `--scenario` | `recon` · `cold` · `both` | `recon`: una sesión, comandos en orden (ejercita la coherencia de sesión). `cold`: sesión nueva por comando (coste del atacante que entra, ejecuta y sale). |
| `--suite` | `recon` · `generative` · `both` · `paired` · `all` | Qué batería. `recon`: 30 comandos alineados con ATT&CK. `generative`: 10 que caen al modelo. `both`: las dos anteriores. **`paired`: 18 comandos en tres bloques de igual coste en un host real, mitad por cada ruta — la única suite que permite contrastar la indistinguibilidad, y la que produjo [§8](#8-resultados-de-referencia).** `all`: las tres. |
| `--repeat` | entero (def. 3) | Iteraciones completas de la secuencia. |
| `--api` | URL (def. `http://localhost:8000`) | Dónde escucha el orquestador. |
| `--outdir` | ruta (def. `benchmarks/results`) | Dónde escribir. |

La ejecución de referencia de [§8](#8-resultados-de-referencia) fue:

```bash
python benchmarks/latency_benchmark.py --suite paired --scenario recon --repeat 3
```

18 comandos × 3 iteraciones = **54 muestras**, 27 por ruta. Se usa `paired` y no `both` porque `recon` y `generative` reparten sus comandos casi perfectamente por ruta: una comparación estratificada no tendría entonces nada que comparar dentro de cada clase, y la cifra global quedaría confundida por el coste intrínseco de los propios comandos. Para la memoria conviene `--repeat 5` o más: con tres iteraciones los percentiles por comando descansan sobre muy pocos puntos.

> **Regla del proyecto:** ninguna cifra entra en la memoria sin proceder de una ejecución de este banco. No se transcribe ningún número a mano. Metodología, hipótesis y matriz de comandos en [`docs/03_TEST_MATRIX_AND_LATENCY_EVALUATION.md`](docs/03_TEST_MATRIX_AND_LATENCY_EVALUATION.md).

---

## 7. Qué es reproducible y qué no

Conviene ser explícito, porque el sistema tiene una parte determinista y otra estocástica.

**Reproducible de forma exacta:**

- La **persona** y los artefactos. Los genera un PRNG sembrado con `PERSONA_SEED` (por defecto `1803`): mismo valor, mismo hostname, mismos usuarios, mismo `/etc/passwd`, mismos honeytokens. Cambiar la semilla cambia el escenario entero de forma controlada.
- Toda la **ruta determinista** y su fidelidad.
- La suite `tests/test_core.py`, que no depende del modelo.

**No reproducible bit a bit:**

- La **ruta generativa**. Corre con `TEMPERATURE=0.3` y sin semilla fijada en el modelo, de modo que el texto varía entre ejecuciones. Por eso los resultados se reportan como **distribuciones sobre N muestras** (media, mediana, desviación, p95, p99) y no como valores puntuales.
- Las **latencias absolutas**, que dependen del hardware de [§4](#4-entorno-de-referencia).

**Bimodalidad de latencia: de problema abierto a normalizado.** La primera medición sin normalizar era **bimodal** —microsegundos en la ruta determinista frente a ~2 s en la generativa—, dos poblaciones tan limpias y separadas que un atacante que cronometrase respuestas podía deducir que había un modelo detrás. La fase de normalización de latencia ([§11](#11-estado-del-proyecto)) lo aborda con un relleno por clase de comando que iguala las dos rutas, y lo valida con un test estadístico —no «media por debajo de 1.000 ms», sino «un atacante no puede separar las dos rutas por tiempo»— (Kolmogorov-Smirnov, AUC del mejor clasificador temporal y coeficiente de bimodalidad) en [`benchmarks/results/RESULTS.md`](benchmarks/results/RESULTS.md). El contraste puede demostrar que dos distribuciones **difieren**, pero un p-valor alto es evidencia de indistinguibilidad al tamaño de muestra empleado, no una prueba: por eso se reporta también, estratificado por clase de comando, el porcentaje de muestras que exceden su objetivo y no admiten relleno.

**Dos avisos sobre la ejecución de referencia versionada.** Ninguno invalida las cifras, pero ambos deben declararse antes de citarlas:

1. **Se midió con un clasificador de coste que ya no es el que corre.** `agents/core/latency.py::classify` etiquetaba `uname -r` como clase `heavy` (traversal de sistema de ficheros) por confundir el flag `-r` con recursión. El arreglo y el CSV entraron en el mismo commit, de modo que la muestra versionada lleva ese comando en `heavy` mientras que el código actual lo pone en `read_small`. Esto desplaza tres muestras entre clases y es la razón de que `heavy` aparezca con una sola ruta. **Al volver a lanzar el banco, la estratificación de [§8](#8-resultados-de-referencia) cambiará**; la global no.
2. **La suite `paired` no estaba equilibrada por clase cuando se midió.** Estaba escrita para dar tres comandos por ruta en cada uno de los tres bloques, pero el reparto real del orquestador no coincidía con esa intención: `wc -l /etc/passwd` caía a la ruta generativa —`wc` solo está implementado como filtro de tubería, no como lectura de un fichero suelto— y `ss -tulpn` a la determinista, porque `ss` comparte el manejador de `netstat`. El resultado fue `builtin` 9/9, `read_small` 3/12 y `proc_scan` 12/6: solo `builtin` sostenía un contraste con potencia. **Ya está corregido en el código** —esos dos comandos se sustituyen por `cat /etc/hosts` (determinista, misma lectura corta) y `top -bn1` (generativa, mismo escaneo de `/proc`)—, pero **la ejecución versionada de [§8](#8-resultados-de-referencia) es anterior al arreglo y sigue llevando el desequilibrio**. Para que la corrección no se pierda otra vez, el desvío se comprueba ahora en tres sitios: `tests/test_core.py` resuelve los 18 comandos y verifica ruta y clase sin necesidad de Docker, el banco aborta antes de medir si la declaración está desequilibrada, y `RESULTS.md` estampa un aviso sobre la tabla estratificada si el marco no resolvió la suite como se declara.

**Sobre la métrica de fidelidad.** El `fidelity_pass_pct` que aparece en `RESULTS.md` es una **comprobación de subcadenas** contra una lista de tokens esperados escrita a mano (`benchmarks/latency_benchmark.py:146`). Es reproducible por un tercero y sirve como prueba de regresión, pero **no mide que el engaño resulte creíble**: para la ruta determinista, que genera esas salidas desde plantillas, un 100 % es casi tautológico. La evaluación de credibilidad requiere adversario y juez ciego, y se aborda en [§12](#12-emulación-de-adversarios-y-credibilidad).

---

## 8. Resultados de referencia

Ejecución con normalización activa, 54 muestras, objetivo de latencia 1.000 ms. **Cifras siempre desde [`benchmarks/results/RESULTS.md`](benchmarks/results/RESULTS.md), que se regenera en cada ejecución** —la tabla siguiente es un extracto de esa fuente y no debe editarse a mano—.

| Ruta | n | Media | Mediana | Desv. típ. | p95 | Dentro de objetivo |
|---|---|---|---|---|---|---|
| **Global** | 54 | 971,1 ms | 786,3 ms | 486,6 ms | 1.831,9 ms | 83,3 % |
| Determinista | 27 | 855,6 ms | 781,2 ms | 158,4 ms | 1.003,6 ms | 88,9 % |
| Generativa | 27 | 1.086,6 ms | 912,0 ms | 655,7 ms | 2.829,5 ms | 77,8 % |

Con el relleno activo la métrica que importa no es la media, sino si las dos rutas son separables por tiempo. El veredicto **global** es **INDISTINGUIBLE**: KS D = 0,22 con p = 0,47, AUC = 0,50, ventaja del atacante 0,1 %.

**Pero el global está confundido y la estratificación lo desmiente en una clase.** La ruta que toma un comando la decide el propio comando, de modo que los comandos de la ruta lenta son también los intrínsecamente más costosos en un host real; solo la comparación dentro de una misma clase elimina esa confusión:

| Clase | n det. | n gen. | KS D | p | AUC | Ventaja | Veredicto |
|---|---|---|---|---|---|---|---|
| `builtin` | 9 | 9 | 0,22 | 0,957 | 0,494 | 1,2 % | **INDISTINGUIBLE** |
| `proc_scan` | 12 | 6 | 1,00 | **0,000156** | **1,00** | **100 %** | **SEPARABLE** |
| `read_small` | 3 | 12 | 0,42 | 0,669 | 0,444 | 11,1 % | Insuficiente |
| `heavy` | 3 | 0 | — | — | — | — | Sin comparación |

En `proc_scan` **el atacante acierta el 100 %**: todas las respuestas generativas de esa clase son más lentas que todas las deterministas. Los responsables están identificados en la tabla por comando de `RESULTS.md` — `lsblk` (2.840,2 ms de media, 0 % dentro de objetivo) y `vmstat 1 1` (1.236,5 ms, 0 %) — y son también los 7 comandos (12,96 %) que excedieron su objetivo y no admitieron relleno.

La lectura honesta para la memoria es por tanto:

> La normalización cierra el canal lateral temporal **en la clase donde hay potencia para contrastarlo** (`builtin`) y **no lo cierra** en `proc_scan`, donde la salida generativa es lo bastante larga como para desbordar el presupuesto. El resultado global de indistinguibilidad no debe citarse sin esta salvedad.

Es un resultado accionable, no un fracaso, y la acción ya está implementada —pero **estas cifras son anteriores a ella y no la reflejan**.

**El arreglo: presupuesto de generación por clase.** El desbordamiento tiene una única causa mecánica, visible en el CSV: las seis muestras de `lsblk` y `vmstat 1 1` agotan las 64 unidades de `MAX_TOKENS`, y una respuesta que sigue escribiéndose cuando su objetivo ya venció no se puede rellenar hacia atrás. `agents/core/latency.py::GenerationBudget` convierte ahora el objetivo sorteado en un presupuesto de tokens antes de llamar al modelo, a partir del mismo modelo de coste que fija ese objetivo:

```text
llm_ms  ≈  evaluación del prompt  +  tokens × ms por token
tokens  =  (objetivo × GEN_SAFETY − evaluación del prompt) / ms por token
```

Los dos términos no se suponen: Ollama los devuelve en cada respuesta y el presupuesto los reestima con una media móvil, de modo que **se ajusta a la máquina en la que corre** en vez de dar por buenas las cifras de [§4](#4-entorno-de-referencia). Cuando el resultado no llega al suelo de plausibilidad (`GEN_MIN_TOKENS`), el problema es el término fijo y no el marginal, así que se recorta primero el contexto replicado —menos turnos y truncado más duro, que es lo único que baja el coste de evaluar el prompt— y solo después se responde igualmente al suelo, marcando el plan como `gen_feasible=false` para que ese desbordamiento quede atribuido en la telemetría en lugar de aparecer sin explicación.

Con la calibración que se desprende de la propia ejecución de referencia (~39 ms/token, ~260 ms de evaluación de prompt), el presupuesto proyecta unos 600 ms para los comandos de `proc_scan` frente a objetivos de 740–970 ms: dentro de banda. **Lo que se paga es fidelidad**, y esta vez es medible: el CSV registra ahora `prompt_eval_ms`, `eval_ms`, `gen_max_tokens` y `output_bytes`, así que la memoria puede enseñar la curva en vez de afirmarla. `GEN_MIN_TOKENS` es la perilla de ese compromiso.

Antes de la ejecución definitiva quedan por hacer solo dos cosas, ambas mecánicas: subir a `--repeat 5` o más, y volver a lanzar el banco para que estas cifras reflejen el arreglo y la suite ya equilibrada de [§7](#7-qué-es-reproducible-y-qué-no).

---

## 9. Telemetría para el SOC

Cada interacción produce un evento JSON Lines listo para ingesta por Wazuh o Filebeat, con la técnica MITRE ATT&CK, la severidad y los honeytokens implicados:

```json
{"timestamp": "2026-01-14T10:22:41.882Z", "event_type": "command.executed",
 "severity": "critical", "wazuh_level": 14, "confidence": "confirmed",
 "session_id": "a3f9c1e28b0d4756", "src_ip": "10.42.99.14",
 "command": "cat /root/.ssh/id_rsa", "response_route": "deterministic",
 "latency_ms": 0.31, "honeytokens": ["HT-4C81A9E2"],
 "mitre": [{"technique_id": "T1552.004", "technique": "Unsecured Credentials: Private Keys",
            "tactic": "Credential Access"}]}
```

Los eventos se escriben en el volumen `agent_data`:

```bash
docker compose exec deception-agent tail -f /app/data/logs/deception-events.jsonl
```

Reglas de correlación y configuración de ingesta en [`docs/04_SIEM_INTEGRATION.md`](docs/04_SIEM_INTEGRATION.md). **El SIEM está desplegado y las reglas validadas contra un manager real**: Wazuh 4.9.2 corre bajo el perfil `siem` del compose y `siem/validate_rules.py` contrasta las 10 reglas contra `wazuh-logtest`, con la evidencia en [`benchmarks/results/SIEM_VALIDATION.md`](benchmarks/results/SIEM_VALIDATION.md). Queda fuera el transporte desde un agente remoto y el panel ([§11](#11-estado-del-proyecto)).

---

## 10. Estructura del repositorio

```text
tfm-generative-deception/
├── docker-compose.yml          Pila completa: inferencia, orquestador, señuelo
├── .env.example                Configuración de referencia
├── agents/                     Orquestador multi-agente
│   ├── main.py                 API HTTP (FastAPI)
│   ├── orchestrator.py         Coordinación y ciclo de vida de sesión
│   ├── core/                   config · llm · latency · mitre · session · telemetry
│   └── roles/                  persona · artifacts · terminal · alerting
├── decoys/ssh/                 Frontend de protocolo SSH (paramiko)
├── benchmarks/
│   ├── latency_benchmark.py    Banco de latencia y fidelidad
│   ├── stats.py                KS, AUC y bimodalidad, sin scipy ni numpy
│   ├── resource_monitor.py     Consumo de CPU/RAM por contenedor
│   ├── cowrie_comparison.py    Comparativa de tres brazos con el mismo cliente
│   └── results/                Ejecución de referencia (CSV · JSON · 4 informes)
├── siem/                       Reglas de Wazuh y validador contra el manager
│   ├── validate_rules.py       Contraste de las 10 reglas con wazuh-logtest
│   └── wazuh/local_rules.xml   Fuente de verdad de las reglas
├── evaluation/                 Emulación de adversarios: atacante, juez ciego, métricas
│   ├── run_deception_eval.py   Arnés: recolección + juicio ciego + informe
│   ├── real_host/              Brazo de control (Debian + sshd real)
│   └── results/                Transcripciones · veredictos · DECEPTION_EVAL.md
├── tests/
│   ├── test_core.py            102 comprobaciones del núcleo (sin Docker ni Ollama)
│   ├── test_evaluation.py      56 del arnés de evaluación ciega
│   └── test_comparison.py      19 del scoring de la comparativa (usa pytest)
└── docs/                       Documentación técnica + demo.html
```

---

## 11. Estado del proyecto

- [x] **Infraestructura** — Docker Compose con Ollama, orquestador y señuelo; arranque ordenado por condiciones de salud.
- [x] **Señuelo SSH** — sesión interactiva, captura de credenciales, clave de host persistente, edición de línea real.
- [x] **Agentes de persona y artefactos** — sistema de ficheros virtual, honeytokens, `.bash_history` generado, simulación de tráfico.
- [x] **Telemetría** — JSON Lines con mapeo MITRE ATT&CK y severidad; reglas de Wazuh **escritas**.
- [x] **Despliegue del SIEM** — Wazuh 4.9.2 en el compose bajo el perfil `siem`; las 10 reglas validadas contra el manager real con `siem/validate_rules.py` (evidencia en `benchmarks/results/SIEM_VALIDATION.md`). Queda fuera el transporte desde un agente remoto y el panel.
- [x] **Normalización de latencia** — relleno por clase de comando que hace las dos rutas indistinguibles por tiempo, validado con un test estadístico (KS + AUC + coeficiente de bimodalidad) en [`benchmarks/results/RESULTS.md`](benchmarks/results/RESULTS.md). Incluye la medición de consumo de CPU/RAM por contenedor en [`benchmarks/results/RESOURCES.md`](benchmarks/results/RESOURCES.md).
- [x] **Presupuesto de generación por clase** — el relleno no puede quitar tiempo, así que el objetivo sorteado se traduce en un techo de tokens (y, si no basta, en un contexto reducido) antes de llamar al modelo, con los dos términos del coste calibrados sobre las respuestas reales. Ataca el único canal lateral interno que seguía abierto, la clase `proc_scan` de [§8](#8-resultados-de-referencia). **Implementado y cubierto por la suite offline; pendiente de la ejecución del banco que lo mida.**
- [x] **Emulación de adversarios** — atacante LLM adaptativo y **juez ciego** contra un host Linux real como control, con acierto contrastado por test binomial y acuerdo entre dos jueces (Cohen κ). Arnés en `evaluation/`, metodología en [`docs/05_ADVERSARY_EMULATION.md`](docs/05_ADVERSARY_EMULATION.md). Ejecución de referencia completada con `qwen2.5:7b`: 16/16 transcripciones juzgadas, resultados y su lectura crítica en [§12](#12-emulación-de-adversarios-y-credibilidad).
- [x] **Comparativa con Cowrie** — Cowrie 2.x en el compose bajo el perfil `compare`, interrogado con el mismo cliente SSH, las mismas credenciales y la misma batería de 30 comandos que el señuelo y el host real. Cuatro ejes medidos (cobertura, coherencia, tiempo hasta el primer byte y coste) en [`benchmarks/results/COMPARISON.md`](benchmarks/results/COMPARISON.md); ver [§13](#13-comparativa-con-un-honeypot-tradicional).
- [ ] **Futuro** — señuelos HTTP y FTP reutilizando el mismo orquestador.

---

## 12. Emulación de adversarios y credibilidad

La latencia ([§8](#8-resultados-de-referencia)) mide si el señuelo es rápido e indistinguible **en el tiempo**; no mide si su contenido **es creíble**. Un host puede responder rápido y aun así delatarse porque su `/etc/passwd` no cuadra con sus procesos, o porque un `ls -l` tiene un formato que ningún `coreutils` real produce. Esa pregunta la responde un juez ciego.

**Diseño.** Un atacante LLM adaptativo (`llama3.2:3b`, de familia distinta a la del señuelo y a la del juez, para que ninguno reconozca su propia salida), con root por SSH, elige cada comando según la salida del anterior e interroga por igual dos brazos: el señuelo y un **host Linux real como control** (Debian sin adornos, servicio `real-host` bajo el perfil `eval`). Las transcripciones se juntan, se barajan y se despojan de toda etiqueta de brazo y puerto; luego **dos jueces independientes** —un modelo mayor (`qwen2.5:7b`) y el propio modelo del señuelo (`qwen2.5-coder:0.5b`) como contraste— clasifican cada una, a ciegas, sin que se les diga que hay un honeypot en la muestra.

**Métrica.** Con la muestra equilibrada al 50 %, un juez inútil acierta el 50 %. El resultado buscado es **que no supere el azar**, contrastado con un test binomial exacto, con matriz de confusión y recall por clase (para descartar al juez que siempre dice «señuelo»), y con el acuerdo entre los dos jueces (Cohen κ). El veredicto del propio atacante se reporta como señal adversaria secundaria, no como la medida ciega: sabe que busca un honeypot y está sesgado.

**Suelo de evidencia.** La primera ejecución de referencia falló por método, no por código: con un atacante de 0,5 B, **doce de dieciséis sesiones acabaron con cero comandos ejecutados** porque el modelo emitía su veredicto en la primera réplica, antes de tocar el host. El juez recibía transcripciones vacías. El arnés rechaza ahora el veredicto hasta que el atacante haya ejecutado `--min-turns` comandos (5 por defecto) y le devuelve el turno; es un mínimo de trabajo, no un empujón hacia ninguna conclusión. Queda fijado en la suite offline con un modelo simulado que insiste en concluir en el turno cero.

```bash
docker compose --profile eval up -d --build real-host   # levantar el control real
docker exec ollama_llm ollama pull qwen2.5:7b            # juez principal (~5 GB, una vez)
docker exec ollama_llm ollama pull llama3.2:3b           # atacante independiente (~2 GB)
pip install -r evaluation/requirements.txt
python evaluation/run_deception_eval.py --sessions 8     # -> evaluation/results/DECEPTION_EVAL.md
```

### Resultados del juez ciego

Ejecución de 2026-08-23, 8 sesiones por brazo, 16 transcripciones, 0 sesiones muertas. **Cifras desde [`evaluation/results/DECEPTION_EVAL.md`](evaluation/results/DECEPTION_EVAL.md), que se regenera.**

| Juez | n | Acierto | p (binomial) | Recall real | Recall decoy | Veredicto |
|---|---|---|---|---|---|---|
| `qwen2.5:7b` (principal) | 15 | 46,7 % | 1,000 | 12,5 % | 75,0 % | INDISTINGUIBLE |
| `qwen2.5-coder:0.5b` (contraste) | 16 | 56,2 % | 0,804 | 100 % | 12,5 % | INDISTINGUIBLE |

**Y aquí es donde la lectura ingenua es la equivocada.** Ninguno de los dos jueces supera el azar, que es formalmente el resultado buscado. Pero las matrices de confusión muestran que **ninguno de los dos está midiendo credibilidad**: el de 7B contesta «decoy» a 13 de 15 transcripciones —incluidas 7 de las 8 del host Debian real— y el de 0,5B contesta «real» a 15 de 16. Son jueces **degenerados**: responden casi siempre lo mismo, y en muestra equilibrada eso produce mecánicamente un 50 % de acierto tanto si el engaño es perfecto como si es pésimo. El acuerdo entre ambos lo confirma: Cohen κ = 0,02, indistinguible de la coincidencia por azar.

La conclusión que sostiene la evidencia es por tanto **más débil que la que el veredicto sugiere**:

> El señuelo **no fue refutado** por este instrumento. No se demuestra que sea indistinguible de un host real, porque el instrumento no ha demostrado ser capaz de distinguir nada. Un juez que no discrimina no puede acreditar credibilidad; solo puede dejar de negarla.

El límite no está en el tamaño de muestra sino en el evaluador, así que ampliar `--sessions` no arregla esto. Las tres líneas que sí lo atacarían, en orden de coste: fijar la capacidad del juez con transcripciones de control cuya clase se conoce antes de usarlo, subir a un juez de 14B o mayor, y —lo único concluyente— un panel de operadores humanos. Las tres quedan declaradas como trabajo futuro, no como resultado.

Las transcripciones íntegras con sus marcas de tiempo y los veredictos de ambos jueces están versionados (`evaluation/results/transcripts.jsonl`, `verdicts.jsonl`): las cifras se pueden recomputar sin volver a ejecutar nada.

### Suite offline

La suite offline `tests/test_evaluation.py` valida, sin Docker ni Ollama, lo que debe ser correcto pase lo que pase el modelo: que el render ciego no filtre el brazo, la estadística y la barrera de seguridad del atacante. Metodología completa, garantías de ceguera y limitaciones en [`docs/05_ADVERSARY_EMULATION.md`](docs/05_ADVERSARY_EMULATION.md). **Igual que en la latencia, ninguna cifra entra en la memoria sin proceder de una ejecución del arnés**; el informe se regenera y no se edita a mano.

---

## 13. Comparativa con un honeypot tradicional

Cowrie es el referente establecido en honeypots SSH de media interacción (Oosterhof, 2014). La comparación solo significa algo si ambos sistemas se interrogan con **el mismo instrumento**, así que el arnés los conduce con el cliente SSH de `evaluation/targets.py` —el mismo que usa el juez ciego— con idénticas credenciales y la misma batería de 30 comandos. Se incluye un tercer brazo, el **host Debian real**, porque la pregunta que interesa no es cuál de los dos honeypots responde más, sino cuál se parece más a un servidor de verdad.

```bash
docker compose --profile compare up -d cowrie      # honeypot de referencia
docker compose --profile eval    up -d real-host   # brazo de control
python benchmarks/cowrie_comparison.py --repeat 2  # -> benchmarks/results/COMPARISON.md
```

### Resultados de la comparativa

| Sistema | Cobertura | Divergencia vs. real | Coherencia | Mediana | p95 |
|---|---|---|---|---|---|
| Marco generativo | **96,7 %** | **8/30** | 96,7 % | 598,0 ms | 666,7 ms |
| Cowrie | 63,3 % | **6/30** | 93,3 % | 10,5 ms | 21,2 ms |
| Host real (control) | 70,0 % | — referencia | 93,3 % | 4,5 ms | 9,8 ms |

**Cómo leer esta tabla, porque la lectura ingenua es la equivocada:**

1. **La cobertura no se lee sola.** El host real solo responde al 70 % de la batería, porque nueve de esas rutas *no existen* en un Debian recién instalado: no hay `/root/.my.cnf`, ni crontab de root, ni `sudo`, ni `nmap`. Una cobertura próxima al 100 % no es una victoria, es una anomalía que ningún sistema real presenta.

2. **Por divergencia, la comparación se invierte.** El marco generativo discrepa del host real en 8 de 30 comandos y Cowrie en solo 6. Las ocho del señuelo son deliberadas —son los honeytokens y artefactos sembrados— pero son también superficie de identificación. La verosimilitud no se maximiza generando *más*, sino generando *lo que un host real tendría*.

3. **La latencia mide el primer byte, no el silencio.** El cliente espera 1,2 s de quietud antes de cerrar una respuesta; medir hasta ahí devuelve ~1.240 ms para los tres brazos, incluido el Debian pelado, y describe el instrumento en vez del sistema.

4. **El canal lateral interno está cerrado; el externo no.** La normalización de [§8](#8-resultados-de-referencia) hace indistinguibles las dos rutas internas (AUC 0,499), pero el señuelo sigue dos órdenes de magnitud por encima de un `sshd` real. **Es la limitación más seria del trabajo**: un adversario con un servidor legítimo de la misma organización como término de comparación puede separarlo por tiempo.

5. **Coherencia perfecta también delata.** El señuelo es *más* estable que el host real (96,7 % frente a 93,3 %), donde `ps aux` e `history` cambian legítimamente entre invocaciones.

El precio de los 33 puntos de cobertura: **dos órdenes de magnitud más de memoria** (los ~4,4 GiB residentes del motor de inferencia, frente a los 54 MiB de Cowrie) y **dos más de latencia**. Desglose comando a comando en [`benchmarks/results/COMPARISON.md`](benchmarks/results/COMPARISON.md).

---

## 14. Trazabilidad: qué respalda cada apartado de la memoria

Qué fichero del repositorio sostiene cada afirmación de la memoria. Sirve al tribunal para ir de una frase a su evidencia sin buscar, y sirve a la autora para no dejar ninguna afirmación sin respaldo.

| Apartado de la memoria | Respaldo en el repositorio |
|---|---|
| 1.2 Ciberengaño generativo vs. honeypot estático | `agents/roles/terminal.py` — resolución híbrida |
| 1.2 Ausencia de falsos positivos | `agents/roles/artifacts.py` — honeytokens; `docs/03` §6 — condiciones de contorno |
| 1.4 (2) Señuelo SSH | `decoys/ssh/ssh_server.py` |
| 1.4 (3) Motor local, sin API externa | `agents/core/llm.py`, `docker-compose.yml` |
| 1.4 (4) Optimización de latencia | `agents/core/config.py`, `agents/core/latency.py` |
| 1.4 (5) Alineación MITRE ATT&CK | `agents/core/mitre.py` |
| 1.4 (6) Infraestructura reproducible | `docker-compose.yml`, `.env.example` |
| 1.4 Estado en ámbito de sesión | `agents/core/session.py` |
| 3.x Arquitectura y diseño | [`docs/01`](docs/01_ARCHITECTURE_AND_TECHNICAL_DESIGN.md) |
| 3.x Despliegue | [`docs/02`](docs/02_DEPLOYMENT_AND_TROUBLESHOOTING_GUIDE.md) |
| 4.1 Emulación de adversarios y juez ciego | [`docs/05`](docs/05_ADVERSARY_EMULATION.md); `evaluation/`; [`DECEPTION_EVAL.md`](evaluation/results/DECEPTION_EVAL.md) (generado) |
| 4.2 Análisis de latencia | `benchmarks/latency_benchmark.py`, `benchmarks/stats.py`; [`RESULTS.md`](benchmarks/results/RESULTS.md) (generado) |
| 4.2 Consumo de recursos | `benchmarks/resource_monitor.py`; [`RESOURCES.md`](benchmarks/results/RESOURCES.md) (generado) |
| 4.3 Validación de fidelidad | `benchmarks/latency_benchmark.py:check_fidelity`, `tests/test_core.py` |
| 4.4 Comparativa con Cowrie | `benchmarks/cowrie_comparison.py`; [`COMPARISON.md`](benchmarks/results/COMPARISON.md) (generado) |
| Objetivo específico: integración SIEM | [`docs/04`](docs/04_SIEM_INTEGRATION.md), `siem/`; [`SIEM_VALIDATION.md`](benchmarks/results/SIEM_VALIDATION.md) (generado) |
| 5.x Limitaciones declaradas | [§7](#7-qué-es-reproducible-y-qué-no), [§8](#8-resultados-de-referencia), [§12](#12-emulación-de-adversarios-y-credibilidad), [§13](#13-comparativa-con-un-honeypot-tradicional) |

### Qué queda fuera, declarado

Ninguno de estos puntos es un olvido: se declaran como limitación en lugar de omitirse.

| Limitación | Dónde se declara |
|---|---|
| Canal lateral temporal **externo** abierto: el señuelo está dos órdenes de magnitud por encima de un `sshd` real | [§13](#13-comparativa-con-un-honeypot-tradicional) punto 4 |
| Canal lateral **interno** aún abierto en la clase `proc_scan` | [§8](#8-resultados-de-referencia) |
| Jueces ciegos degenerados: el engaño no fue refutado, no fue demostrado | [§12](#12-emulación-de-adversarios-y-credibilidad) |
| Sin adversario humano (estudio con sujetos, fuera de alcance) | `docs/03` §7 |
| H4 (cero falsos positivos) es un argumento estructural, no una medida | `docs/03` §6 |
| Transporte agente→manager y panel de Wazuh sin validar | [`docs/04`](docs/04_SIEM_INTEGRATION.md), [§9](#9-telemetría-para-el-soc) |
| La ejecución versionada se midió con un clasificador de coste ya corregido | [§7](#7-qué-es-reproducible-y-qué-no) |
| Un solo modelo medido de extremo a extremo (`0.5b`); el `3b` queda documentado, no medido | [§4](#4-entorno-de-referencia) |
| Señuelos HTTP y FTP: trabajo futuro | [§11](#11-estado-del-proyecto) |

---

## 15. Demostración en vivo

Guion para enseñar el sistema funcionando delante de alguien, en unos 12 minutos. Cada paso dice **qué escribir**, **qué debe salir** y **qué se está demostrando**, para poder narrarlo mientras corre.

**Versión visual:** [`docs/demo.html`](docs/demo.html) — se abre con doble clic, sin servidor ni conexión. Arquitectura, flujo de una interacción, resultados medidos y este mismo guion paso a paso.

### Antes de empezar (hazlo el día antes, no delante del tribunal)

```bash
docker compose up -d --build          # la primera vez baja ~400 MB de modelo
docker compose ps                     # los 3 servicios en healthy/running
curl -s http://127.0.0.1:8000/health  # {"status":"ok","ready":true}
ssh-keygen -R "[localhost]:2222"      # evita el aviso de clave de host cambiada
```

Si `/health` no responde `ready:true`, el modelo no terminó de bajar: `docker compose logs model-puller`.

### El guion

| # | Escribe | Debe salir | Demuestra |
|---|---|---|---|
| 1 | `curl -s http://127.0.0.1:8000/persona \| python -m json.tool` | Empresa, hostname, usuarios, aplicación | La persona se generó una vez y está congelada |
| 2 | `ssh root@localhost -p 2222` (contraseña: **cualquiera**) | Banner MOTD y prompt `root@<host>:~#` | Acepta todo por diseño, y ya registró la credencial |
| 3 | `whoami` · `hostname` · `cat /etc/os-release` | `root`, el hostname de la persona, Ubuntu 22.04 | Ruta determinista |
| 4 | `cat /etc/passwd` → apunta un usuario → `ls -la /home` | Los mismos usuarios en los dos sitios | **Coherencia**: lo que un honeypot estático no tiene |
| 5 | `cat /etc/passwd` otra vez | Byte a byte idéntico | No hay un modelo reinventando el fichero |
| 6 | `cd /tmp && touch payload.sh && ls -la` | El fichero aparece | Estado de sesión con overlay |
| 7 | `cat /root/.ssh/id_rsa` | Una clave privada con su marca `HT-XXXXXXXX` | **Honeytoken**: su uso fuera del señuelo es un positivo por construcción |
| 8 | `systemctl status nginx` | Salida plausible que nadie escribió a mano | **Ruta generativa**, el LLM local |
| 9 | `tail -5 /var/log/nginx/access.log` (espera 10 s y repite) | Líneas nuevas | El tráfico simulado sigue creciendo: no es un fichero congelado |
| 10 | `exit` | — | Cierra la sesión y emite el resumen |

### El lado del defensor (la mitad que se olvida enseñar)

En otra terminal, **mientras** ocurre lo anterior:

```bash
docker compose exec deception-agent tail -f /app/data/logs/deception-events.jsonl
```

Cada comando aparece como un evento JSON Lines con su técnica MITRE ATT&CK, su severidad, su `wazuh_level` y los honeytokens implicados. El paso 7 dispara la señal de mayor valor del sistema (nivel 15). Para enseñarlo formateado:

```bash
docker compose exec deception-agent tail -f /app/data/logs/deception-events.jsonl   | python -c "import sys,json; [print(f\"{e['severity']:8} {e['event_type']:18} {e.get('command','')}\") for e in map(json.loads,sys.stdin)]"
```

### Si hay tiempo: las tres piezas de evaluación

```bash
python tests/test_core.py                                  # 102/102, sin Docker, ~2 s
python benchmarks/latency_benchmark.py --suite paired --repeat 3   # regenera RESULTS.md
docker compose --profile compare up -d cowrie              # el tercer brazo
```

### Al terminar

```bash
docker compose down          # conserva modelo y volúmenes
docker compose down -v       # borra todo, modelo incluido
```

### Fallos que pueden ocurrir

| Síntoma | Qué decir mientras lo arreglas | Arreglo |
|---|---|---|
| El SSH tarda mucho en el primer comando | «El modelo estaba descargado de RAM; `keep_alive` lo evita en régimen normal» | Ejecuta un comando cualquiera antes de empezar, para calentar |
| La persona sale genérica (`srv-web-prod-02`) | «Es el perfil de reserva: el señuelo no degrada a un estado obviamente falso si la inferencia cae» | `docker compose exec deception-agent rm /app/data/persona.json && docker compose restart deception-agent` |
| Aviso de clave de host cambiada | — | `ssh-keygen -R "[localhost]:2222"` |
| `/health` no da `ready` | «Sigue bajando el modelo» | `docker compose logs -f model-puller` |

Troubleshooting completo en [`docs/02`](docs/02_DEPLOYMENT_AND_TROUBLESHOOTING_GUIDE.md) §6.

---

## Créditos

* **Autora:** María Celeste Montoya Bonilla
* **Programa:** Máster en Ciberseguridad — Universidad Complutense de Madrid
* **Tutores:** Prof. Javier Domínguez Gómez · Prof. Román Ramírez Giménez

---

## Aviso

Este software está destinado exclusivamente a investigación en defensa activa y a despliegues autorizados en redes propias. Acepta cualquier credencial por diseño y registra en claro todo lo que el atacante escribe. No lo despliegues en un segmento de producción sin aislamiento de red.
