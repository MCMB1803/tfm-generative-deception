# Generative Deception Framework (TFM · UCM)

Señuelo SSH de ciberengaño dinámico guiado por una arquitectura multi-agente y un modelo de lenguaje local (Ollama), para la detección temprana de intrusiones en entornos corporativos.

**Este README es la guía de reproducción.** Contiene los pasos exactos para levantar el sistema, re-ejecutar el banco de pruebas y obtener las cifras de la memoria, junto con el entorno de referencia en que se midieron y las condiciones bajo las que son —y no son— reproducibles.

---

## Índice

1. [Qué hace el sistema](#1-qué-hace-el-sistema)
   - [La decisión de diseño central: resolución híbrida](#la-decisión-de-diseño-central-resolución-híbrida)
2. [Arquitectura](#2-arquitectura)
3. [Reproducción rápida](#3-reproducción-rápida)
   - [Requisitos](#requisitos)
   - [Levantar la pila](#levantar-la-pila)
   - [Comprobar que está en pie](#comprobar-que-está-en-pie)
   - [Pruebas offline](#pruebas-offline-no-necesitan-docker-ni-ollama)
4. [Entorno de referencia](#4-entorno-de-referencia)
5. [Fijar las versiones](#5-fijar-las-versiones)
6. [Re-ejecutar el banco de pruebas](#6-re-ejecutar-el-banco-de-pruebas)
   - [Opciones](#opciones)
7. [Qué es reproducible y qué no](#7-qué-es-reproducible-y-qué-no)
8. [Resultados de referencia](#8-resultados-de-referencia)
9. [Telemetría para el SOC](#9-telemetría-para-el-soc)
10. [Estructura del repositorio](#10-estructura-del-repositorio)
11. [Estado del proyecto](#11-estado-del-proyecto)
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
                             (paramiko)            (4 agentes)                 (qwen2.5-coder:3b)
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

Un solo comando. El orden de arranque se resuelve con condiciones de salud: `ollama-llm` → `model-puller` (descarga el modelo y termina) → `deception-agent` → `ssh-decoy`. La primera ejecución tarda varios minutos mientras baja el modelo (~2 GB).

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
python tests/test_core.py
```

Sustituye el cliente LLM por un doble de prueba y ejercita la capa determinista: coherencia de la persona entre llamadas, sistema de ficheros virtual, mapeo ATT&CK, higiene de la salida y binarios ausentes. **No requiere instalar dependencias.** Salida esperada: `50/50 comprobaciones superadas`, código de salida 0.

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
| Modelo | `qwen2.5-coder:3b` |
| Parámetros | `MAX_TOKENS=220`, `TEMPERATURE=0.3`, `SESSION_CONTEXT_TURNS=6`, `PERSONA_SEED=1803` |

Que no haya GPU no es un defecto que ocultar: es la condición realista de un despliegue en un servidor corporativo cualquiera, y las cifras deben leerse así. En una máquina con CUDA la ruta generativa será sustancialmente más rápida y **los resultados de [§8](#8-resultados-de-referencia) no se reproducirán**; lo que debe reproducirse es la *metodología*, no el número absoluto.

---

## 5. Fijar las versiones

Por defecto el proyecto usa etiquetas móviles (`ollama/ollama:latest`, `qwen2.5-coder:3b`). Es cómodo para desarrollar y **malo para reproducir**: dentro de seis meses esas etiquetas apuntan a otro artefacto. Antes de la ejecución que vaya a citarse en la memoria, registra los identificadores exactos:

```bash
# Digest de la imagen de Ollama
docker image inspect ollama/ollama:latest --format "{{index .RepoDigests 0}}"

# Identificador del modelo descargado
docker exec ollama_llm ollama list
docker exec ollama_llm ollama show qwen2.5-coder:3b --modelfile | head -5

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
| `--suite` | `recon` · `generative` · `both` | Qué batería: 30 comandos deterministas alineados con ATT&CK, 10 generativos, o ambas. |
| `--repeat` | entero (def. 3) | Iteraciones completas de la secuencia. |
| `--api` | URL (def. `http://localhost:8000`) | Dónde escucha el orquestador. |
| `--outdir` | ruta (def. `benchmarks/results`) | Dónde escribir. |

La ejecución de referencia de [§8](#8-resultados-de-referencia) fue `--repeat 1 --scenario recon --suite both` (40 muestras). Para la memoria conviene `--repeat 5` o más: con una sola iteración los percentiles no significan gran cosa.

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

**Limitación conocida y abierta.** La distribución de latencia de la ejecución de referencia es **bimodal**: ~2 ms en la ruta determinista frente a ~2.044 ms en la generativa, con desviaciones típicas de 1,6 y 7,3 ms. Ningún host real produce dos poblaciones tan limpias y tan separadas, así que un atacante que cronometre respuestas puede separar ambas rutas y deducir que hay un modelo detrás. Está documentado aquí a propósito, no escondido: es el problema que aborda la fase de normalización de latencia ([§11](#11-estado-del-proyecto)), y la métrica correcta no es «media por debajo de 1.000 ms» sino «un atacante no puede separar las dos rutas por tiempo», contrastable con un test estadístico.

**Sobre la métrica de fidelidad.** El `fidelity_pass_pct` que aparece en `RESULTS.md` es una **comprobación de subcadenas** contra una lista de tokens esperados escrita a mano (`benchmarks/latency_benchmark.py:146`). Es reproducible por un tercero y sirve como prueba de regresión, pero **no mide que el engaño resulte creíble**: para la ruta determinista, que genera esas salidas desde plantillas, un 100 % es casi tautológico. La evaluación de credibilidad requiere adversario y juez ciego, que es la fase pendiente de [§11](#11-estado-del-proyecto).

---

## 8. Resultados de referencia

Ejecución del **2026-08-22T15:41:31Z**, 40 muestras, objetivo de latencia 1.000 ms. Fuente: [`benchmarks/results/RESULTS.md`](benchmarks/results/RESULTS.md).

| Ruta | n | Media | Mediana | Desv. típ. | p95 | Dentro de objetivo |
|---|---|---|---|---|---|---|
| **Global** | 40 | 512,9 ms | 2,2 ms | 895,5 ms | 2.048,8 ms | 75,0 % |
| Determinista | 30 | 2,4 ms | 1,5 ms | 1,6 ms | 5,6 ms | 100 % |
| Generativa | 10 | 2.044,4 ms | 2.045,4 ms | 7,3 ms | 2.054,0 ms | **0 %** |

Reparto: 75 % de los comandos por la ruta determinista, 25 % por la generativa.

La ruta generativa **incumple el objetivo en el 100 % de las muestras**. Léase junto a la limitación conocida de [§7](#7-qué-es-reproducible-y-qué-no): es el punto de partida del trabajo pendiente, no un resultado que el proyecto dé por bueno.

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

Reglas de correlación y configuración de ingesta en [`docs/05_SIEM_INTEGRATION.md`](docs/05_SIEM_INTEGRATION.md). **El SIEM está especificado y provisto, pero no desplegado ni validado**: las reglas están escritas y el formato de evento se diseñó para ingesta directa, pero el envío real a un Wazuh en producción, el disparo de las reglas y su visualización en el panel siguen pendientes ([§11](#11-estado-del-proyecto)).

---

## 10. Estructura del repositorio

```text
tfm-generative-deception/
├── docker-compose.yml          Pila completa: inferencia, orquestador, señuelo
├── .env.example                Configuración de referencia
├── agents/                     Orquestador multi-agente
│   ├── main.py                 API HTTP (FastAPI)
│   ├── orchestrator.py         Coordinación y ciclo de vida de sesión
│   ├── core/                   config · llm · mitre · session · telemetry
│   └── roles/                  persona · artifacts · terminal · alerting
├── decoys/ssh/                 Frontend de protocolo SSH (paramiko)
├── benchmarks/
│   ├── latency_benchmark.py    Banco de latencia y fidelidad
│   └── results/                Ejecución de referencia (CSV · JSON · RESULTS.md)
├── tests/test_core.py          Suite offline (sin Docker ni Ollama)
└── docs/                       Documentación técnica
```

---

## 11. Estado del proyecto

- [x] **Infraestructura** — Docker Compose con Ollama, orquestador y señuelo; arranque ordenado por condiciones de salud.
- [x] **Señuelo SSH** — sesión interactiva, captura de credenciales, clave de host persistente, edición de línea real.
- [x] **Agentes de persona y artefactos** — sistema de ficheros virtual, honeytokens, `.bash_history` generado, simulación de tráfico.
- [x] **Telemetría** — JSON Lines con mapeo MITRE ATT&CK y severidad; reglas de Wazuh **escritas**.
- [x] **Despliegue del SIEM** — Wazuh 4.9.2 en el compose bajo el perfil `siem`; las 10 reglas validadas contra el manager real con `siem/validate_rules.py` (evidencia en `benchmarks/results/SIEM_VALIDATION.md`). Queda fuera el transporte desde un agente remoto y el panel.
- [ ] **Normalización de latencia** — eliminar la bimodalidad de [§7](#7-qué-es-reproducible-y-qué-no) y validar con un test estadístico que las dos rutas no son separables por tiempo. Incluye medición de consumo de CPU/RAM por contenedor.
- [ ] **Emulación de adversarios** — atacante LLM adaptativo y juez ciego, con transcripciones de un host real como control.
- [ ] **Comparativa con Cowrie** — despliegue y misma batería de pruebas.
- [ ] **Futuro** — señuelos HTTP y FTP reutilizando el mismo orquestador.

---

## Créditos

* **Autora:** María Celeste Montoya Bonilla
* **Programa:** Máster en Ciberseguridad — Universidad Complutense de Madrid
* **Tutores:** Prof. Javier Domínguez Gómez · Prof. Román Ramírez Giménez

---

## Aviso

Este software está destinado exclusivamente a investigación en defensa activa y a despliegues autorizados en redes propias. Acepta cualquier credencial por diseño y registra en claro todo lo que el atacante escribe. No lo despliegues en un segmento de producción sin aislamiento de red.
