# Generative Deception Framework (TFM · UCM)

Sistema de ciberengaño dinámico e interactivo guiado por una arquitectura multi-agente y un modelo de lenguaje local (Ollama), para la detección temprana de intrusiones en entornos corporativos.

---

## Descripción

Implementación práctica del Trabajo Fin de Máster (**Máster en Ciberseguridad — Universidad Complutense de Madrid**). El objetivo es desplegar una solución de defensa activa capaz de superar las limitaciones de los *honeypots* estáticos, que un atacante identifica en segundos por su falta de historial, sus servicios inertes y sus respuestas incoherentes.

El sistema despliega un señuelo SSH que mantiene una **identidad de host coherente**, la puebla con **artefactos sintéticos** (historiales de shell, ficheros de negocio, credenciales trampa, logs que siguen creciendo) y resuelve la interacción con el atacante mediante **cuatro agentes especializados** apoyados en un LLM cuantizado ejecutado en local, sin ninguna dependencia de APIs externas.

### La decisión de diseño central: resolución híbrida

Cada comando toma una de dos rutas:

| Ruta | Qué resuelve | Coste | Propiedad que aporta |
|---|---|---|---|
| **Determinista** | Reconocimiento (`whoami`, `uname`, `cat /etc/passwd`, `ls`, `ps`, `ip a`…) resuelto desde la persona y el sistema de ficheros de artefactos. | microsegundos | Coherencia exacta y estable durante toda la sesión. |
| **Generativa** | Todo lo demás, enviado al LLM local con la persona y los últimos turnos como contexto. | inferencia | Cobertura ilimitada de comandos, sin respuestas pregrabadas. |

Enviar todos los comandos al modelo sería más simple y peor: gastaría el presupuesto de latencia en trivialidades y devolvería un `/etc/passwd` distinto cada vez, que es justamente la incoherencia que delata la trampa. No enviar ninguno reconstruiría un honeypot estático. La división compra las dos propiedades a la vez.

---

## Arquitectura

```text
[ Atacante ]  --SSH:2222-->  ssh-decoy  --HTTP-->  deception-agent  --HTTP-->  ollama-llm
                             (paramiko)            (4 agentes)                 (qwen2.5-coder:3b)
                              EXPUESTO              INTERNO                     INTERNO
                                                        │
                                                        ▼  JSON Lines -> SIEM
```

| Agente | Cuándo | Responsabilidad |
|---|---|---|
| **Persona** | Arranque | Quién dice ser el host: empresa, usuarios, `/etc/passwd`, red, procesos. |
| **Artefactos** | Arranque + hilo continuo | Qué hay en el host: ficheros, honeytokens, `.bash_history`, tráfico de logs simulado. |
| **Terminal** | Por comando | Qué responde el host, por la ruta determinista o la generativa. |
| **Alertas** | Por evento | Qué se le cuenta al SOC: técnica ATT&CK, severidad, telemetría JSON Lines. |

Detalle completo en [`docs/01_ARCHITECTURE_AND_TECHNICAL_DESIGN.md`](docs/01_ARCHITECTURE_AND_TECHNICAL_DESIGN.md).

---

## Estructura del repositorio

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
├── benchmarks/                 Banco de latencia y fidelidad
├── tests/test_core.py          Suite offline (sin Docker ni Ollama)
└── docs/                       Documentación técnica y memoria
```

---

## Despliegue

### Requisitos
Docker Engine 20.10+, Docker Compose v2, 8 GB de RAM (16 GB recomendado), 10 GB de disco. Python 3.10+ en el host solo para las pruebas.

### Puesta en marcha

```bash
git clone https://github.com/MCMB1803/tfm-generative-deception.git
cd tfm-generative-deception
cp .env.example .env
docker compose up -d --build
```

Un solo comando. El modelo se descarga automáticamente y el orden de arranque se resuelve con condiciones de salud. La primera ejecución tarda varios minutos mientras baja el modelo (~2 GB).

### Verificación

```bash
curl -s http://127.0.0.1:8000/stats | python -m json.tool    # estado del orquestador
ssh root@localhost -p 2222                                   # cualquier contraseña vale
```

Guía completa y troubleshooting en [`docs/02_DEPLOYMENT_AND_TROUBLESHOOTING_GUIDE.md`](docs/02_DEPLOYMENT_AND_TROUBLESHOOTING_GUIDE.md).

---

## Evaluación

```bash
python tests/test_core.py                                        # coherencia, offline
python benchmarks/latency_benchmark.py --scenario both --repeat 5 # latencia y fidelidad
```

El banco de pruebas escribe `benchmarks/results/`: muestras crudas en CSV, agregados en JSON y tablas listas para la memoria en `RESULTS.md`.

> **Todas las cifras de la memoria proceden de una ejecución concreta de este banco.** No se transcribe ningún número a mano. Metodología, hipótesis y matriz de comandos en [`docs/03_TEST_MATRIX_AND_LATENCY_EVALUATION.md`](docs/03_TEST_MATRIX_AND_LATENCY_EVALUATION.md).

---

## Telemetría para el SOC

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

Reglas de correlación y configuración de ingesta en [`docs/05_SIEM_INTEGRATION.md`](docs/05_SIEM_INTEGRATION.md).

---

## Estado del proyecto

- [x] **Fase 1** — Infraestructura Docker Compose con Ollama y orquestador Python.
- [x] **Fase 2** — Señuelo SSH interactivo con captura de credenciales y clave de host persistente.
- [x] **Fase 3** — Agente de artefactos: sistema de ficheros virtual, honeytokens, `.bash_history` generado, simulación de tráfico.
- [x] **Fase 4** — Telemetría estructurada JSON Lines con mapeo MITRE ATT&CK y reglas de Wazuh documentadas.
- [ ] **Fase 5** — Emulación de adversarios con operador humano y comparativa medida frente a Cowrie.
- [ ] **Futuro** — Señuelos HTTP y FTP reutilizando el mismo orquestador.

---

## Créditos

* **Autora:** María Celeste Montoya Bonilla
* **Programa:** Máster en Ciberseguridad — Universidad Complutense de Madrid
* **Tutores:** Prof. Javier Domínguez Gómez · Prof. Román Ramírez Giménez

---

## Aviso

Este software está destinado exclusivamente a investigación en defensa activa y a despliegues autorizados en redes propias. Acepta cualquier credencial por diseño y registra en claro todo lo que el atacante escribe. No lo despliegues en un segmento de producción sin aislamiento de red.
