# 04. Borrador y Estructura de la Memoria del TFM

## Datos del Proyecto
* **Título:** Ciberengaño Dinámico Multi-Agente con IA (Generative Deception)
* **Autora:** María Celeste Montoya Bonilla
* **Titulación:** Máster en Ciberseguridad - Universidad Complutense de Madrid (UCM)
* **Tutores:** Prof. Javier Domínguez Gómez / Prof. Román Ramírez Giménez

---

## Índice General de la Memoria

```text
CAPÍTULO 1: INTRODUCCIÓN Y JUSTIFICACIÓN
  1.1. Contexto y Planteamiento del Problema
  1.2. Justificación Técnica: Ciberengaño Generativo vs. Honeypots Estáticos
  1.3. Objetivos del Proyecto (General y Específicos)
  1.4. Alcance y Limitaciones

CAPÍTULO 2: ESTADO DEL ARTE Y MARCO TEÓRICO
  2.1. Evolución de los Sistemas Trampa en Ciberseguridad (Honeypots y Honeytokens)
  2.2. Modelos de Lenguaje (LLMs) Aplicados a la Ciberdefensa
  2.3. Arquitecturas Multi-Agente y Generación Dinámica de Artefactos
  2.4. Plataformas In-House y Soluciones Comerciales (Deception Technology)

CAPÍTULO 3: ARQUITECTURA Y DISEÑO DEL SISTEMA
  3.1. Requisitos Funcionales y No Funcionales
  3.2. Diseño de la Infraestructura Containerizada (Docker & Ollama)
  3.3. Implementación del Servicio Trampa SSH (Paramiko & Python)
  3.4. Integración del LLM Local (Prompt Engineering & Optimización de Latencia)

CAPÍTULO 4: EVALUACIÓN, PRUEBAS Y RESULTADOS
  4.1. Escenarios de Emulación de Adversarios (Red Teaming)
  4.2. Análisis de Latencia y Rendimiento del Modelo LLM
  4.3. Validación de Fidelidad de Comandos y Ausencia de Falsos Positivos
  4.4. Comparativa con Honeypots Tradicionales (Cowrie / Dionaea)

CAPÍTULO 5: CONCLUSIONES Y TRABAJO FUTURO
  5.1. Conclusiones Principales
  5.2. Cumplimiento de Objetivos
  5.3. Líneas de Trabajo Futuro (Integración SIEM Wazuh, Multi-Servicio HTTP/FTP)

BIBLIOGRAFÍA Y ANEXOS
```



---

## Correspondencia entre la Implementación y la Memoria

Qué fichero del repositorio respalda cada apartado. Útil para el tribunal y para no dejar afirmaciones sin evidencia.

| Apartado de la memoria | Respaldo en el repositorio |
|---|---|
| 1.2 Ciberengaño generativo | `agents/roles/terminal.py` — resolución híbrida |
| 1.2 Cero falsos positivos | `agents/roles/artifacts.py` — honeytokens; `docs/03` §6 — condiciones de contorno |
| 1.4.1 (2) Señuelo SSH | `decoys/ssh/ssh_server.py` |
| 1.4.1 (3) Motor local offline | `agents/core/llm.py`, `docker-compose.yml` |
| 1.4.1 (4) Optimización de latencia | `agents/core/config.py` (`MAX_TOKENS`, `keep_alive`, `SESSION_CONTEXT_TURNS`) |
| 1.4.1 (5) Alineación MITRE ATT&CK | `agents/core/mitre.py` |
| 1.4.1 (6) Infraestructura reproducible | `docker-compose.yml`, `.env.example` |
| 1.4.2 Estado en ámbito de sesión | `agents/core/session.py` |
| 3.x Arquitectura | `docs/01_ARCHITECTURE_AND_TECHNICAL_DESIGN.md` |
| 4.2 Análisis de latencia | `benchmarks/results/RESULTS.md` (generado) |
| 4.3 Validación de fidelidad | `benchmarks/latency_benchmark.py`, `tests/test_core.py` |
| Objetivo específico: SIEM | `docs/05_SIEM_INTEGRATION.md` |

## Pendiente antes de la Entrega

1. **Ejecutar el banco de pruebas en el hardware definitivo** y documentar CPU, RAM y si hay GPU. Las cifras del capítulo 4 deben salir de ahí.
2. **Capítulo 2 (Estado del Arte)** sigue sin redactar: Cowrie, Dionaea, HoneyGPT, LLM-based deception, Thinkst Canary, tecnología de deception comercial.
3. **Apartado 4.4**: si el calendario lo permite, desplegar Cowrie y pasarle el mismo banco de pruebas para que la comparativa sea medida y no cualitativa.
4. **Fase 5 (Red Teaming)**: la emulación con operador humano queda pendiente; si no se hace, declararlo como limitación en lugar de omitirlo.
5. **Validar la integración con Wazuh** (`docs/05` §7) o reportarla explícitamente como especificada y no verificada.
6. Corregir la numeración `1.4.1`, etiquetada «Limitaciones» cuando su contenido es el **Alcance**.
