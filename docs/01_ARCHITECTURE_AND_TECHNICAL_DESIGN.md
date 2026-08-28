# 01. Arquitectura y Diseño Técnico del Sistema

## 1. Visión General de la Solución

El **Generative Deception Framework** implementa un entorno de ciberengaño dinámico e interactivo para la detección temprana de intrusiones. A diferencia de un *honeypot* estático, el sistema no sirve respuestas pregrabadas: mantiene una identidad de host coherente, la puebla con artefactos sintéticos y resuelve la interacción con el atacante mediante una arquitectura multi-agente apoyada en un modelo de lenguaje local y cuantizado (`qwen2.5-coder:0.5b`) ejecutado sobre **Ollama**.

La decisión de diseño central del proyecto es la **resolución híbrida de comandos**, descrita en la sección 4. No es un detalle de implementación: es lo que permite cumplir simultáneamente los dos requisitos que el capítulo 1 de la memoria plantea como críticos y que están en tensión directa —coherencia frente a *fingerprinting*, y latencia por debajo de 1.000 ms.

---

## 2. Topología de Despliegue

Todos los componentes se ejecutan en contenedores sobre la red *bridge* dedicada `deception-net`. **El señuelo SSH es el único servicio publicado hacia el exterior.** Ni el orquestador ni el motor de inferencia son alcanzables desde la red del atacante.

```text
[ Atacante / Red no confiable ]
            │
            │  SSH  ->  host:2222
            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  deception-net (bridge Docker aislado)                                      │
│                                                                             │
│  ┌──────────────────────┐                                                   │
│  │  ssh-decoy           │   Frontend de protocolo. Solo habla SSH.          │
│  │  paramiko            │   Sin persona, sin artefactos, sin LLM.           │
│  │  :2222  [EXPUESTO]   │                                                   │
│  └──────────┬───────────┘                                                   │
│             │ HTTP  POST /session/command                                   │
│             ▼                                                               │
│  ┌──────────────────────┐        ┌──────────────────────────┐               │
│  │  deception-agent     │  HTTP  │  ollama-llm              │               │
│  │  Orquestador         ├───────►│  Motor de inferencia     │               │
│  │  4 agentes           │ :11434 │  qwen2.5-coder:0.5b (Q4) │               │
│  │  :8000 [INTERNO]     │        │  :11434  [INTERNO]       │               │
│  └──────────┬───────────┘        └──────────────────────────┘               │
│             │                                                               │
│             ▼  JSON Lines                                                   │
│  ┌──────────────────────┐                                                   │
│  │  agent_data (volumen)│  deception-events.jsonl  ->  Wazuh / Filebeat      │
│  │                      │  latency.jsonl           ->  benchmark cap. 4      │
│  │                      │  persona.json            ->  identidad congelada   │
│  └──────────────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

El puerto `8000` del orquestador y el `11434` de Ollama se publican **únicamente en la interfaz de loopback del host** (`127.0.0.1`), lo que permite ejecutar el banco de pruebas desde la máquina anfitriona sin exponerlos a la red.

---

## 3. Arquitectura Multi-Agente

El orquestador (`agents/orchestrator.py`) coordina cuatro agentes con responsabilidades disjuntas. Los dos primeros se ejecutan una sola vez en el arranque; los dos últimos, en cada interacción.

| Agente | Módulo | Cuándo se ejecuta | Responsabilidad |
|---|---|---|---|
| **Persona** | `roles/persona.py` | Arranque (1 vez) | Decide **quién dice ser** el host: empresa, dominio, hostname, usuarios, aplicación desplegada. |
| **Artefactos** | `roles/artifacts.py` | Arranque (1 vez) + hilo continuo | Decide **qué hay** en el host: sistema de ficheros virtual, honeytokens, historiales de shell, tráfico de logs. |
| **Terminal** | `roles/terminal.py` | Por comando | Decide **qué responde** el host a un comando concreto. |
| **Alertas** | `roles/alerting.py` | Por evento | Decide **qué se le cuenta al SOC**: clasificación ATT&CK, severidad, telemetría. |

### 3.1. Agente de Persona

Genera la identidad del host llamando **una única vez** al LLM para producir la capa narrativa (empresa ficticia, nombres de usuario, aplicación de negocio) en formato JSON. A partir de ese JSON, el módulo *renderiza de forma determinista* los artefactos de sistema concretos: `/etc/passwd`, `/etc/shadow`, `/etc/group`, la cadena del kernel, la configuración de red, la tabla de procesos.

La separación es intencionada. Pedir `/etc/passwd` al modelo en cada `cat` devuelve un fichero distinto cada vez, que es exactamente la incoherencia que un atacante detecta. Generar la narrativa una vez y renderizar de forma determinista produce un host que sigue siendo el mismo host durante toda la interacción, con coste de inferencia cero por comando.

La persona se cachea en `persona.json`. Si Ollama no responde o devuelve un JSON inválido, se usa un perfil de reserva completo: **el señuelo nunca degrada a un estado obviamente falso por un fallo de inferencia.**

### 3.2. Agente de Artefactos

Materializa el tercer objetivo específico de la memoria. Tres funciones:

1. **Sistema de ficheros virtual.** Nodos con ruta, propietario, permisos, tamaño, fecha y contenido, derivados de la persona. Garantiza que `ls`, `cat` y `/etc/passwd` concuerden entre sí.
2. **Honeytokens.** Credenciales fabricadas —contraseña de base de datos, clave de API, clave SSH privada, `~/.my.cnf`— insertadas en ubicaciones plausibles. No autentican contra nada, por lo que **cualquier uso de una de ellas en cualquier punto del parque es un verdadero positivo por construcción**. Cada una lleva un identificador de rastreo (`HT-XXXXXXXX`).
3. **Simulación de tráfico.** Un hilo en segundo plano añade entradas a `/var/log/nginx/access.log` y `/var/log/auth.log` cada pocos segundos. Responde al vector de *fingerprinting* «inexistencia de tráfico de red legítimo» citado en la sección 1.1 de la memoria: un atacante que haga `tail -f` sobre el log ve peticiones llegando, no un fichero congelado en el momento del despliegue.

Los `.bash_history` se generan con el LLM en el arranque (una llamada por cuenta). Un `.bash_history` vacío es la señal de honeypot más fiable que existe, y es el artefacto que más se beneficia de la generación por modelo.

### 3.3. Agente de Terminal

Ver sección 4.

### 3.4. Agente de Alertas

Convierte cada interacción en un evento JSON Lines listo para SIEM. Toda interacción con el señuelo es no autorizada por construcción, por lo que los eventos llevan confianza fija `confirmed` en lugar de una puntuación heurística. La severidad procede del mapeo ATT&CK (`core/mitre.py`) y escala con el comportamiento de la sesión.

---

## 4. Resolución Híbrida de Comandos

Es el núcleo técnico del trabajo. Cada comando toma una de dos rutas:

**Ruta determinista.** Los comandos de reconocimiento cuya salida debe ser estable y coherente (`whoami`, `id`, `uname`, `cat /etc/passwd`, `ls`, `ps`, `ip a`, `netstat`, `df`, `history`…) se resuelven desde la persona y el sistema de ficheros de artefactos. Coste de cómputo: microsegundos. Fidelidad: exacta. Coherencia entre invocaciones: garantizada.

> **Ojo con «microsegundos».** Ese es el coste de *cómputo*, no el tiempo que ve el atacante. La capa de normalización (sección 4.4) retiene deliberadamente la respuesta hasta el objetivo que le corresponde a ese comando, de modo que la latencia medida en la ruta determinista es de **cientos de milisegundos**. Es intencionado: una respuesta instantánea es tan delatora como una lenta.

**Ruta generativa.** Todo lo demás se envía al LLM local, inyectando el bloque de contexto de la persona y los últimos turnos de la sesión, de forma que la invención del modelo se mantenga dentro del mundo que la capa determinista ya estableció.

El argumento de diseño:

> Enviar **todos** los comandos al modelo sería más simple y peor: gastaría el presupuesto de 1.000 ms en trivialidades y respondería `cat /etc/passwd` distinto cada vez. Enviar **ninguno** reconstruiría un honeypot estático. La división es lo que compra ambas propiedades a la vez, y el reparto determinista/generativo es una métrica de cabecera del capítulo 4.

### 4.1. Tuberías

Una tubería se resuelve por su primer segmento y los filtros posteriores (`grep`, `head`, `tail`, `wc`, `sort`, `uniq`) se aplican sobre ese texto en Python. Así `cat /etc/passwd | grep root` permanece en la ruta determinista en lugar de caer al modelo.

### 4.2. Estado de sesión

Cada sesión mantiene su `cwd`, sus variables de entorno y una **capa de superposición** del sistema de ficheros con lo que el atacante ha creado o borrado. Un `touch /tmp/payload.sh` seguido de `ls /tmp` es coherente. Esto materializa la limitación declarada en la sección 1.4.2 de la memoria: el estado vive en el ámbito de la sesión activa.

### 4.3. Normalización de latencia

La resolución híbrida crea, sin quererlo, el problema más serio del diseño. Medido sobre el hardware de referencia, las dos rutas costaban **2,4 ms ± 1,6** y **2.044,4 ms ± 7,3**: dos poblaciones limpias, estrechas y separadas por dos segundos. Ningún host real se comporta así. Un atacante que se limite a cronometrar las respuestas las reparte en dos cubos y deduce algo que ningún honeypot debería revelar —que detrás de algunas hay un modelo de lenguaje, y por tanto que el host es un señuelo—. Bajar el coste de inferencia no lo arregla: la señal no es la magnitud, es la **bimodalidad**.

`agents/core/latency.py` impone la propiedad que faltaba: la latencia debe ser función del **comando**, que el atacante ve, y nunca de la **ruta**, que es un detalle interno.

```text
L  =  rtt(sesion)  +  coste_ejecucion(clase_del_comando)  +  jitter
```

Antes de resolver nada se sortea el objetivo de ese comando a partir de su clase de coste (`builtin`, `read_small`, `list_dir`, `proc_scan`, `net_probe`, `heavy`), con una mediana y una dispersión log-normal tomadas de lo que ese tipo de comando cuesta en un servidor real. El RTT es constante dentro de la sesión, porque un atacante conecta por una sola ruta de red. Resuelva quien resuelva, la respuesta se retiene hasta que el objetivo se agota.

**Limitación honesta, y es la que gobierna el resultado.** El relleno solo puede *añadir* tiempo. Cuando la ruta generativa desborda su objetivo, el retraso ya no se puede devolver y esa muestra sigue siendo separable. Esos desbordamientos se cuentan (`overruns`) y se reportan en lugar de esconderse: **el porcentaje de exceso es la medida real de si la normalización se sostiene**, y llevarlo a cero es un problema de ajuste —`MAX_TOKENS`, tamaño del modelo, objetivo por clase—. En la ejecución de referencia desbordó el 12,96 % de las muestras, todas en la clase `proc_scan`, que es exactamente la clase que sigue siendo separable.

La métrica que acompaña a este módulo no es «media por debajo de 1.000 ms» sino «un atacante no puede separar las dos rutas por tiempo», que es contrastable: ver `benchmarks/stats.py` (Kolmogorov-Smirnov de dos muestras, AUC del mejor clasificador temporal y coeficiente de bimodalidad).

### 4.4. Higiene de salida

La salida del modelo se somete a un filtro antes de llegar al atacante: se eliminan bloques de código markdown y prompts reflejados, y **cualquier respuesta que rompa el personaje** (menciones a IA, modelo, simulación, honeypot, Ollama…) se descarta por completo y se sustituye por un error de bash creíble. La salida también se acota en líneas: un muro de texto es en sí mismo una señal.

---

## 5. Flujo de una Interacción

```text
[Atacante]        [ssh-decoy]       [deception-agent]        [ollama-llm]
    │                  │                    │                     │
    │── SSH connect ──►│                    │                     │
    │                  │── POST /open ─────►│  Alerta: session.opened
    │                  │◄── session_id ─────┤
    │◄─ banner MOTD ───┤   + banner + prompt│
    │                  │                    │
    │── "root/1234" ──►│── POST /auth ─────►│  Alerta: auth.attempt (credenciales)
    │◄── aceptado ─────┤                    │
    │                  │                    │
    │── "whoami" ─────►│── POST /command ──►│  RUTA DETERMINISTA
    │                  │                    │  persona.users -> "root"
    │◄─── "root" ──────┤◄─── ~0.1 ms ───────┤  Alerta: command.executed T1033
    │                  │                    │
    │── "figlet hola"─►│── POST /command ──►│  RUTA GENERATIVA
    │                  │                    │──── /api/chat ─────►│
    │                  │                    │◄─── stdout ─────────┤
    │◄── salida ───────┤◄─────────────────  │  Alerta: command.executed
    │                  │                    │  + latencia registrada
    │── "exit" ───────►│── POST /close ────►│  Alerta: session.closed (resumen)
```

---

## 6. Aislamiento y Contención

1. **Superficie expuesta mínima.** Solo el puerto del señuelo SSH está publicado. El orquestador y Ollama viven en la red interna.
2. **Sin ejecución real.** Ninguna respuesta procede de ejecutar nada: no se invoca `/bin/bash`, no hay `subprocess`, no hay evaluación de la entrada del atacante. Las técnicas de escape basadas en sintaxis bash no tienen sobre qué actuar.
3. **Contenedor del señuelo endurecido.** `cap_drop: ALL` y `no-new-privileges`. El señuelo escucha en el puerto no privilegiado 2222 dentro del contenedor precisamente para no necesitar `CAP_NET_BIND_SERVICE`.
4. **Límite de sesiones concurrentes.** Un semáforo acotado rechaza conexiones por encima del límite: la inundación de conexiones es un ataque plausible contra el propio señuelo.
5. **Fallo cerrado.** Si el orquestador o el motor de inferencia caen, el señuelo responde con errores de shell verosímiles en lugar de trazas o silencio.

> **Nota de operación.** El señuelo captura credenciales en texto claro por diseño. El volumen `agent_data` contiene datos sensibles de la interacción y debe tratarse con el mismo control de acceso que cualquier fuente de telemetría del SOC.

---

## 7. Mapa de Ficheros

```text
agents/
├── main.py                 API HTTP (FastAPI) del orquestador
├── orchestrator.py         Coordinación de los cuatro agentes y ciclo de sesión
├── core/
│   ├── config.py           Configuración por variables de entorno
│   ├── llm.py              Cliente Ollama instrumentado (mide cada llamada)
│   ├── latency.py          Normalización: la latencia depende del comando, no de la ruta
│   ├── mitre.py            Mapeo comando -> técnica ATT&CK -> severidad
│   ├── session.py          Estado por sesión: cwd, entorno, overlay de ficheros
│   └── telemetry.py        Emisión de eventos JSON Lines para SIEM
└── roles/
    ├── persona.py          Agente de Persona
    ├── artifacts.py        Agente de Artefactos
    ├── terminal.py         Agente de Terminal (resolución híbrida)
    └── alerting.py         Agente de Alertas

decoys/ssh/ssh_server.py    Frontend de protocolo SSH (paramiko)
benchmarks/                 Banco de pruebas de latencia y fidelidad
benchmarks/stats.py         KS, AUC y bimodalidad, sin scipy ni numpy
siem/                       Reglas de Wazuh y validador contra el manager
evaluation/                 Atacante LLM, juez ciego y host real de control
tests/test_core.py          Suite offline (sin Docker ni Ollama)
```
