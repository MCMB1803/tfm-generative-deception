# 01. Arquitectura y Diseño Técnico del Sistema

## 1. Visión General de la Solución
El proyecto **Generative Deception Framework** implementa un entorno de ciberengaño dinámico e interactivo diseñado para la detección temprana de amenazas avanzadas (APTs) e intrusiones en redes corporativas.

A diferencia de los *honeypots* pasivos tradicionales, esta arquitectura utiliza Inteligencia Artificial Generativa a través de un modelo de lenguaje (LLM) local y cuantizado (`qwen2.5-coder:3b`) ejecutado mediante **Ollama**. Esto permite emular el comportamiento completo de una terminal SSH de Linux en tiempo real sin revelar artefactos estáticos ni firmas previsibles.

---

## 2. Diagrama de Topología e Infraestructura (Docker Compose)

Toda la solución está containerizada y aislada en una red virtual dedicada denominada `deception-net` (`172.18.0.0/16`), garantizando contención absoluta frente a un posible compromiso.

```text
[ Atacante / Red Externa ]
            │
            │  SSH (Port 2222)
            ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Docker Host (deception-net)                                           │
│                                                                        │
│   ┌────────────────────────┐         ┌──────────────────────────────┐ │
│   │   Contenedor:          │         │   Contenedor:                │ │
│   │   ssh-decoy            │  HTTP   │   ollama-llm                 │ │
│   │   (Python + Paramiko)  ├────────►│   (Ollama Engine)            │ │
│   │   Port: 2222:22        │  :11434 │   Model: qwen2.5-coder:3b    │ │
│   └───────────┬────────────┘         └──────────────────────────────┘ │
│               │                                                        │
│               │ Logs & Telemetría                                      │
│               ▼                                                        │
│   ┌────────────────────────┐                                           │
│   │   Contenedor:          │                                           │
│   │   deception-agent      │                                           │
│   │   (Orquestador & Test) │                                           │
│   └────────────────────────┘                                           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Descripción de Componentes

### 3.1. Servidor Trampa SSH (`ssh-decoy`)
* **Puerto Expuesto:** `2222` (mapeado al puerto interno `22`).
* **Tecnología:** Python 3.11 con librería `paramiko` para emulación de protocolo SSH a bajo nivel.
* **Mecanismo de Autenticación:**
  * Acepta cualquier combinación de usuario y contraseña (*catch-all*).
  * Genera una alerta inmediata en los registros indicando la IP de origen, puerto, usuario y clave ingresada.
* **Gestión de Sesión:**
  * Emula la experiencia de *pseudo-terminal* (PTY) interactiva.
  * Mantiene búferes de comandos y procesa caracteres de control (`
`, `
`, `Ctrl+C`).
  * Envía el prompt emulado `root@ubuntu-srv:~# `.

### 3.2. Motor Inferencia IA Local (`ollama-llm`)
* **Puerto Interno:** `11434`.
* **Modelo Elegido:** `qwen2.5-coder:3b` (Cuantización Q4_K_M).
* **Razón de Elección:** Optimizado específicamente para la generación de código, sintaxis de consola bash y salida estructurada sin decoraciones visuales innecesarias.
* **Inferencia Offline:** Cero dependencias de APIs de pago externas (OpenAI/Anthropic/Claude), manteniendo privacidad absoluta y consistencia en evaluaciones académicas y profesionales.

### 3.3. Agente Orquestador y Test de Latencia (`deception-agent`)
* **Función:** Monitorear el estado de salud (*healthcheck*) de los servicios y realizar pruebas automatizadas de latencia del motor de inferencia enviando comandos simulados de telemetría.

---

## 4. Flujo de Datos y Secuencia de Interacción

```text
[Atacante]           [ssh-decoy]           [ollama-llm]
    │                     │                     │
    │─── 1. SSH Connect ─►│                     │
    │    (Port 2222)      │                     │
    │                     │── 2. Log Auth ─────►│ (Guarda credenciales)
    │◄── 3. Banner Ubuntu ┤                     │
    │                     │                     │
    │─── 4. 'whoami' ────►│                     │
    │                     │── 5. POST /generate►│ (Prompt del sistema)
    │                     │◄── 6. Raw stdout ───┤ (Latencia: ~0.4s)
    │◄── 7. "root
" ─────┤                     │
```

---

## 5. Medidas de Aislamiento y Seguridad

1. **Aislamiento de Red:** Los contenedores se comunican exclusivamente a través del *bridge* `deception-net`. No hay acceso a redes internas de producción.
2. **Sin Privilegios Reales:** El contenedor `ssh-decoy` corre en espacio de usuario limitado dentro del contenedor Docker. Los comandos ejecutados no tocan el sistema operativo host.
3. **Control de Escape de Shell:** Todas las respuestas provienen del motor probabilístico de IA; no existe ejecución de shell real (`/bin/bash` local no es invocado), anulando ataques de escape de contenedor basados en sintaxis bash.