# Generative Deception Framework (TFM - UCM)

Sistema de Ciberengaño Dinámico e Interactivo guiado por Arquitecturas Multi-Agente e Inteligencia Artificial (LLM Local) para entornos corporativos.

---

## 📌 Descripción del Proyecto

Este proyecto constituye la implementación práctica del Trabajo Fin de Máster (**Máster en Ciberseguridad - Universidad Complutense de Madrid**). El objetivo es desplegar una solución de **Defensa Activa y Ciberengaño (Generative Deception)** capaz de superar las limitaciones de los *honeypots* estáticos tradicionales.

Mediante el uso de un ecosistema multi-agente en Python orquestado con un modelo de lenguaje local (LLM cuantizado ejecutado en Ollama), el sistema genera artefactos sintéticos, simula comportamiento humano e interactúa en tiempo real con atacantes con una latencia mínima, garantizando alertas de intrusión en el SOC con una tasa de falsos positivos cercana a cero.

---

## 🏗️ Arquitectura y Estructura del Repositorio

El proyecto está diseñado para ser **100% reproducible** mediante Docker y Docker Compose, aislando todos los componentes dentro de una red virtual dedicada (`deception-net`).

```text
tfm-generative-deception/
├── docker-compose.yml
├── .gitignore
├── README.md
└── agents/
    ├── Dockerfile
    ├── requirements.txt
    └── main.py
└── docs/
    ├── 01_ARCHITECTURE_AND_TECHNICAL_DESIGN
    ├── 02_DEPLOYMENT_AND_TROUBLESHOOTING_GUIDE
    ├── 03_TEST_MATRIX_AND_LATENCY_EVALUATION
    └── 04_TFM_THESIS_DRAFT_AND_STRUCTURE
```


## Componentes Clave

* `ollama-llm`: Contenedor con el motor de inferencia local (Ollama) ejecutando modelos cuantizados ligeros (qwen2.5-coder:3b).
* `deception-agent`: Orquestador multi-agente desarrollado en Python para gestionar la interacción entre los servicios trampa (decoys) y el LLM, midiendo tiempos de latencia.

## 🚀 Requisitos Previos e Instalación

### Prerrequisitos

* Docker Engine (v20.10+) y Docker Compose (v2.0+).
* Git.

### Despliegue Rápido
1. Clonar el repositorio:


```bash
git clone [https://github.com/MCMB1803/tfm-generative-deception.git](https://github.com/MCMB1803/tfm-generative-deception.git)
cd tfm-generative-deception
```
2. Iniciar el motor de IA local (Ollama):

```bash
docker-compose up -d ollama-llm
```
3. Descargar el modelo cuantizado ultraligero:

```bash
docker exec -it ollama_llm ollama run qwen2.5-coder:3b
```
*(Escribe `/bye` y pulsa Enter una vez cargado el prompt para salir).*

4. Construir y ejecutar el orquestador multi-agente (Test de Latencia):


```bash
docker-compose up --build deception-agent
```

## 🧪 Verificación de Latencia y Rendimiento
El contenedor deception-agent ejecuta pruebas automáticas de simulación de comandos de consola (whoami, ls -la) enviando peticiones al LLM local para registrar la latencia de respuesta (medida en segundos).

**Objetivo de rendimiento**: Mantener las respuestas por debajo de 1.000 ms para evitar que la latencia del LLM delate el entorno trampa ante un atacante.

### 🗺️ Roadmap de Desarrollo

- [x] Fase 1: Infraestructura base en Docker Compose con Ollama y Python Agent.

- [ ] Fase 2: Implementación del servicio SSH trampa expuesto (ssh-decoy en puerto 2222).

- [ ] Fase 3: Desarrollo del Agente de Artefactos e Inyección Dinámica de .bash_history y archivos trampa.

- [ ] Fase 4: Integración con SIEM Open Source (Wazuh / ELK Stack) para alertado automatizado.

- [ ] Fase 5: Pruebas de emulación de adversarios (Red Teaming) y medición final de latencias.

---
## ✒️ Créditos y Tutoría

* **Autor:** María Celeste Montoya Bonilla
* **Programa:** Máster en Ciberseguridad - Universidad Complutense de Madrid
* **Tutores:** Prof. Javier Domínguez Gómez / Prof. Román Ramírez Giménez
