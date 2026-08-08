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
