# 04. Borrador y Estructura de la Memoria del TFM

## Datos del Proyecto
* **Título:** Ciberengaño Dinámico Multi-Agente con IA (Generative Deception)
* **Autor:** María
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

## Resumen del Capítulo 1

### 1.1. Contexto y Planteamiento del Problema
En el panorama actual de la ciberseguridad, las amenazas avanzadas persistentes (APTs) han evolucionado sus técnicas para evadir los controles perimetrales tradicionales. Cuando un atacante logra acceso inicial a una red corporativa, inicia una fase de reconocimiento interno y movimiento lateral. Los Centros de Operaciones de Seguridad (SOC) enfrentan altos niveles de fatiga de alertas debido a los falsos positivos generados por herramientas convencionales.

### 1.2. Justificación Técnica
Para resolver estas deficiencias, la defensa activa propone el **Ciberengaño Generativo**. Al integrar Inteligencia Artificial mediante LLMs locales aislados en contenedores Docker, es posible simular entornos interactivos creíbles que:
1. Garantizan una tasa de falsos positivos igual a cero (cualquier acceso no autorizado a un señuelo es malicioso).
2. Evitan el *fingerprinting* de servicios estáticos mediante la generación dinâmica de respuestas.
3. Mantienen estricta privacidad y reproducibilidad sin depender de servicios en la nube.