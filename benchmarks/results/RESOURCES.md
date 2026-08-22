# Consumo de recursos por contenedor

Generado automaticamente por `benchmarks/resource_monitor.py` el 2026-08-22T23:44:43+00:00. **No editar a mano**: se regenera en cada ejecucion.

Instantes muestreados: **7** (21 lecturas de contenedor).

| Contenedor | Muestras | CPU media | CPU maxima | Desv. tip. CPU | RAM media | RAM maxima |
|---|---|---|---|---|---|---|
| `ollama_llm` | 7 | 0.34 % | 2.31 % | 0.87 % | 4474.9 MiB | 4474.9 MiB |
| `deception_agent` | 7 | 0.77 % | 4.17 % | 1.5 % | 41.9 MiB | 41.9 MiB |
| `honeypot_ssh` | 7 | 0.0 % | 0.0 % | 0.0 % | 29.0 MiB | 29.0 MiB |
| **Pila completa** | 7 | 1.11 % | 4.18 % | — | 4545.8 MiB | 4545.8 MiB |

El total de la pila se calcula sumando los contenedores **en cada instante** y tomando despues el peor instante, no sumando el maximo que alcanzo cada contenedor por separado: esos picos pueden no haber coincidido nunca.

> El porcentaje de CPU que reporta Docker esta normalizado al total de nucleos: 100 % equivale a un nucleo saturado, no a la maquina entera.
