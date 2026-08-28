# Resultados medidos de latencia y fidelidad

Generado automaticamente por `benchmarks/latency_benchmark.py` el 2026-08-22T23:40:56+00:00. **No editar a mano**: se regenera en cada ejecucion.

Objetivo de latencia: **1000 ms**. Muestras totales: **54**.

> **Reagregado el 2026-08-28 sin volver a medir.** Mismas muestras que la ejecucion original; se recalculan los agregados tras corregir dos defectos de informe.

## 1. Resumen global

| Ruta | n | Media | Mediana | Desv. tip. | Min | Max | p95 | p99 | Dentro de objetivo | Fidelidad |
|---|---|---|---|---|---|---|---|---|---|---|
| **Global** | 54 | 971.1 ms | 786.3 ms | 486.6 ms | 717.3 ms | 2970.4 ms | 1831.9 ms | 2939.1 ms | 83.3 % | 100.0 % |
| Determinista | 27 | 855.6 ms | 781.2 ms | 158.4 ms | 718.8 ms | 1397.5 ms | 1003.6 ms | 1295.4 ms | 88.9 % | 100.0 % |
| Generativa | 27 | 1086.6 ms | 912.0 ms | 655.7 ms | 717.3 ms | 2970.4 ms | 2829.5 ms | 2955.1 ms | 77.8 % | 100.0 % |

Reparto de rutas: **50.0 %** determinista, **50.0 %** generativa.

## 2. Detalle por comando

| Comando | Tecnica ATT&CK | Ruta | n | Media | p95 | Dentro de objetivo | Fidelidad |
|---|---|---|---|---|---|---|---|
| `whoami` | T1033 | deterministic | 3 | 801.8 ms | 933.4 ms | 100.0 % | 100.0 % |
| `hostname` | T1082 | deterministic | 3 | 805.7 ms | 940.9 ms | 100.0 % | 100.0 % |
| `pwd` | T1083 | deterministic | 3 | 804.7 ms | 936.9 ms | 100.0 % | 100.0 % |
| `ps aux` | T1057 | deterministic | 3 | 827.7 ms | 974.9 ms | 66.7 % | 100.0 % |
| `df -h` | T1082 | deterministic | 3 | 824.0 ms | 971.4 ms | 100.0 % | 100.0 % |
| `stat /etc/passwd` | T1083 | generative | 3 | 870.2 ms | 959.3 ms | 100.0 % | 100.0 % |
| `tty` | T1033 | generative | 3 | 802.2 ms | 934.4 ms | 100.0 % | 100.0 % |
| `umask` | T1082 | generative | 3 | 805.6 ms | 941.2 ms | 100.0 % | 100.0 % |
| `alias` | T1082 | generative | 3 | 805.9 ms | 940.5 ms | 100.0 % | 100.0 % |
| `wc -l /etc/passwd` | T1087.001 | generative | 3 | 808.1 ms | 940.7 ms | 100.0 % | 100.0 % |
| `head -3 /etc/passwd` | T1087.001 | deterministic | 3 | 809.5 ms | 938.5 ms | 100.0 % | 100.0 % |
| `uname -r` | T1082 | deterministic | 3 | 1111.6 ms | 1356.7 ms | 66.7 % | 100.0 % |
| `file /etc/passwd` | T1083 | generative | 3 | 805.4 ms | 941.3 ms | 100.0 % | 100.0 % |
| `printenv HOME` | T1082 | generative | 3 | 804.9 ms | 944.8 ms | 100.0 % | 100.0 % |
| `free -m` | T1082 | deterministic | 3 | 866.0 ms | 984.5 ms | 66.7 % | 100.0 % |
| `ss -tulpn` | T1049 | deterministic | 3 | 849.7 ms | 976.8 ms | 100.0 % | 100.0 % |
| `lsblk` | T1082 | generative | 3 | 2840.2 ms | 2964.5 ms | 0.0 % | 100.0 % |
| `vmstat 1 1` | T1082 | generative | 3 | 1236.5 ms | 1258.2 ms | 0.0 % | 100.0 % |

## 3. Indistinguibilidad temporal de las dos rutas

La pregunta que responde este apartado no es si la latencia media cumple el objetivo, sino si un atacante que **solo cronometra respuestas** puede saber cual de las dos rutas le ha contestado. Si puede, deduce que hay un modelo de lenguaje detras y que el host es un senuelo.

| Estadistico | Valor | Lectura |
|---|---|---|
| Kolmogorov-Smirnov D | 0.2222 | Distancia maxima entre las dos distribuciones empiricas (0 = identicas). |
| KS p-valor | 0.465599 | Por debajo de 0,05 las rutas son estadisticamente distinguibles. |
| AUC | 0.4993 | Acierto del mejor clasificador temporal posible (0,5 = azar). |
| Ventaja del atacante | 0.1 % | Cuanto supera al azar. |
| Coef. de bimodalidad | 0.852 | Por encima de 0,555 la muestra agrupada es mas compatible con dos modas que con una. |

**Veredicto: INDISTINGUIBLE.** No se detecta diferencia entre las dos rutas (KS no significativo) y un clasificador temporal apenas supera el azar.

Normalizacion: **7** comandos (12.96 %) excedieron su objetivo y no pudieron rellenarse, con un exceso medio de 1047.1 ms.

El relleno solo puede **anadir** tiempo. Un comando cuya resolucion ya supera su objetivo no admite correccion, y esa muestra sigue siendo separable: el porcentaje de exceso es, por tanto, la medida real de si la normalizacion se sostiene.

### 3.1. Por clase de comando

La cifra global esta **confundida**: la ruta que toma un comando la decide el propio comando, de modo que los comandos de la ruta lenta son tambien los intrinsecamente mas costosos en un host real. Comparar solo dentro de una misma clase elimina esa confusion.

| Clase | n det. | n gen. | KS D | p | AUC | Ventaja | Veredicto |
|---|---|---|---|---|---|---|---|
| `builtin` | 9 | 9 | 0.2222 | 0.957475 | 0.4938 | 1.2 % | INDISTINGUIBLE |
| `heavy` | 3 | 0 | — | — | — | — | Sin comparacion: una sola ruta alcanza esta clase |
| `proc_scan` | 12 | 6 | 1.0 | 0.000156 | 1.0 | 100.0 % | SEPARABLE |
| `read_small` | 3 | 12 | 0.4167 | 0.669176 | 0.4444 | 11.1 % | INSUFICIENTE |

> El contraste KS puede demostrar que dos distribuciones **diferen**, pero nunca que sean identicas. Un p-valor alto es evidencia de indistinguibilidad al tamano de muestra empleado, no una prueba.

## 4. Fallos de fidelidad observados

Ninguno: todas las salidas contienen los tokens esperados.
