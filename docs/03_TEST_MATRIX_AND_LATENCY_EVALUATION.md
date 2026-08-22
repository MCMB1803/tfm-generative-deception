# 03. Matriz de Pruebas y Metodología de Evaluación

> **Este documento define *cómo* se mide. No contiene resultados.**
> Las cifras medidas se generan automáticamente en `benchmarks/results/RESULTS.md`
> al ejecutar el banco de pruebas, y no deben transcribirse a mano a ningún otro
> sitio. Cualquier número que aparezca en la memoria del TFM debe proceder de una
> ejecución concreta y reproducible de este banco, con su hardware documentado.

---

## 1. Hipótesis a Validar

| ID | Hipótesis | Criterio de aceptación | Instrumento |
|---|---|---|---|
| **H1** | El sistema responde lo bastante rápido como para no delatarse por latencia. | p95 de latencia extremo a extremo por debajo de 1.000 ms. | `benchmarks/latency_benchmark.py` |
| **H2** | Las salidas son fieles a un Ubuntu 22.04 real. | 100 % de las aserciones de fidelidad superadas. | Mismo banco, columna `fidelity_pass` |
| **H3** | La emulación es coherente consigo misma dentro de una sesión. | `cat /etc/passwd` idéntico entre invocaciones; ficheros creados visibles después. | `tests/test_core.py` |
| **H4** | El sistema no produce falsos positivos. | Todo evento emitido corresponde a una interacción no autorizada. | Argumento estructural, sección 5 |
| **H5** | El señuelo sigue siendo creíble si el motor de inferencia cae. | Ninguna traza ni error interno alcanza al atacante. | `tests/test_core.py`, bloque de degradación |

---

## 2. Instrumentación

Cada comando resuelto emite un registro en `latency.jsonl` con:

| Campo | Significado |
|---|---|
| `route` | `deterministic` o `generative`. **La variable independiente principal.** |
| `handler` | Manejador concreto que resolvió el comando (`whoami`, `ls`, `llm`…). |
| `total_ms` | Tiempo de resolución dentro del orquestador. |
| `llm_ms` | Tiempo atribuible a la inferencia (0 en ruta determinista). |
| `eval_tokens` | Tokens generados por el modelo. |
| `within_target` | Si la respuesta cumplió el objetivo de latencia. |

El banco de pruebas mide además `wall_ms`: el tiempo **extremo a extremo desde el cliente**, incluyendo el salto HTTP que el señuelo SSH también paga. `wall_ms` es la cifra que debe reportarse en la memoria, porque es la que experimenta el atacante. `total_ms` y `llm_ms` sirven para descomponerla.

---

## 3. Matriz de Comandos

Secuencia de 30 comandos alineada con las técnicas MITRE ATT&CK declaradas en el alcance (sección 1.4.1 de la memoria). Definida en `benchmarks/latency_benchmark.py::RECON_SEQUENCE`.

La columna **Aserción** es la comprobación objetiva de fidelidad: subcadenas que la salida debe contener obligatoriamente. Son aserciones de subcadena, no juicios de valor, para que un tercero pueda reproducir el resultado exactamente.

| ID | Comando | Técnica ATT&CK | Aserción de fidelidad |
|---|---|---|---|
| TC-01 | `whoami` | T1033 | `root` |
| TC-02 | `id` | T1033 | `uid=0`, `root` |
| TC-03 | `hostname` | T1082 | — |
| TC-04 | `uname -a` | T1082 | `Linux`, `x86_64` |
| TC-05 | `cat /etc/os-release` | T1082 | `Ubuntu`, `22.04` |
| TC-06 | `pwd` | T1083 | `/root` |
| TC-07 | `ls -la` | T1083 | `total` |
| TC-08 | `ls -la /var/www` | T1083 | — |
| TC-09 | `cat /etc/passwd` | T1087.001 | `root:x:0:0`, `/bin/bash` |
| TC-10 | `cat /etc/shadow` | T1087.001 | `root:$6$` |
| TC-11 | `cat /etc/group` | T1087.001 | `sudo:x:27` |
| TC-12 | `ps aux` | T1057 | `USER`, `PID`, `nginx` |
| TC-13 | `ip a` | T1016 | `eth0`, `inet` |
| TC-14 | `netstat -tulpn` | T1016 | `LISTEN` |
| TC-15 | `cat /etc/hosts` | T1016 | `127.0.0.1`, `localhost` |
| TC-16 | `df -h` | T1082 | `Filesystem`, `/dev/sda` |
| TC-17 | `free -h` | T1082 | `Mem:`, `Swap:` |
| TC-18 | `history` | T1552.001 | — |
| TC-19 | `cat /root/.bash_history` | T1552.001 | — |
| TC-20 | `ls -la /root/.ssh` | T1552.004 | `id_rsa` |
| TC-21 | `cat /root/.ssh/id_rsa` | T1552.004 | `PRIVATE KEY` |
| TC-22 | `cat /root/.my.cnf` | T1552.001 | `password` |
| TC-23 | `crontab -l` | T1053.003 | — |
| TC-24 | `cat /etc/crontab` | T1053.003 | `SHELL`, `PATH` |
| TC-25 | `tail -20 /var/log/auth.log` | T1005 | — |
| TC-26 | `cat /etc/passwd \| grep bash` | T1087.001 | `root` |
| TC-27 | `sudo -l` | T1548.003 | `may run` |
| TC-28 | `which nmap` | T1046 | — |
| TC-29 | `uptime` | T1082 | `load average` |
| TC-30 | `lscpu` | T1082 | `Architecture` |

Los casos sin aserción (TC-03, TC-08, TC-18, TC-19, TC-23, TC-25, TC-28) se miden en latencia pero su fidelidad depende de la persona generada, que varía entre despliegues; se evalúan cualitativamente en el capítulo 4.

---

## 4. Escenarios

| Escenario | Descripción | Qué mide |
|---|---|---|
| `recon` | Los 30 comandos en **una única sesión**, en orden. | Latencia en condiciones normales; ejercita la coherencia de sesión y el crecimiento del contexto inyectado al modelo. |
| `cold` | Cada comando en una **sesión nueva**. | Coste del atacante que conecta, ejecuta un comando y se va. Aísla el sobrecoste de apertura de sesión. |

---

## 5. Procedimiento de Ejecución

```bash
# 1. Levantar la pila completa y esperar a que el modelo se descargue
docker compose up -d --build

# 2. Confirmar que el orquestador está listo
curl -s http://127.0.0.1:8000/stats | python -m json.tool

# 3. Suite offline de coherencia (H3, H5) -- no necesita Docker
python tests/test_core.py

# 4. Banco de latencia y fidelidad (H1, H2)
python benchmarks/latency_benchmark.py --scenario both --repeat 5
```

**Documentar siempre junto a los resultados:** modelo de CPU, núcleos, RAM, si Docker corre sobre WSL2 o Linux nativo, presencia o ausencia de GPU, y la etiqueta exacta del modelo. La latencia de inferencia depende por completo del hardware, y un resultado sin su entorno no es reproducible.

Se recomienda `--repeat 5` como mínimo. Con una sola iteración la desviación típica no es interpretable y el primer comando absorbe el coste de carga del modelo.

---

## 6. Sobre la Ausencia de Falsos Positivos (H4)

H4 **no se valida experimentalmente**, y la memoria debe decirlo así explícitamente. No es una medida, es una propiedad estructural: ningún usuario ni proceso legítimo de la organización tiene motivo operativo para conectarse a un host señuelo que no aparece en ningún inventario ni en ningún flujo de trabajo. Toda conexión es, por construcción, no autorizada.

Esta propiedad tiene dos condiciones de contorno que conviene declarar en el capítulo 4 en lugar de omitirlas:

1. **Escaneo legítimo.** Un escáner de vulnerabilidades corporativo o un inventario de red generarán conexiones al señuelo. Son verdaderos positivos de conexión pero no de intrusión, y deben excluirse por IP de origen en la regla de correlación del SIEM.
2. **Tráfico de fondo de Internet.** Si el señuelo se expone a Internet en lugar de a un segmento interno, recibirá ruido de escaneo masivo continuo. Sigue sin ser un falso positivo, pero cambia por completo el volumen de alertas y la interpretación del indicador.

---

## 7. Limitaciones de la Evaluación

* **Un solo modelo.** Toda la evaluación usa `qwen2.5-coder:3b`. Una comparativa entre modelos y niveles de cuantización queda como trabajo futuro.
* **Sin adversario humano.** El banco ejecuta una secuencia fija. No mide si un operador de *red team* con experiencia identificaría el entorno; eso requiere un estudio con sujetos, fuera del alcance.
* **La fidelidad se mide por subcadenas.** Una salida puede contener los tokens esperados y aun así resultar poco creíble en conjunto. La aserción es una cota inferior de fidelidad, no una medida de realismo.
* **Sin línea base comparativa medida.** La comparación con Cowrie/Dionaea del apartado 4.4 de la memoria es cualitativa salvo que se despliegue Cowrie y se le pase el mismo banco de pruebas, lo cual es recomendable si el calendario lo permite.
