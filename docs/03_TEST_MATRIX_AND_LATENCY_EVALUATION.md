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
| **H1b** | Un atacante que solo cronometra respuestas no puede saber qué ruta le contestó. | KS no significativo (p ≥ 0,05) y ventaja del clasificador temporal < 20 %, **estratificado por clase de comando**. | `benchmarks/stats.py` |
| **H2** | Las salidas son fieles a un Ubuntu 22.04 real. | 100 % de las aserciones de fidelidad superadas. | Mismo banco, columna `fidelity_pass` |
| **H3** | La emulación es coherente consigo misma dentro de una sesión. | `cat /etc/passwd` idéntico entre invocaciones; ficheros creados visibles después. | `tests/test_core.py` |
| **H4** | El sistema no produce falsos positivos. | Todo evento emitido corresponde a una interacción no autorizada. | Argumento estructural, sección 5 |
| **H5** | El señuelo sigue siendo creíble si el motor de inferencia cae. | Ninguna traza ni error interno alcanza al atacante. | `tests/test_core.py`, bloque de degradación |

> **H1 y H1b no se cumplen a la vez, y la memoria debe decirlo.** La normalización de latencia
> (`agents/core/latency.py`) persigue H1b **añadiendo** tiempo: retiene cada respuesta hasta el
> objetivo que le corresponde a su clase de comando. Eso sube necesariamente el p95 y, en la
> ejecución de referencia, lo deja en **1.831,9 ms**: H1, tal como está redactada, **no se cumple**.
>
> El conflicto no es un fallo, es el hallazgo. Un sistema que responde en 2 ms cumple H1 con
> holgura y suspende H1b de forma catastrófica, porque la instantaneidad es en sí misma la señal.
> H1 mide la hipótesis equivocada: importa que la latencia sea **plausible para el comando**, no
> que sea baja. La redacción correcta para la memoria es la de H1b, y H1 debe reformularse como
> **«el 83,3 % de las respuestas cae dentro del objetivo de su clase»** o retirarse.

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

### 3.1. La suite `paired`: la única que contrasta indistinguibilidad

La matriz anterior mide **cobertura y fidelidad**, y para eso sirve. Pero no puede contrastar H1b, y conviene entender por qué antes de citar ninguna cifra de indistinguibilidad.

El problema es de confusión estadística. La ruta que toma un comando la decide el propio comando, de modo que los comandos que caen a la ruta generativa son también los intrínsecamente más caros en un host real. Comparar `whoami` (determinista, instantáneo de verdad) con `dpkg -l` (generativo, lento de verdad) y concluir que «las rutas difieren» no dice nada sobre el señuelo: diría lo mismo de un servidor legítimo. En `RECON_SEQUENCE` y `GENERATIVE_SEQUENCE` el reparto es casi perfecto por ruta, así que una comparación **dentro de la misma clase de coste** no tiene nada que comparar.

`PAIRED_SEQUENCE` (`benchmarks/latency_benchmark.py`) existe para eso: 18 comandos en tres bloques, escritos para que dentro de cada bloque **cuesten lo mismo en un host real** pero el marco resuelva la mitad por cada ruta.

| Bloque | Coste real | Comandos |
|---|---|---|
| `builtin` | casi instantáneo | `whoami`, `pwd`, `hostname`, `tty`, `umask`, `alias` |
| `read_small` | una lectura corta | `wc -l /etc/passwd`, `head -3 /etc/passwd`, `uname -r`, `stat /etc/passwd`, `file /etc/passwd`, `printenv HOME` |
| `proc_scan` | lee `/proc` y tablas del sistema | `ps aux`, `df -h`, `free -m`, `ss -tulpn`, `lsblk`, `vmstat 1 1` |

**Toda cifra de indistinguibilidad debe salir de `--suite paired`.** La ejecución de referencia fue `--suite paired --scenario recon --repeat 3` (54 muestras, 27 por ruta).

**Dos defectos conocidos de esta suite, a corregir antes de la ejecución definitiva:**

1. **El equilibrio previsto no se cumple.** La suite está escrita para dar 3 comandos por ruta en cada bloque, pero el reparto real del orquestador no coincide con esa intención: `wc -l /etc/passwd` cae a la ruta generativa y `ss -tulpn` a la determinista. El resultado medido es `builtin` 9/9, `read_small` 3/12 y `proc_scan` 12/6 muestras. **Solo `builtin` sostiene un contraste con potencia.** El arreglo es reasignar esos dos comandos a su bloque real, o sustituirlos por otros cuyo reparto se haya comprobado con `/session/command` antes de medir.
2. **La ejecución versionada se midió con un clasificador ya corregido.** `classify()` etiquetaba `uname -r` como clase `heavy` al confundir el flag `-r` con recursión; el arreglo y el CSV entraron en el mismo commit. Por eso `heavy` aparece en `RESULTS.md` con una sola ruta. Al volver a medir, esas tres muestras pasan a `read_small` y la estratificación cambia.

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

# 3. Suites offline de coherencia (H3, H5) -- no necesitan Docker
python tests/test_core.py           # 81/81
python tests/test_evaluation.py     # 56/56

# 4. Cobertura y fidelidad (H2): la matriz de 30 + 10 comandos
python benchmarks/latency_benchmark.py --suite both --scenario both --repeat 5

# 5. Indistinguibilidad temporal (H1b): la unica suite valida para esto
python benchmarks/latency_benchmark.py --suite paired --scenario recon --repeat 5

# 6. Credibilidad del contenido (H6): ver docs/05
python evaluation/run_deception_eval.py --sessions 8
```

Los pasos 4 y 5 escriben en el mismo `--outdir` y **el segundo sobrescribe al primero**. Usa `--outdir` distintos si necesitas conservar los dos, que es lo habitual: el 4 alimenta el apartado de fidelidad y el 5 el de indistinguibilidad.

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

* **Un solo modelo medido de extremo a extremo.** Toda la evaluación usa `qwen2.5-coder:0.5b`. El `3b` está documentado y justificado (README §4) pero **no medido**: no hay una ejecución del banco con él. La comparación entre los dos, y entre niveles de cuantización, queda como trabajo futuro y es la primera medida que haría falta para sostener el capítulo 4 en su forma completa.
* **Sin adversario humano.** El banco ejecuta una secuencia fija. No mide si un operador de *red team* con experiencia identificaría el entorno; eso requiere un estudio con sujetos, fuera del alcance.
* **La fidelidad se mide por subcadenas.** Una salida puede contener los tokens esperados y aun así resultar poco creíble en conjunto. La aserción es una cota inferior de fidelidad, no una medida de realismo. Para la ruta determinista, que genera esas salidas desde plantillas, un 100 % es casi tautológico. La credibilidad se mide en `docs/05`, no aquí.
* **La normalización no cierra el canal en todas las clases.** En la ejecución de referencia la clase `proc_scan` sigue siendo **perfectamente separable** (AUC = 1,0, p = 0,000156): la salida generativa de esa clase desborda su objetivo y el relleno no puede recuperarlo. Se declara en el README §8 y es un problema de ajuste abierto, no un resultado cerrado.
* **El canal lateral externo sigue abierto.** La normalización iguala las dos rutas *internas*, pero el señuelo responde dos órdenes de magnitud más lento que un `sshd` real (`benchmarks/results/COMPARISON.md`). Un adversario con un servidor legítimo de la misma organización como término de comparación lo separa por tiempo. Es la limitación más seria del trabajo.
* **La comparativa con Cowrie ya está medida; Dionaea no.** El apartado 4.4 tiene tres brazos medidos con el mismo instrumento —marco generativo, Cowrie y host Debian real— en `benchmarks/cowrie_comparison.py`. Dionaea queda fuera: es un honeypot de baja interacción multi-protocolo y no ofrece una shell SSH que interrogar con la misma batería, de modo que incluirlo sería comparar instrumentos distintos.
