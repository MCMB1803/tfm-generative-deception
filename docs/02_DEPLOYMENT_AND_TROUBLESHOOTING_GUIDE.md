# 02. Guía de Despliegue, Configuración y Troubleshooting

## 1. Requisitos

### Hardware

| Recurso | Mínimo | Recomendado | Nota |
|---|---|---|---|
| CPU | 4 núcleos x86_64 / ARM64 | 8 núcleos | La latencia de la ruta generativa depende directamente de la CPU. |
| RAM | 8 GB | 16 GB | Medido: el contenedor de Ollama sostiene **4.474,9 MiB** residentes con `keep_alive`, y la pila completa **4.545,8 MiB** (ver `benchmarks/results/RESOURCES.md`). |
| Disco | 10 GB | 20 GB SSD | Imagen de Ollama + modelo (~400 MB el `0.5b`, ~2 GB el `3b`) + volúmenes. |
| GPU | — | Opcional | No requerida. Con GPU la latencia generativa baja de forma sustancial; **documéntalo si la usas**, porque invalida la comparación con una ejecución en CPU. |

### Software

* Docker Engine 20.10+ y Docker Compose v2 (sintaxis `docker compose`, sin guion).
* Git.
* Python 3.10+ en el host, solo para ejecutar el banco de pruebas y la suite offline.
* En Windows: WSL2 con Ubuntu 22.04 LTS.

---

## 2. Despliegue

### Paso 1 — Clonar y configurar

```bash
git clone https://github.com/MCMB1803/tfm-generative-deception.git
cd tfm-generative-deception
cp .env.example .env
```

Edita `.env` si quieres cambiar el modelo, el objetivo de latencia o los puertos. Los valores por defecto funcionan sin tocar nada.

> **`.env` está en `.gitignore` y debe seguir estándolo.** Nunca guardes tokens ni credenciales reales en él.

### Paso 2 — Levantar la pila

```bash
docker compose up -d --build
```

Un único comando levanta todo. El orden de arranque está resuelto por `depends_on` con condiciones de salud:

```text
ollama-llm  --(healthy)-->  model-puller  --(completed)-->  deception-agent  --(healthy)-->  ssh-decoy
```

`model-puller` descarga `qwen2.5-coder:0.5b` automáticamente y termina. **La primera ejecución tarda unos minutos** mientras se descargan ~400 MB de modelo; las siguientes son inmediatas porque el volumen `ollama_data` persiste.

> **Sobre el modelo por defecto.** El `0.5b` no es una elección de comodidad: es lo que permite que la ruta generativa quepa en la misma banda temporal que la determinista y, con ello, que la normalización de latencia se sostenga. El `3b` produce salidas notablemente mejores pero genera a ~45 ms/token en CPU, lo que deja la ruta generativa en ~2 s e impide la indistinguibilidad. El razonamiento completo y las cifras están en el README §4.

### Paso 3 — Verificar

```bash
# Progreso de la descarga del modelo
docker compose logs -f model-puller

# Estado del orquestador: persona generada, artefactos, honeytokens
curl -s http://127.0.0.1:8000/stats | python -m json.tool

# Identidad completa que ha asumido el señuelo
curl -s http://127.0.0.1:8000/persona | python -m json.tool
```

`"ready": true` en `/stats` indica que los cuatro agentes han arrancado.

### Paso 4 — Probar el señuelo

```bash
ssh root@localhost -p 2222
# Contraseña: cualquiera. Se acepta todo y se registra.
```

Dentro de la sesión, prueba la coherencia, no solo un comando suelto:

```bash
whoami
cat /etc/passwd          # anota los usuarios
ls -la /home             # deben ser los mismos usuarios
cd /tmp && touch prueba.sh && ls -la    # el fichero debe seguir ahí
cat /etc/passwd          # debe ser byte a byte idéntico a la primera vez
exit
```

---

## 3. Observación de la Telemetría

```bash
# Eventos SOC en vivo
docker compose logs -f deception-agent | grep EVENT

# Fichero JSON Lines completo
docker compose exec deception-agent cat /app/data/logs/deception-events.jsonl

# Solo las latencias
docker compose exec deception-agent cat /app/data/logs/latency.jsonl

# Credenciales capturadas
docker compose logs ssh-decoy | grep "ALERTA SOC"
```

Tipos de evento emitidos: `session.opened`, `auth.attempt`, `command.executed`, `session.closed`, `system.ready`, `system.latency_breach`, `system.inference_degraded`, `artifacts.built`.

---

## 4. Evaluación

```bash
# Suites offline: no necesitan Docker ni Ollama
python tests/test_core.py           # 81/81  nucleo del orquestador
python tests/test_evaluation.py     # 56/56  arnes de evaluacion ciega
pytest tests/test_comparison.py -q  # 19     scoring de la comparativa (requiere pytest)

# Banco de latencia y fidelidad (la pila debe estar levantada)
pip install requests
python benchmarks/latency_benchmark.py --suite paired --scenario recon --repeat 5
```

Resultados en `benchmarks/results/`: `latency_samples.csv` (muestras crudas), `latency_summary.json` (agregados) y `RESULTS.md` (tablas listas para el capítulo 4).

Usa `--suite paired` y no `--suite both` para cualquier cifra de indistinguibilidad: es la única batería cuyos comandos alcanzan las dos rutas dentro de una misma clase de coste, que es lo que el contraste estratificado necesita.

Los otros tres instrumentos, cada uno con su perfil de compose:

```bash
docker compose --profile siem    up -d              && python siem/validate_rules.py
docker compose --profile eval    up -d real-host    && python evaluation/run_deception_eval.py --sessions 8
docker compose --profile compare up -d cowrie       && python benchmarks/cowrie_comparison.py --repeat 2
```

---

## 5. Operaciones Habituales

| Acción | Comando |
|---|---|
| Regenerar la persona | `docker compose exec deception-agent rm /app/data/persona.json && docker compose restart deception-agent` |
| Cambiar de modelo | Editar `MODEL_NAME` en `.env` y `docker compose up -d --force-recreate` |
| Reiniciar solo el señuelo | `docker compose restart ssh-decoy` |
| Parar todo conservando datos | `docker compose down` |
| Borrar todo, modelo incluido | `docker compose down -v` |
| Ver modelos descargados | `docker compose exec ollama-llm ollama list` |

---

## 6. Troubleshooting

### `failed to dial gRPC: unable to upgrade to h2c, received 400`
Desalineación entre BuildKit y el socket de Docker Desktop en Windows/WSL.
```bash
export DOCKER_BUILDKIT=0          # PowerShell: $env:DOCKER_BUILDKIT=0
docker compose up -d --build
```

### `deception-agent` se queda en `starting`
El bootstrap espera a Ollama. Es normal durante la primera descarga.
```bash
docker compose logs model-puller     # ¿terminó la descarga?
docker compose logs deception-agent  # ¿qué está esperando?
```
Si el modelo no llegó a descargarse, fuerza la descarga a mano:
```bash
docker compose exec ollama-llm ollama pull qwen2.5-coder:0.5b
docker compose restart deception-agent
```

### La persona sale con nombres genéricos (`srv-web-prod-02`, «Distribuciones Arganzuela»)
Es el **perfil de reserva**: significa que el LLM no estaba disponible o devolvió un JSON inválido cuando se generó la persona. Confírmalo:
```bash
curl -s http://127.0.0.1:8000/stats | grep -i source   # "fallback" vs "llm"
```
Solución: asegúrate de que el modelo está descargado, borra `persona.json` y reinicia el agente.

### Latencias muy por encima de 1.000 ms en la ruta generativa
Por orden de impacto:
1. **El modelo se descargó de RAM.** `OLLAMA_KEEP_ALIVE=30m` lo evita; verifica que la variable llegó al contenedor.
2. **Contexto demasiado largo.** Baja `SESSION_CONTEXT_TURNS` de 6 a 3 en `.env`.
3. **Salida demasiado larga.** Baja `MAX_TOKENS` de 64 a 48. Es la palanca más directa: la clase `proc_scan` es la que desborda su objetivo en la ejecución de referencia, y lo hace por longitud de salida.
4. **CPU insuficiente.** Es el límite duro. Documenta el hardware en la memoria en lugar de ocultar el resultado.

### El cliente SSH avisa de cambio de clave de host
Solo debería ocurrir si se borró el volumen `decoy_data`. La clave se persiste precisamente para evitarlo.
```bash
ssh-keygen -R "[localhost]:2222"
```

### `Permission denied` al escribir la clave de host
El volumen `decoy_data` no se montó. Comprueba `docker compose config` y que la sección `volumes` del servicio esté presente.

### `Could not resolve host: github.com` en WSL2
```bash
sudo bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
```

### `remote: Invalid username or token` al hacer push
Genera un *Personal Access Token* con permiso `repo` y configura el remoto. **No incrustes el token en la URL del remoto ni lo guardes en `.env`**: usa el gestor de credenciales de Git.
```bash
git config --global credential.helper store   # o 'manager' en Windows
git push    # pedirá usuario y token una sola vez
```

---

## 7. Seguridad Operativa del Despliegue

1. **Nunca despliegues esto en un segmento de producción sin aislamiento de red.** El señuelo acepta todas las credenciales por diseño.
2. **El volumen `agent_data` contiene credenciales en claro** capturadas del atacante. Trátalo con el control de acceso de una fuente de telemetría del SOC.
3. **No publiques los puertos 8000 ni 11434** más allá de loopback. La configuración por defecto ya los restringe a `127.0.0.1`.
4. **Los honeytokens deben registrarse en el SIEM.** Su valor está en detectar su uso *fuera* del señuelo. Obtén la lista con `curl -s http://127.0.0.1:8000/stats`.
5. Para un despliegue real, sitúa el señuelo en una VLAN sin rutas hacia sistemas productivos.
