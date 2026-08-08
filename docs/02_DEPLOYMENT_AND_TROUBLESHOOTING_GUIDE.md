# 02. Guía de Despliegue, Configuración y Troubleshooting

## 1. Requisitos del Sistema

### Hardware Recomendado
* **CPU:** 4 núcleos x86_64 / ARM64.
* **RAM:** Mínimo 8 GB (Recomendado 16 GB para ejecución fluida de Ollama en memoria).
* **Almacenamiento:** 10 GB de espacio libre en disco SSD.

### Software Requerido
* **Docker Engine:** Version 20.10+
* **Docker Desktop / Docker Compose:** Version 2.0+ (Sintaxis `docker compose`)
* **Git**
* **WSL2 (Windows Subsystem for Linux):** En entornos Windows 10/11 (Ubuntu 22.04 LTS recomendado).

---

## 2. Paso a Paso para el Despliegue

### Paso 1: Clonar el Repositorio
```bash
git clone https://github.com/MCMB1803/tfm-generative-deception.git
cd tfm-generative-deception
```

### Paso 2: Crear la Estructura de Directorios
Asegúrate de tener la siguiente estructura de carpetas en el proyecto:
```text
tfm-generative-deception/
├── docker-compose.yml
├── .gitignore
├── README.md
├── agents/
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
├── decoys/
│   └── ssh/
│       ├── Dockerfile
│       ├── requirements.txt
│       └── ssh_server.py
└── docs/
    ├── 01_ARQUITECTURA_Y_DISENO.md
    ├── 02_GUIA_DE_DESPLIEGUE.md
    ├── 03_MATRIZ_DE_PRUEBAS_Y_LATENCIA.md
    └── 04_MEMORIA_TFM_ESTRUCTURA.md
```

### Paso 3: Desplegar la Infraestructura con Docker Compose
Abre tu consola de comandos (PowerShell / WSL / Terminal Linux) en la raíz del repositorio y ejecuta:

```bash
docker compose up -d --build
```

### Paso 4: Descargar el Modelo de IA Local
Ejecuta el siguiente comando para descargar el modelo `qwen2.5-coder:3b` dentro del contenedor de Ollama (solo se requiere la primera vez):

```bash
docker exec -it ollama_llm ollama run qwen2.5-coder:3b
```
*Cuando se complete la descarga y aparezca el símbolo `>>>`, escribe `/bye` y pulsa Enter para salir.*

---

## 3. Pruebas de Funcionamiento

### Prueba 1: Conexión SSH a la Trampa
Conéctate desde una terminal secundaria al puerto 2222:
```bash
ssh root@localhost -p 2222
```
* **Contraseña:** Introduce cualquier cadena (ej. `admin123`).
* **Ejecución de Comandos:** Prueba `whoami`, `cat /etc/passwd`, `ls -la /var/www/html`.

### Prueba 2: Inspección de Alertas de Red y Latencia
Abre la consola de logs del honeypot SSH para verificar los registros de auditoría y la velocidad de respuesta:

```bash
docker compose logs -f ssh-decoy
```

---

## 4. Resolución de Problemas Frecuentes (Troubleshooting)

### Error 1: `failed to dial gRPC: unable to upgrade to h2c, received 400`
* **Causa:** Desalineación entre BuildKit y el socket de comunicación de Docker Desktop en Windows / WSL.
* **Solución Rápida:** Desactivar BuildKit en la sesión actual:
  * *PowerShell:* `$env:DOCKER_BUILDKIT=0`
  * *Bash:* `export DOCKER_BUILDKIT=0`
  * Luego ejecutar: `docker compose up -d --build`

### Error 2: `Could not resolve host: github.com` al hacer `git push`
* **Causa:** Pérdida de resolución DNS en la instancia de WSL2.
* **Solución:** Sobrescribir el resolvedor en WSL2:
  ```bash
  sudo bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
  ```

### Error 3: `remote: Invalid username or token` o `403 Forbidden`
* **Causa:** Autenticación por contraseña tradicional rechazada por GitHub.
* **Solución:**
  1. Generar un *Personal Access Token (PAT Classic)* en GitHub con permiso **`repo`** marcado.
  2. Actualizar la URL remota:
     ```bash
     git remote set-url origin https://TU_TOKEN@github.com/MCMB1803/tfm-generative-deception.git
     ```