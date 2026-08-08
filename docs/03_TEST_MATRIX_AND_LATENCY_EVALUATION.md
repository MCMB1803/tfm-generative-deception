# 03. Matriz de Pruebas y Evaluación de Latencia

## 1. Metodología de Evaluación
Para validar la viabilidad operativa del sistema de ciberengaño generativo en un entorno de producción, la solución debe cumplir con dos parámetros fundamentales:

1. **Fidelidad y Coherencia:** Las salidas de comando emuladas deben ser sintácticamente correctas y coherentes con un servidor Ubuntu 22.04 LTS real.
2. **Rendimiento y Latencia (Target < 1000 ms):** El tiempo entre el envío de un comando por parte del atacante y la recepción de la salida no debe superar 1 segundo para evitar delatar la naturaleza artificial del entorno.

---

## 2. Matriz de Comandos de Prueba

| ID | Comando Inyectado | Categoría de Reconocimiento | Salida Esperada | Estado | Latencia Promedio |
|---|---|---|---|---|---|
| **TC-01** | `whoami` | Identificación de Usuario | `root` | PASSED | ~0.35 s |
| **TC-02** | `uname -a` | Reconocimiento de Kernel | `Linux ubuntu-srv 5.15.0-101-generic x86_64` | PASSED | ~0.42 s |
| **TC-03** | `id` | Verificación de Privilegios | `uid=0(root) gid=0(root) groups=0(root)` | PASSED | ~0.38 s |
| **TC-04** | `ls -la /var/www/html` | Exploración Web/Archivos | Listado detallado de `index.html`, permisos | PASSED | ~0.51 s |
| **TC-05** | `cat /etc/passwd` | Extracción de Cuentas | Lista de usuarios (`root`, `daemon`, `www-data`) | PASSED | ~0.65 s |
| **TC-06** | `ip a` | Enumeración de Red | Interfaz `eth0` con IP de subred interna | PASSED | ~0.58 s |
| **TC-07** | `ps aux` | Listado de Procesos | Procesos del sistema (`systemd`, `sshd`, `nginx`) | PASSED | ~0.72 s |
| **TC-08** | `history` | Análisis de Artefactos | Comandos históricos simulados | PASSED | ~0.48 s |

---

## 3. Registro y Análisis de Tiempos de Respuesta

Las mediciones fueron capturadas en un entorno de pruebas con CPU x86_64 (4 núcleos) y 16 GB de RAM ejecutando Docker en WSL2:

* **Latencia Mínima:** 0.320 segundos (`whoami`).
* **Latencia Máxima:** 0.780 segundos (`ps aux`).
* **Latencia Promedio Global:** **0.512 segundos**.

### Conclusión de Rendimiento
El modelo `qwen2.5-coder:3b` cuantizado mantiene holgadamente los tiempos de respuesta por debajo del límite crítico de **1.000 ms**. Esto garantiza que la interacción del atacante sea fluida e indistinguible de una sesión SSH legítima.