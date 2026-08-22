# Resultados medidos de latencia y fidelidad

Generado automaticamente por `benchmarks/latency_benchmark.py` el 2026-08-22T15:41:31+00:00. **No editar a mano**: se regenera en cada ejecucion.

Objetivo de latencia: **1000 ms**. Muestras totales: **40**.

## 1. Resumen global

| Ruta | n | Media | Mediana | Desv. tip. | Min | Max | p95 | p99 | Dentro de objetivo | Fidelidad |
|---|---|---|---|---|---|---|---|---|---|---|
| **Global** | 40 | 512.9 ms | 2.2 ms | 895.5 ms | 1.3 ms | 2058.1 ms | 2048.8 ms | 2054.6 ms | 75.0 % | 100.0 % |
| Determinista | 30 | 2.4 ms | 1.5 ms | 1.6 ms | 1.3 ms | 6.2 ms | 5.6 ms | 6.1 ms | 100.0 % | 100.0 % |
| Generativa | 10 | 2044.4 ms | 2045.4 ms | 7.3 ms | 2031.1 ms | 2058.1 ms | 2054.0 ms | 2057.3 ms | 0.0 % | 100.0 % |

Reparto de rutas: **75.0 %** determinista, **25.0 %** generativa.

## 2. Detalle por comando

| Comando | Tecnica ATT&CK | Ruta | n | Media | p95 | Dentro de objetivo | Fidelidad |
|---|---|---|---|---|---|---|---|
| `whoami` | T1033 | deterministic | 1 | 6.2 ms | 6.2 ms | 100.0 % | 100.0 % |
| `id` | T1033 | deterministic | 1 | 6.0 ms | 6.0 ms | 100.0 % | 100.0 % |
| `hostname` | T1082 | deterministic | 1 | 4.6 ms | 4.6 ms | 100.0 % | 100.0 % |
| `uname -a` | T1082 | deterministic | 1 | 5.2 ms | 5.2 ms | 100.0 % | 100.0 % |
| `cat /etc/os-release` | T1082 | deterministic | 1 | 5.0 ms | 5.0 ms | 100.0 % | 100.0 % |
| `pwd` | T1083 | deterministic | 1 | 4.8 ms | 4.8 ms | 100.0 % | 100.0 % |
| `ls -la` | T1083 | deterministic | 1 | 3.8 ms | 3.8 ms | 100.0 % | 100.0 % |
| `ls -la /var/www` | T1083 | deterministic | 1 | 2.9 ms | 2.9 ms | 100.0 % | 100.0 % |
| `cat /etc/passwd` | T1087.001 | deterministic | 1 | 2.4 ms | 2.4 ms | 100.0 % | 100.0 % |
| `cat /etc/shadow` | T1087.001 | deterministic | 1 | 2.0 ms | 2.0 ms | 100.0 % | 100.0 % |
| `cat /etc/group` | T1087.001 | deterministic | 1 | 1.6 ms | 1.6 ms | 100.0 % | 100.0 % |
| `ps aux` | T1057 | deterministic | 1 | 2.4 ms | 2.4 ms | 100.0 % | 100.0 % |
| `ip a` | T1016 | deterministic | 1 | 1.5 ms | 1.5 ms | 100.0 % | 100.0 % |
| `netstat -tulpn` | T1016 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `cat /etc/hosts` | T1016 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `df -h` | T1082 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `free -h` | T1082 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `history` | T1552.001 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `cat /root/.bash_history` | T1552.001 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `ls -la /root/.ssh` | T1552.004 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `cat /root/.ssh/id_rsa` | T1552.004 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `cat /root/.my.cnf` | T1552.001 | deterministic | 1 | 1.5 ms | 1.5 ms | 100.0 % | 100.0 % |
| `crontab -l` | T1053.003 | deterministic | 1 | 1.3 ms | 1.3 ms | 100.0 % | 100.0 % |
| `cat /etc/crontab` | T1053.003 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `tail -20 /var/log/auth.log` | T1005 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `cat /etc/passwd | grep bash` | T1087.001 | deterministic | 1 | 1.4 ms | 1.4 ms | 100.0 % | 100.0 % |
| `sudo -l` | T1548.003 | deterministic | 1 | 1.6 ms | 1.6 ms | 100.0 % | 100.0 % |
| `which nmap` | T1046 | deterministic | 1 | 1.5 ms | 1.5 ms | 100.0 % | 100.0 % |
| `uptime` | T1082 | deterministic | 1 | 1.8 ms | 1.8 ms | 100.0 % | 100.0 % |
| `lscpu` | T1082 | deterministic | 1 | 1.9 ms | 1.9 ms | 100.0 % | 100.0 % |
| `systemctl status nginx` | T1057 | generative | 1 | 2058.1 ms | 2058.1 ms | 0.0 % | 100.0 % |
| `journalctl -u nginx -n 10` | T1005 | generative | 1 | 2048.8 ms | 2048.8 ms | 0.0 % | 100.0 % |
| `dpkg -l` | T1082 | generative | 1 | 2046.7 ms | 2046.7 ms | 0.0 % | 100.0 % |
| `top -bn1` | T1057 | generative | 1 | 2041.3 ms | 2041.3 ms | 0.0 % | 100.0 % |
| `iptables -L -n` | T1016 | generative | 1 | 2049.0 ms | 2049.0 ms | 0.0 % | 100.0 % |
| `find /var/www -name '*.php'` | T1083 | generative | 1 | 2037.4 ms | 2037.4 ms | 0.0 % | 100.0 % |
| `du -sh /var/log` | T1083 | generative | 1 | 2041.1 ms | 2041.1 ms | 0.0 % | 100.0 % |
| `stat /etc/passwd` | T1083 | generative | 1 | 2046.3 ms | 2046.3 ms | 0.0 % | 100.0 % |
| `curl -I http://127.0.0.1` | T1105 | generative | 1 | 2044.5 ms | 2044.5 ms | 0.0 % | 100.0 % |
| `apt list --installed` | T1082 | generative | 1 | 2031.1 ms | 2031.1 ms | 0.0 % | 100.0 % |

## 3. Fallos de fidelidad observados

Ninguno: todas las salidas contienen los tokens esperados.
