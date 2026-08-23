# Comparativa con un honeypot tradicional (Cowrie)

Generado: 2026-08-23T22:53:22.673614+00:00

Los tres brazos se interrogan con el mismo cliente SSH, las mismas
credenciales y la misma bateria de treinta comandos, de modo que las
diferencias sean atribuibles al sistema y no al procedimiento.

La latencia es **tiempo hasta el primer byte**, no hasta el silencio:
el cliente compartido espera 1,2 s de quietud antes de dar por cerrada
una respuesta, y medir hasta ahi devuelve ~1.240 ms para todos los
brazos, incluido un Debian pelado. Esa cifra describe el instrumento,
no el sistema.

**La cobertura se lee contra el host real, nunca sola.** Un Debian
genuino no responde al 100 % de la bateria porque la mitad de esas
rutas no existen en el. Un senuelo que responda a todo no gana: exhibe
un indicio que ningun sistema real presenta. La columna que importa es
la divergencia respecto al host real.

| Sistema | Version SSH | Cobertura | Divergencia | Coherencia | Mediana | p95 |
|---|---|---|---|---|---|---|
| marco-generativo | `SSH-2.0-OpenSSH_8.9p1 Ubuntu` | 96.7 % | 8/30 | 96.7 % | 598.0 ms | 666.7 ms |
| cowrie | `SSH-2.0-OpenSSH_9.2p1 Debian` | 63.3 % | 6/30 | 93.3 % | 10.5 ms | 21.2 ms |
| host-real | `SSH-2.0-OpenSSH_9.2p1 Debian` | 70.0 % | — (referencia) | 93.3 % | 4.5 ms | 9.8 ms |

## Coste computacional durante la bateria

| Contenedor | CPU media | CPU max | RAM media | RAM max |
|---|---|---|---|---|
| honeypot_ssh | 0.5 % | 1.1 % | 46.4 MiB | 46.5 MiB |
| compare_cowrie | 1.3 % | 2.9 % | 54.4 MiB | 54.5 MiB |
| eval_real_host | 0.4 % | 0.8 % | 5.4 MiB | 5.5 MiB |

## Detalle por brazo

**marco-generativo** — sin respuesta (1): `which nmap`

**marco-generativo** — incoherentes entre dos lecturas (1): `history`

**marco-generativo** — divergen del host real (8): `ls -la /var/www`, `ls -la /root/.ssh`, `cat /root/.ssh/id_rsa`, `cat /root/.my.cnf`, `crontab -l`, `cat /etc/crontab`, `tail -20 /var/log/auth.log`, `sudo -l`

**cowrie** — sin respuesta (11): `cat /etc/os-release`, `ls -la /var/www`, `ip a`, `df -h`, `cat /root/.bash_history`, `ls -la /root/.ssh`, `cat /root/.ssh/id_rsa`, `cat /root/.my.cnf`, `cat /etc/crontab`, `tail -20 /var/log/auth.log`, `which nmap`

**cowrie** — incoherentes entre dos lecturas (2): `ps aux`, `history`

**cowrie** — divergen del host real (6): `cat /etc/os-release`, `ip a`, `df -h`, `cat /root/.bash_history`, `crontab -l`, `sudo -l`

**host-real** — sin respuesta (9): `ls -la /var/www`, `ls -la /root/.ssh`, `cat /root/.ssh/id_rsa`, `cat /root/.my.cnf`, `crontab -l`, `cat /etc/crontab`, `tail -20 /var/log/auth.log`, `sudo -l`, `which nmap`

**host-real** — incoherentes entre dos lecturas (2): `ps aux`, `history`

