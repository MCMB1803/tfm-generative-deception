"""Artifact Agent -- dynamic injection of synthetic artefacts.

This is the component the TFM lists as its third specific objective: neutralise
fingerprinting by populating the decoy with the traces a *used* server has and
an empty honeypot does not -- shell history, business files, credentials in
config files, and log files that keep growing while nobody is watching.

Three responsibilities:

1. A virtual filesystem (paths, owners, modes, sizes, contents) rendered once
   from the persona, so `ls` and `cat` agree with each other and with
   /etc/passwd.
2. Honeytokens: fabricated credentials embedded in plausible places. They
   authenticate nothing, so any use of one anywhere in the estate is a true
   positive by construction -- the zero-false-positive claim in section 1.2.
3. A background traffic simulator that appends entries to nginx and auth logs
   on a timer, so `tail -f /var/log/nginx/access.log` shows a live server
   rather than a file frozen at deployment time.
"""
from __future__ import annotations

import logging
import random
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from core import config
from core.llm import OllamaClient
from core.telemetry import emit_event
from roles.persona import Persona

log = logging.getLogger("agent.artifacts")

_HISTORY_PROMPT = """Write the .bash_history of {who} on a Linux server.
Server role: {role}
Application: {app} deployed at {web_root}. Stack: nginx, python3, mysql.

Output ONLY the command lines, one per line, no numbering, no comments,
no markdown, no explanation. {count} lines. They must look like real
day-to-day sysadmin work on this specific server: checking services,
tailing logs, editing configs, database maintenance, deployments.
Do not include any command that reveals this is a simulation."""


@dataclass
class FSNode:
    """One entry in the virtual filesystem."""

    path: str
    kind: str = "file"  # "file" | "dir" | "link"
    owner: str = "root"
    group: str = "root"
    mode: str = "-rw-r--r--"
    size: int = 0
    mtime: str = "Dec 17 09:41"
    content: str | None = None
    target: str | None = None  # for symlinks
    honeytoken_id: str | None = None

    @property
    def name(self) -> str:
        return self.path.rstrip("/").rsplit("/", 1)[-1] or "/"


class VirtualFilesystem:
    """Path-indexed store of synthetic filesystem nodes."""

    def __init__(self) -> None:
        self.nodes: dict[str, FSNode] = {}

    def add(self, node: FSNode) -> FSNode:
        self.nodes[node.path.rstrip("/") or "/"] = node
        return node

    def get(self, path: str) -> FSNode | None:
        return self.nodes.get(path.rstrip("/") or "/")

    def exists(self, path: str) -> bool:
        return (path.rstrip("/") or "/") in self.nodes

    def children(self, path: str) -> list[FSNode]:
        parent = path.rstrip("/") or "/"
        prefix = "/" if parent == "/" else parent + "/"
        out = []
        for p, node in self.nodes.items():
            if p == parent or not p.startswith(prefix):
                continue
            if "/" in p[len(prefix):]:
                continue  # not a direct child
            out.append(node)
        return sorted(out, key=lambda n: n.name)

    def listing(self, path: str, long: bool = True, all_files: bool = False,
                extra_names: set[str] | None = None) -> str:
        """Render `ls` / `ls -la` output for a directory."""
        entries = self.children(path)
        if not all_files:
            entries = [e for e in entries if not e.name.startswith(".")]

        synthetic = []
        for name in sorted(extra_names or set()):
            if any(e.name == name for e in entries):
                continue
            if not all_files and name.startswith("."):
                continue
            synthetic.append(FSNode(path=f"{path.rstrip('/')}/{name}", size=0,
                                    mtime=datetime.now().strftime("%b %d %H:%M")))
        entries = sorted(entries + synthetic, key=lambda n: n.name)

        if not long:
            return "  ".join(e.name for e in entries)

        rows = []
        total = 0
        if all_files:
            rows.append(("drwxr-xr-x", 2, "root", "root", 4096, "Dec 17 09:41", "."))
            rows.append(("drwxr-xr-x", 22, "root", "root", 4096, "Nov 04 03:12", ".."))
        for e in entries:
            links = 2 if e.kind == "dir" else 1
            rows.append((e.mode, links, e.owner, e.group, e.size, e.mtime, e.name))
            total += max(4, (e.size + 1023) // 1024)

        out = [f"total {total}"]
        for mode, links, owner, group, size, mtime, name in rows:
            out.append(f"{mode} {links:>2} {owner:<8} {group:<8} {size:>7} {mtime} {name}")
        return "\n".join(out)


class ArtifactAgent:
    """Builds the artefact layer and keeps the log files alive."""

    def __init__(self, llm: OllamaClient, persona: Persona) -> None:
        self.llm = llm
        self.persona = persona
        self.fs = VirtualFilesystem()
        self.honeytokens: dict[str, dict[str, Any]] = {}
        self._rng = random.Random(config.PERSONA_SEED)
        self._traffic_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._access_log: list[str] = []
        self._auth_log: list[str] = []
        self._log_lock = threading.Lock()

    # -- build -------------------------------------------------------------
    def build(self) -> VirtualFilesystem:
        """Populate the virtual filesystem. Called once at start-up."""
        self._build_skeleton()
        self._build_home_dirs()
        self._build_webroot()
        self._build_configs_with_honeytokens()
        self._seed_logs()
        self._build_histories()
        log.info(
            "Artefactos construidos: %d nodos, %d honeytokens",
            len(self.fs.nodes), len(self.honeytokens),
        )
        emit_event(
            "artifacts.built",
            nodes=len(self.fs.nodes),
            honeytoken_count=len(self.honeytokens),
            persona=self.persona.hostname,
        )
        return self.fs

    def _dir(self, path: str, owner: str = "root", group: str = "root",
             mode: str = "drwxr-xr-x", mtime: str = "Nov 04 03:12") -> FSNode:
        return self.fs.add(FSNode(path=path, kind="dir", owner=owner, group=group,
                                  mode=mode, size=4096, mtime=mtime))

    def _file(self, path: str, content: str, owner: str = "root", group: str = "root",
              mode: str = "-rw-r--r--", mtime: str = "Dec 17 09:41",
              honeytoken_id: str | None = None) -> FSNode:
        return self.fs.add(FSNode(path=path, kind="file", owner=owner, group=group,
                                  mode=mode, size=len(content.encode()), mtime=mtime,
                                  content=content, honeytoken_id=honeytoken_id))

    def _build_skeleton(self) -> None:
        p = self.persona
        for d in ("/", "/root", "/home", "/etc", "/var", "/var/www", "/var/log",
                  "/var/log/nginx", "/opt", "/tmp", "/srv", "/usr", "/usr/local",
                  "/etc/nginx", "/etc/nginx/sites-available", "/etc/ssh", "/etc/mysql",
                  "/opt/backup", "/opt/scripts"):
            self._dir(d)
        self._dir("/root", mode="drwx------")
        self._dir("/tmp", mode="drwxrwxrwt", mtime="Dec 17 10:02")

        # /proc entries a recon script reads directly rather than via a tool.
        self._dir("/proc")
        self._file("/proc/version",
                   f"Linux version {p.kernel} (buildd@lcy02-amd64-045) "
                   "(x86_64-linux-gnu-gcc-11 (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, "
                   "GNU ld (GNU Binutils for Ubuntu) 2.38) #111-Ubuntu SMP "
                   "Tue Mar 5 20:16:58 UTC 2024\n")
        self._file("/proc/cpuinfo", "\n".join(
            f"processor\t: {i}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n"
            f"model\t\t: 85\nmodel name\t: {p.cpu_model}\ncpu MHz\t\t: 2400.000\n"
            f"cache size\t: 14080 KB\ncores\t\t: {p.cpu_cores // 2}\n"
            for i in range(p.cpu_cores)))

        self._file("/etc/passwd", p.etc_passwd())
        self._file("/etc/shadow", p.etc_shadow(), group="shadow", mode="-rw-r-----")
        self._file("/etc/group", p.etc_group())
        self._file("/etc/os-release", p.os_release())
        self._file("/etc/hostname", p.hostname + "\n")
        self._file(
            "/etc/hosts",
            "127.0.0.1\tlocalhost\n"
            f"127.0.1.1\t{p.hostname}.{p.domain} {p.hostname}\n"
            f"{p.gateway}\tgw-core.{p.domain}\n"
            f"10.42.18.10\tdc01.{p.domain}\n"
            f"10.42.18.11\tsrv-db-prod-01.{p.domain}\n"
            f"10.42.20.15\tsrv-backup-01.{p.domain}\n"
            "\n::1\tip6-localhost ip6-loopback\n",
        )
        self._file("/etc/resolv.conf",
                   f"nameserver 10.42.18.10\nnameserver 10.42.18.11\nsearch {p.domain}\n")
        self._file("/etc/crontab",
                   "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
                   "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
                   "30 2\t* * *\troot\t/opt/scripts/backup_db.sh >> /var/log/backup.log 2>&1\n"
                   "*/10 *\t* * *\tdeploy\t/opt/scripts/healthcheck.sh\n")

    def _build_home_dirs(self) -> None:
        p = self.persona
        for u in p.users:
            home = f"/home/{u['name']}"
            self._dir(home, owner=u["name"], group=u["name"], mode="drwxr-xr-x")
            self._dir(f"{home}/.ssh", owner=u["name"], group=u["name"], mode="drwx------")
            self._file(f"{home}/.bashrc", "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
                                          "export HISTSIZE=2000\nexport HISTFILESIZE=5000\n"
                                          "alias ll='ls -alF'\nalias la='ls -A'\n",
                       owner=u["name"], group=u["name"])
            self._file(f"{home}/.profile", "# ~/.profile\nmesg n 2> /dev/null || true\n",
                       owner=u["name"], group=u["name"])
        self._dir("/root/.ssh", mode="drwx------")

    def _build_webroot(self) -> None:
        p = self.persona
        root = p.web_root.rstrip("/")
        self._dir(root, owner="www-data", group="www-data")
        for sub in ("static", "templates", "media", "logs"):
            self._dir(f"{root}/{sub}", owner="www-data", group="www-data")
        self._file(f"{root}/index.html",
                   f"<!doctype html>\n<html lang=\"es\">\n<head>\n"
                   f"  <meta charset=\"utf-8\">\n  <title>{p.company} - {p.app_name}</title>\n"
                   f"</head>\n<body>\n  <h1>Portal interno de {p.company}</h1>\n"
                   f"  <p>Acceso restringido al personal autorizado.</p>\n</body>\n</html>\n",
                   owner="www-data", group="www-data")
        self._file(f"{root}/robots.txt", "User-agent: *\nDisallow: /admin\nDisallow: /api\n",
                   owner="www-data", group="www-data")
        self._dir(f"/opt/{p.app_name}", owner="deploy", group="deploy")
        self._file(f"/opt/{p.app_name}/manage.py",
                   "#!/usr/bin/env python3\nimport os, sys\n\n"
                   "if __name__ == '__main__':\n"
                   f"    os.environ.setdefault('DJANGO_SETTINGS_MODULE', '{p.app_name}.settings')\n"
                   "    from django.core.management import execute_from_command_line\n"
                   "    execute_from_command_line(sys.argv)\n",
                   owner="deploy", group="deploy", mode="-rwxr-xr-x")

    def _honeytoken(self, kind: str, value: str, location: str) -> str:
        """Register a fabricated credential and return its tracking id."""
        token_id = f"HT-{uuid.uuid4().hex[:8].upper()}"
        self.honeytokens[value] = {
            "honeytoken_id": token_id,
            "kind": kind,
            "value": value,
            "location": location,
        }
        return token_id

    def _build_configs_with_honeytokens(self) -> None:
        p = self.persona
        rng = self._rng
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

        db_pass = "".join(rng.choice(alphabet) for _ in range(18))
        api_key = "sk_live_" + "".join(rng.choice(alphabet) for _ in range(32))
        smtp_pass = "".join(rng.choice(alphabet) for _ in range(14))

        env_path = f"/opt/{p.app_name}/.env"
        ht_db = self._honeytoken("db_password", db_pass, env_path)
        ht_api = self._honeytoken("api_key", api_key, env_path)
        ht_smtp = self._honeytoken("smtp_password", smtp_pass, env_path)

        self._file(
            env_path,
            f"# {p.company} - {p.app_name} production settings\n"
            "DEBUG=False\n"
            f"ALLOWED_HOSTS={p.hostname}.{p.domain},{p.ip_addr}\n"
            f"DATABASE_URL=mysql://{p.app_name}_rw:{db_pass}@10.42.18.11:3306/{p.app_name}_prod\n"
            f"SECRET_KEY={''.join(rng.choice(alphabet) for _ in range(50))}\n"
            f"BILLING_API_KEY={api_key}\n"
            f"SMTP_HOST=smtp.{p.domain}\nSMTP_USER=noreply@{p.domain}\n"
            f"SMTP_PASSWORD={smtp_pass}\n",
            owner="deploy", group="deploy", mode="-rw-------",
            honeytoken_id=f"{ht_db},{ht_api},{ht_smtp}",
        )

        my_pass = "".join(rng.choice(alphabet) for _ in range(16))
        ht_my = self._honeytoken("mysql_root_password", my_pass, "/root/.my.cnf")
        self._file("/root/.my.cnf",
                   f"[client]\nuser=root\npassword={my_pass}\nhost=10.42.18.11\n",
                   mode="-rw-------", honeytoken_id=ht_my)

        key_body = "\n".join(
            "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                    for _ in range(64))
            for _ in range(24)
        )
        priv_key = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{key_body}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        # Register a substring that actually occurs in the file. Registering a
        # label instead would mean the token never matches when the attacker
        # reads the key, which is the exact moment worth alerting on.
        ht_key = self._honeytoken("ssh_private_key", key_body[:48], "/root/.ssh/id_rsa")
        self._file("/root/.ssh/id_rsa", priv_key, mode="-rw-------", honeytoken_id=ht_key)
        self._file("/root/.ssh/id_rsa.pub",
                   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7f2kJ"
                   + "".join(rng.choice(alphabet) for _ in range(180))
                   + f" root@{p.hostname}\n")
        self._file("/root/.ssh/authorized_keys",
                   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"
                   + "".join(rng.choice(alphabet) for _ in range(43))
                   + f" {p.users[0]['name']}@admin-workstation\n", mode="-rw-------")
        self._file("/root/.ssh/known_hosts",
                   f"10.42.18.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"
                   + "".join(rng.choice(alphabet) for _ in range(43)) + "\n"
                   f"srv-backup-01.{p.domain} ssh-rsa AAAAB3NzaC1yc2EAAAAD"
                   + "".join(rng.choice(alphabet) for _ in range(60)) + "\n")

        self._file("/etc/nginx/sites-available/default",
                   "server {\n    listen 80 default_server;\n"
                   f"    server_name {p.hostname}.{p.domain};\n"
                   f"    root {p.web_root};\n    index index.html;\n\n"
                   "    location /api/ {\n        proxy_pass http://127.0.0.1:8000;\n"
                   "        proxy_set_header X-Real-IP $remote_addr;\n    }\n}\n")

        self._file("/opt/scripts/backup_db.sh",
                   "#!/bin/bash\n# Volcado nocturno a srv-backup-01\nset -euo pipefail\n"
                   f"STAMP=$(date +%Y%m%d)\nmysqldump --defaults-file=/root/.my.cnf "
                   f"{p.app_name}_prod | gzip > /opt/backup/{p.app_name}_$STAMP.sql.gz\n"
                   f"rsync -az /opt/backup/ backup@srv-backup-01.{p.domain}:/srv/dumps/{p.hostname}/\n"
                   "find /opt/backup -name '*.sql.gz' -mtime +14 -delete\n",
                   mode="-rwxr-xr-x")
        self._file("/opt/scripts/healthcheck.sh",
                   "#!/bin/bash\ncurl -sf http://127.0.0.1:8000/health || "
                   "systemctl restart " + p.app_name + "\n",
                   owner="deploy", group="deploy", mode="-rwxr-xr-x")

        for days_ago in (1, 2, 5, 9):
            stamp = (datetime.now() - timedelta(days=days_ago)).strftime("%Y%m%d")
            self.fs.add(FSNode(
                path=f"/opt/backup/{p.app_name}_{stamp}.sql.gz",
                owner="root", group="root", mode="-rw-r-----",
                size=rng.randint(180_000_000, 340_000_000),
                mtime=(datetime.now() - timedelta(days=days_ago)).strftime("%b %d 02:31"),
                content=None,  # binary: cat must not render it as text
            ))

    def _seed_logs(self) -> None:
        """Pre-fill log files with history, then let the traffic thread extend them."""
        p = self.persona
        now = datetime.now()
        for i in range(120):
            self._access_log.append(self._fake_access_line(now - timedelta(seconds=(120 - i) * 37)))
        for i in range(25):
            self._auth_log.append(self._fake_auth_line(now - timedelta(minutes=(25 - i) * 11)))

        self._file("/var/log/nginx/access.log", "", owner="www-data", group="adm")
        self._file("/var/log/nginx/error.log",
                   f"2025/12/17 04:12:08 [error] 889#889: *20481 open() \"{p.web_root}/favicon.ico\" "
                   "failed (2: No such file or directory), client: 10.42.18.201, server: "
                   f"{p.hostname}.{p.domain}, request: \"GET /favicon.ico HTTP/1.1\"\n",
                   owner="www-data", group="adm")
        self._file("/var/log/auth.log", "", group="adm")
        self._file("/var/log/syslog", "", group="adm")
        self._file("/var/log/backup.log",
                   "\n".join(
                       f"[{(datetime.now() - timedelta(days=d)).strftime('%Y-%m-%d')} 02:30:04] "
                       f"Volcado completado: {p.app_name}_prod "
                       f"({self._rng.randint(180, 340)} MB) -> srv-backup-01"
                       for d in range(7, 0, -1)
                   ) + "\n")

    def _fake_access_line(self, when: datetime) -> str:
        rng = self._rng
        ips = ["10.42.18.201", "10.42.18.214", "10.42.19.42", "10.42.18.77", "10.42.20.15"]
        paths = ["/", "/api/pedidos", "/api/clientes", "/static/app.css", "/static/app.js",
                 "/api/health", "/login", "/api/informes?mes=12", "/media/logo.png"]
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
            "python-requests/2.31.0",
        ]
        status = rng.choices([200, 200, 200, 204, 302, 304, 404, 500], k=1)[0]
        return (
            f'{rng.choice(ips)} - - [{when.strftime("%d/%b/%Y:%H:%M:%S +0100")}] '
            f'"GET {rng.choice(paths)} HTTP/1.1" {status} {rng.randint(180, 24000)} '
            f'"-" "{rng.choice(agents)}"'
        )

    def _fake_auth_line(self, when: datetime) -> str:
        rng = self._rng
        p = self.persona
        user = rng.choice([u["name"] for u in p.users])
        templates = [
            f"sshd[{rng.randint(20000, 29999)}]: Accepted publickey for {user} from 10.42.18.201 "
            f"port {rng.randint(40000, 60000)} ssh2: RSA SHA256:"
            + "".join(rng.choice("abcdefABCDEF0123456789") for _ in range(20)),
            f"CRON[{rng.randint(30000, 39999)}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            f"sudo:  {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
            f"systemd-logind[701]: New session {rng.randint(400, 900)} of user {user}.",
        ]
        return f'{when.strftime("%b %d %H:%M:%S")} {p.hostname} {rng.choice(templates)}'

    def _build_histories(self) -> None:
        """LLM-authored shell history -- the highest-value anti-fingerprint artefact.

        An empty .bash_history is the single most reliable honeypot tell, so this
        is worth one inference call per account at start-up."""
        p = self.persona
        targets = [("root", "/root/.bash_history", "root", 45)]
        for u in p.users[:2]:
            targets.append((u["name"], f"/home/{u['name']}/.bash_history", u["name"], 30))

        for who, path, owner, count in targets:
            lines = self._generate_history(who, count)
            self._file(path, "\n".join(lines) + "\n", owner=owner, group=owner,
                       mode="-rw-------", mtime="Dec 17 09:58")

    def _generate_history(self, who: str, count: int) -> list[str]:
        p = self.persona
        prompt = _HISTORY_PROMPT.format(
            who=f"the {who} account", role=p.role, app=p.app_name,
            web_root=p.web_root, count=count,
        )
        response = self.llm.chat([{"role": "user", "content": prompt}],
                                 max_tokens=700, temperature=0.7)
        if response.ok and response.text:
            lines = [
                re.sub(r"^\s*(?:\d+\s+|[-*]\s+|`)", "", ln).strip().strip("`")
                for ln in response.text.splitlines()
            ]
            lines = [ln for ln in lines if ln and not ln.startswith("#") and len(ln) < 160]
            if len(lines) >= 8:
                log.info("Historial de %s generado por LLM (%d lineas, %.0f ms)",
                         who, len(lines), response.latency_ms)
                return lines[:count]
        log.warning("Historial de %s: se usa plantilla de reserva", who)
        return self._fallback_history(who, count)

    def _fallback_history(self, who: str, count: int) -> list[str]:
        p = self.persona
        pool = [
            "cd /opt/" + p.app_name, "git pull origin main", "systemctl status nginx",
            "systemctl restart " + p.app_name, "tail -f /var/log/nginx/error.log",
            "df -h", "free -m", "htop", "journalctl -u nginx --since '1 hour ago'",
            f"mysql -u root -p {p.app_name}_prod", "vim /etc/nginx/sites-available/default",
            "nginx -t", "systemctl reload nginx", "./manage.py migrate",
            "./manage.py collectstatic --noinput", "sudo apt update",
            "sudo apt upgrade -y", "docker ps", "crontab -l",
            f"ls -la {p.web_root}", "curl -I http://127.0.0.1:8000/health",
            "grep -c ' 500 ' /var/log/nginx/access.log", "who", "uptime",
            "sudo systemctl status mysql", "/opt/scripts/backup_db.sh",
            "rsync -az /opt/backup/ backup@srv-backup-01:/srv/dumps/",
            "netstat -tulpn | grep LISTEN", "ss -tan state established",
            "chown -R www-data:www-data " + p.web_root, "history | tail -20",
        ]
        rng = random.Random(config.PERSONA_SEED + len(who))
        return [rng.choice(pool) for _ in range(count)]

    # -- log accessors -----------------------------------------------------
    def access_log(self, lines: int | None = None) -> str:
        with self._log_lock:
            data = self._access_log[-lines:] if lines else self._access_log
            return "\n".join(data)

    def auth_log(self, lines: int | None = None) -> str:
        with self._log_lock:
            data = self._auth_log[-lines:] if lines else self._auth_log
            return "\n".join(data)

    def match_honeytoken(self, text: str) -> list[dict[str, Any]]:
        """Detect a honeytoken echoed back in attacker input."""
        return [meta for value, meta in self.honeytokens.items() if value and value in text]

    # -- traffic simulation ------------------------------------------------
    def start_traffic(self, interval: float = 8.0) -> None:
        """Append log entries on a timer so the server looks alive.

        Answers the 'inexistencia de tráfico de red legítimo' fingerprint listed
        in section 1.1: an attacker who tails the access log during a long
        session sees new requests arriving, not a dead file."""
        if self._traffic_thread and self._traffic_thread.is_alive():
            return

        def loop() -> None:
            while not self._stop.wait(interval):
                now = datetime.now()
                with self._log_lock:
                    for _ in range(self._rng.randint(1, 4)):
                        self._access_log.append(self._fake_access_line(now))
                    if self._rng.random() < 0.15:
                        self._auth_log.append(self._fake_auth_line(now))
                    # Bound memory: this runs for the lifetime of the container.
                    if len(self._access_log) > 5000:
                        del self._access_log[:1000]
                    if len(self._auth_log) > 2000:
                        del self._auth_log[:500]

        self._stop.clear()
        self._traffic_thread = threading.Thread(target=loop, daemon=True,
                                                name="traffic-simulator")
        self._traffic_thread.start()
        log.info("Simulador de trafico iniciado (intervalo %.1fs)", interval)

    def stop_traffic(self) -> None:
        self._stop.set()
