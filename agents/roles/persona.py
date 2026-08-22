"""Persona Agent -- builds and freezes the identity of the decoy host.

Runs once at framework start-up. The LLM invents the *narrative* layer (which
company, which users, which application), and this module renders that
narrative into the concrete system artefacts a reconnaissance command touches:
/etc/passwd, the kernel string, the network config, the process table.

The split matters. Asking the LLM for /etc/passwd on every `cat` gives a
different file each time, which is exactly the incoherence an attacker
fingerprints. Generating the narrative once and rendering deterministically
gives a host that stays the same host for the whole engagement -- and costs
zero inference time per command.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from core import config
from core.llm import OllamaClient

log = logging.getLogger("agent.persona")

_NARRATIVE_PROMPT = """You invent realistic fictional metadata for a corporate Linux server.
Answer with ONE JSON object and nothing else. No markdown, no code fences, no commentary.

Schema:
{
  "company": "short fictional Spanish company name",
  "domain": "company internal domain, e.g. corp.example.local",
  "hostname": "linux hostname, lowercase, with a dash, e.g. srv-web-prod-02",
  "role": "one line describing what this server does",
  "app_name": "name of the business application hosted here, lowercase, one word",
  "users": [
    {"name": "unix username", "full_name": "person full name", "uid": 1000, "role": "their job"}
  ],
  "service_accounts": ["three service account usernames, lowercase"],
  "web_root": "absolute path to the web application directory"
}

Rules: exactly 4 entries in "users" with uid 1000, 1001, 1002, 1003. Spanish names.
The company must sound like a mid-size firm, not a tech giant."""


@dataclass
class Persona:
    """The frozen identity of the decoy host."""

    company: str
    domain: str
    hostname: str
    role: str
    app_name: str
    web_root: str
    users: list[dict[str, Any]]
    service_accounts: list[str]

    # Rendered system facts
    distro: str = "Ubuntu 22.04.4 LTS"
    kernel: str = "5.15.0-101-generic"
    arch: str = "x86_64"
    ip_addr: str = "10.42.18.37"
    netmask: int = 24
    gateway: str = "10.42.18.1"
    mac: str = "02:42:0a:2a:12:25"
    generated_by: str = "llm"
    seed: int = config.PERSONA_SEED

    boot_time: str = "2025-11-04 03:12:07"
    memory_gb: int = 16
    cpu_model: str = "Intel(R) Xeon(R) Silver 4210R CPU @ 2.40GHz"
    cpu_cores: int = 8

    extra: dict[str, Any] = field(default_factory=dict)

    # -- rendered artefacts -------------------------------------------------
    def etc_passwd(self) -> str:
        lines = [
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "sync:x:4:65534:sync:/bin:/bin/sync",
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
            "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin",
            "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin",
            "syslog:x:102:109::/home/syslog:/usr/sbin/nologin",
            "sshd:x:103:65534::/run/sshd:/usr/sbin/nologin",
            "mysql:x:104:110:MySQL Server,,,:/nonexistent:/bin/false",
        ]
        for u in self.users:
            lines.append(
                "{name}:x:{uid}:{uid}:{full},,,:/home/{name}:/bin/bash".format(
                    name=u["name"], uid=u["uid"], full=u.get("full_name", "")
                )
            )
        base_uid = 990
        for i, svc in enumerate(self.service_accounts):
            uid = base_uid - i
            lines.append(f"{svc}:x:{uid}:{uid}::/var/lib/{svc}:/usr/sbin/nologin")
        return "\n".join(lines)

    def etc_shadow(self) -> str:
        """Readable only as root. The hashes are structurally valid SHA-512
        crypt strings but correspond to no password: they are honeytokens.
        Any offline cracking attempt or reuse elsewhere is, by construction,
        a true positive."""
        rng = random.Random(self.seed)
        alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

        def fake_hash() -> str:
            salt = "".join(rng.choice(alphabet) for _ in range(16))
            digest = "".join(rng.choice(alphabet) for _ in range(43))
            return f"$6${salt}${digest}"

        lines = [f"root:{fake_hash()}:19845:0:99999:7:::"]
        for locked in (
            "daemon", "bin", "sys", "sync", "man", "www-data", "nobody",
            "systemd-network", "systemd-resolve", "syslog", "sshd", "mysql",
        ):
            lines.append(f"{locked}:*:19845:0:99999:7:::")
        for u in self.users:
            lines.append(f"{u['name']}:{fake_hash()}:19912:0:99999:7:::")
        for svc in self.service_accounts:
            lines.append(f"{svc}:!:19845:0:99999:7:::")
        return "\n".join(lines)

    def etc_group(self) -> str:
        admins = ",".join(u["name"] for u in self.users[:2])
        lines = [
            "root:x:0:",
            "adm:x:4:syslog",
            f"sudo:x:27:{admins}",
            "www-data:x:33:",
            "ssh:x:114:",
            "mysql:x:110:",
        ]
        for u in self.users:
            lines.append(f"{u['name']}:x:{u['uid']}:")
        return "\n".join(lines)

    def uname_a(self) -> str:
        return (
            f"Linux {self.hostname} {self.kernel} #111-Ubuntu SMP "
            f"Tue Mar 5 20:16:58 UTC 2024 {self.arch} {self.arch} {self.arch} GNU/Linux"
        )

    def os_release(self) -> str:
        return "\n".join([
            'PRETTY_NAME="Ubuntu 22.04.4 LTS"',
            'NAME="Ubuntu"',
            'VERSION_ID="22.04"',
            'VERSION="22.04.4 LTS (Jammy Jellyfish)"',
            "VERSION_CODENAME=jammy",
            "ID=ubuntu",
            "ID_LIKE=debian",
            'HOME_URL="https://www.ubuntu.com/"',
            'SUPPORT_URL="https://help.ubuntu.com/"',
            'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"',
            "UBUNTU_CODENAME=jammy",
        ])

    def ip_a(self) -> str:
        return "\n".join([
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000",
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00",
            "    inet 127.0.0.1/8 scope host lo",
            "       valid_lft forever preferred_lft forever",
            "    inet6 ::1/128 scope host",
            "       valid_lft forever preferred_lft forever",
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000",
            f"    link/ether {self.mac} brd ff:ff:ff:ff:ff:ff",
            f"    inet {self.ip_addr}/{self.netmask} brd 10.42.18.255 scope global eth0",
            "       valid_lft forever preferred_lft forever",
            "    inet6 fe80::42:aff:fe2a:1225/64 scope link",
            "       valid_lft forever preferred_lft forever",
        ])

    def ifconfig(self) -> str:
        return "\n".join([
            f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500",
            f"        inet {self.ip_addr}  netmask 255.255.255.0  broadcast 10.42.18.255",
            "        inet6 fe80::42:aff:fe2a:1225  prefixlen 64  scopeid 0x20<link>",
            f"        ether {self.mac}  txqueuelen 1000  (Ethernet)",
            "        RX packets 8412907  bytes 6142883091 (6.1 GB)",
            "        RX errors 0  dropped 0  overruns 0  frame 0",
            "        TX packets 7218334  bytes 3980215522 (3.9 GB)",
            "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0",
            "",
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536",
            "        inet 127.0.0.1  netmask 255.0.0.0",
            "        inet6 ::1  prefixlen 128  scopeid 0x10<host>",
            "        loop  txqueuelen 1000  (Local Loopback)",
            "        RX packets 194832  bytes 21403118 (21.4 MB)",
            "        RX errors 0  dropped 0  overruns 0  frame 0",
            "        TX packets 194832  bytes 21403118 (21.4 MB)",
            "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0",
        ])

    def netstat(self) -> str:
        return "\n".join([
            "Active Internet connections (only servers)",
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name",
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      654/sshd: /usr/sbin",
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      889/nginx: master p",
            "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      889/nginx: master p",
            "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      1104/mysqld",
            "tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      891/python3",
            f"tcp        0     36 {self.ip_addr}:22        10.42.18.201:51244      ESTABLISHED 20481/sshd: root@pt",
        ])

    def ps_aux(self) -> str:
        rows = [
            ("root", 1, 0.0, 0.1, 168404, 11912, "?", "Ss", "Nov04", "0:24", "/sbin/init"),
            ("root", 2, 0.0, 0.0, 0, 0, "?", "S", "Nov04", "0:00", "[kthreadd]"),
            ("root", 412, 0.0, 0.2, 47120, 17300, "?", "Ss", "Nov04", "0:11",
             "/lib/systemd/systemd-journald"),
            ("root", 654, 0.0, 0.1, 15420, 8104, "?", "Ss", "Nov04", "0:02", "/usr/sbin/sshd -D"),
            ("syslog", 701, 0.0, 0.1, 224376, 5216, "?", "Ssl", "Nov04", "0:08",
             "/usr/sbin/rsyslogd -n -iNONE"),
            ("root", 889, 0.0, 0.3, 1238404, 28840, "?", "Ssl", "Nov04", "1:47",
             "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"),
            ("www-data", 891, 0.1, 0.9, 1401228, 74120, "?", "Sl", "Nov04", "8:12",
             f"/usr/bin/python3 /opt/{self.app_name}/manage.py runserver 127.0.0.1:8000"),
            ("www-data", 892, 0.1, 0.8, 1398112, 71004, "?", "Sl", "Nov04", "7:55",
             f"/usr/bin/python3 /opt/{self.app_name}/worker.py"),
            ("mysql", 1104, 0.4, 4.2, 2418836, 341220, "?", "Ssl", "Nov04", "22:31", "/usr/sbin/mysqld"),
            ("root", 1402, 0.0, 0.1, 12180, 6104, "?", "Ss", "Nov04", "0:01", "/usr/sbin/cron -f"),
            ("root", 20481, 0.0, 0.1, 17284, 10240, "?", "Ss", "10:02", "0:00", "sshd: root@pts/0"),
            ("root", 20493, 0.0, 0.0, 8420, 5108, "pts/0", "Ss", "10:02", "0:00", "-bash"),
            ("root", 20618, 0.0, 0.0, 10072, 3204, "pts/0", "R+", "10:14", "0:00", "ps aux"),
        ]
        out = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        for user, pid, cpu, mem, vsz, rss, tty, stat, start, cputime, cmd in rows:
            out.append(
                f"{user:<10} {pid:>5} {cpu:>4.1f} {mem:>4.1f} {vsz:>6} {rss:>5} "
                f"{tty:<8} {stat:<4} {start:>5} {cputime:>6} {cmd}"
            )
        return "\n".join(out)

    def df_h(self) -> str:
        return "\n".join([
            "Filesystem      Size  Used Avail Use% Mounted on",
            "tmpfs           1.6G  1.7M  1.6G   1% /run",
            "/dev/sda2        97G   60G   33G  65% /",
            "tmpfs           7.9G     0  7.9G   0% /dev/shm",
            "tmpfs           5.0M     0  5.0M   0% /run/lock",
            "/dev/sda1       511M  6.1M  505M   2% /boot/efi",
            "/dev/sdb1       197G   84G  104G  45% /var/lib/mysql",
            "tmpfs           1.6G   16K  1.6G   1% /run/user/1000",
        ])

    def free_h(self) -> str:
        return "\n".join([
            "               total        used        free      shared  buff/cache   available",
            "Mem:            15Gi       5.4Gi       1.2Gi       412Mi       8.9Gi       9.4Gi",
            "Swap:          4.0Gi          0B       4.0Gi",
        ])

    def motd(self) -> str:
        return "\n".join([
            f"Welcome to {self.distro} (GNU/Linux {self.kernel} {self.arch})",
            "",
            " * Documentation:  https://help.ubuntu.com",
            " * Management:     https://landscape.canonical.com",
            " * Support:        https://ubuntu.com/advantage",
            "",
            "  System information as of Wed Dec 17 10:02:41 CET 2025",
            "",
            "  System load:  0.08               Processes:             184",
            "  Usage of /:   65.4% of 96.72GB   Users logged in:       0",
            f"  Memory usage: 34%                IPv4 address for eth0: {self.ip_addr}",
            "  Swap usage:   0%",
            "",
            "17 updates can be applied immediately.",
            "8 of these updates are standard security updates.",
            "",
            "Last login: Wed Dec 17 09:41:22 2025 from 10.42.18.201",
        ])

    def context_block(self) -> str:
        """Compact system description injected into the Terminal Agent prompt.

        Deliberately short: every token here is paid on every generative
        command, and prompt evaluation is a measurable share of the latency
        budget (see docs/03)."""
        users = ", ".join(f"{u['name']}({u['uid']})" for u in self.users)
        return (
            f"Host: {self.hostname}.{self.domain} running {self.distro}, "
            f"kernel {self.kernel} {self.arch}.\n"
            f"Purpose: {self.role}\n"
            f"Human users: {users}. Service accounts: {', '.join(self.service_accounts)}.\n"
            f"Web app '{self.app_name}' deployed at {self.web_root}, served by nginx, "
            f"backed by MySQL on localhost:3306. eth0 = {self.ip_addr}/{self.netmask}, "
            f"gateway {self.gateway}. Uptime 47 days."
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# -- fallback profile --------------------------------------------------------
# Used when Ollama is unreachable or returns unusable JSON. The decoy must
# never fail open into an obviously-fake state just because inference is down.
_FALLBACK: dict[str, Any] = {
    "company": "Distribuciones Arganzuela S.L.",
    "domain": "arganzuela.local",
    "hostname": "srv-web-prod-02",
    "role": "Servidor de aplicacion del portal interno de pedidos",
    "app_name": "portalpedidos",
    "web_root": "/var/www/portalpedidos",
    "users": [
        {"name": "acastro", "full_name": "Alberto Castro", "uid": 1000, "role": "Administrador de sistemas"},
        {"name": "mvazquez", "full_name": "Marta Vazquez", "uid": 1001, "role": "Responsable de infraestructura"},
        {"name": "lserrano", "full_name": "Lucia Serrano", "uid": 1002, "role": "Desarrolladora backend"},
        {"name": "pnavarro", "full_name": "Pablo Navarro", "uid": 1003, "role": "Analista de datos"},
    ],
    "service_accounts": ["deploy", "backup", "monitoring"],
}


def _extract_json(text: str) -> dict[str, Any] | None:
    """Small instruct models wrap JSON in prose or fences despite instructions,
    so scan for the first balanced object rather than trusting the whole reply."""
    cleaned = re.sub(r"```(?:json)?", "", text).strip()
    start = cleaned.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(cleaned)):
        if cleaned[i] == "{":
            depth += 1
        elif cleaned[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(cleaned[start : i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _validate(data: dict[str, Any]) -> bool:
    required = {"company", "domain", "hostname", "app_name", "users", "service_accounts"}
    if not required.issubset(data):
        return False
    users = data.get("users")
    if not isinstance(users, list) or len(users) < 2:
        return False
    return all(isinstance(u, dict) and "name" in u for u in users)


class PersonaAgent:
    """Generates the host identity once, then serves it from cache."""

    def __init__(self, llm: OllamaClient, cache_path: str | None = None) -> None:
        self.llm = llm
        self.cache_path = cache_path or config.PERSONA_CACHE

    def load_or_generate(self, force: bool = False) -> Persona:
        if not force:
            cached = self._load_cache()
            if cached is not None:
                log.info("Persona cargada de cache: %s (%s)", cached.hostname, cached.company)
                return cached

        narrative, source = self._generate_narrative()
        persona = self._render(narrative, source)
        self._save_cache(persona)
        log.info("Persona generada (%s): %s @ %s", source, persona.hostname, persona.company)
        return persona

    # -- internals ---------------------------------------------------------
    def _generate_narrative(self) -> tuple[dict[str, Any], str]:
        response = self.llm.chat(
            [{"role": "user", "content": _NARRATIVE_PROMPT}],
            max_tokens=600,
            temperature=0.85,  # variety matters here, and this runs exactly once
        )
        if response.ok and response.text:
            data = _extract_json(response.text)
            if data and _validate(data):
                log.info("Narrativa de persona generada por el LLM en %.0f ms", response.latency_ms)
                return data, "llm"
            log.warning("El LLM devolvio una persona no valida; se usa el perfil de reserva")
        else:
            log.warning("Generacion de persona fallida (%s); se usa el perfil de reserva",
                        response.error)
        return dict(_FALLBACK), "fallback"

    def _render(self, data: dict[str, Any], source: str) -> Persona:
        rng = random.Random(config.PERSONA_SEED)

        users: list[dict[str, Any]] = []
        for i, raw in enumerate(data.get("users", [])[:6]):
            name = re.sub(r"[^a-z0-9_-]", "", str(raw.get("name", "")).lower())[:12]
            if not name:
                continue
            users.append({
                "name": name,
                "full_name": str(raw.get("full_name", name))[:40],
                "uid": 1000 + len(users),
                "role": str(raw.get("role", ""))[:60],
            })
        if len(users) < 2:
            users = [dict(u) for u in _FALLBACK["users"]]

        svc = [re.sub(r"[^a-z0-9_-]", "", str(s).lower())[:12] for s in data.get("service_accounts", [])[:4]]
        svc = [s for s in svc if s] or list(_FALLBACK["service_accounts"])

        app = re.sub(r"[^a-z0-9_-]", "", str(data.get("app_name", "")).lower())[:20] or "portalapp"
        hostname = re.sub(r"[^a-z0-9.-]", "", str(data.get("hostname", "")).lower())[:30] or "srv-app-01"
        octet = rng.randint(20, 240)

        return Persona(
            company=str(data.get("company") or _FALLBACK["company"])[:60],
            domain=str(data.get("domain") or _FALLBACK["domain"])[:40],
            hostname=hostname,
            role=str(data.get("role") or "Servidor de aplicaciones interno")[:120],
            app_name=app,
            web_root=str(data.get("web_root") or f"/var/www/{app}")[:80],
            users=users,
            service_accounts=svc,
            ip_addr=f"10.42.18.{octet}",
            mac=f"02:42:0a:2a:12:{octet:02x}",
            generated_by=source,
        )

    def _load_cache(self) -> Persona | None:
        if not os.path.exists(self.cache_path):
            return None
        try:
            with open(self.cache_path, encoding="utf-8") as fh:
                return Persona(**json.load(fh))
        except (OSError, ValueError, TypeError) as exc:
            log.warning("Cache de persona ilegible (%s); se regenerara", exc)
            return None

    def _save_cache(self, persona: Persona) -> None:
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as fh:
                json.dump(persona.to_dict(), fh, ensure_ascii=False, indent=2)
        except OSError as exc:
            log.warning("No se pudo cachear la persona: %s", exc)
