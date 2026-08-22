"""SSH decoy -- protocol frontend.

Deliberately thin. This process speaks SSH (paramiko) and nothing else: it
terminates the transport, emulates a PTY, and forwards every command to the
orchestrator API. No persona, no artefacts, no LLM calls, no ATT&CK mapping
live here, which is what lets the same orchestrator serve a future HTTP or FTP
decoy unchanged.

Two properties this file is responsible for:
  * the host key is persistent -- regenerating it every boot changes the
    server's SSH fingerprint, which is itself a honeypot tell;
  * line editing behaves like a real terminal (backspace, Ctrl+C, Ctrl+D,
    Ctrl+L, history), because a shell that ignores backspace is detected in
    one typo.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time

import paramiko
import requests

LOG_FORMAT = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=LOG_FORMAT,
                    datefmt="%H:%M:%S")
logging.getLogger("paramiko").setLevel(logging.WARNING)
log = logging.getLogger("ssh-decoy")

AGENT_API = os.getenv("AGENT_API", "http://deception-agent:8000").rstrip("/")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "22"))
HOST_KEY_PATH = os.getenv("HOST_KEY_PATH", "/app/data/ssh_host_rsa_key")
API_TIMEOUT = float(os.getenv("API_TIMEOUT", "30"))
MAX_SESSIONS = int(os.getenv("MAX_SESSIONS", "50"))

# Advertised version string. Must match a real Ubuntu 22.04 OpenSSH build:
# banner mismatch is the cheapest honeypot detection there is.
SSH_BANNER = os.getenv("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

_session_semaphore = threading.BoundedSemaphore(MAX_SESSIONS)


# -- host key ----------------------------------------------------------------
def load_host_key() -> paramiko.RSAKey:
    """Load the persistent host key, generating it once on first boot."""
    if os.path.exists(HOST_KEY_PATH):
        try:
            key = paramiko.RSAKey(filename=HOST_KEY_PATH)
            log.info("Clave de host cargada (fingerprint estable)")
            return key
        except (paramiko.SSHException, OSError) as exc:
            log.warning("Clave de host ilegible (%s); se regenera", exc)

    log.info("Generando clave de host RSA-2048 (solo la primera vez)...")
    key = paramiko.RSAKey.generate(2048)
    try:
        os.makedirs(os.path.dirname(HOST_KEY_PATH), exist_ok=True)
        key.write_private_key_file(HOST_KEY_PATH)
        os.chmod(HOST_KEY_PATH, 0o600)
    except OSError as exc:
        log.warning("No se pudo persistir la clave de host: %s "
                    "(el fingerprint cambiara al reiniciar)", exc)
    return key


# -- orchestrator client -----------------------------------------------------
class AgentClient:
    """HTTP client against the deception-agent orchestrator."""

    def __init__(self, base: str = AGENT_API) -> None:
        self.base = base
        self.http = requests.Session()

    def wait_ready(self, attempts: int = 120, delay: float = 5.0) -> bool:
        for i in range(attempts):
            try:
                r = self.http.get(f"{self.base}/health", timeout=5)
                if r.status_code == 200 and r.json().get("ready"):
                    log.info("Orquestador listo")
                    return True
                log.info("Orquestador arrancando (intento %d/%d)...", i + 1, attempts)
            except requests.RequestException:
                log.info("Orquestador inalcanzable (intento %d/%d)...", i + 1, attempts)
            time.sleep(delay)
        return False

    def open(self, src_ip: str, src_port: int) -> dict | None:
        return self._post("/session/open", {"src_ip": src_ip, "src_port": src_port})

    def auth(self, session_id: str, username: str, password: str, method: str = "password") -> None:
        self._post("/session/auth", {"session_id": session_id, "username": username,
                                     "password": password, "method": method})

    def command(self, session_id: str, command: str) -> dict | None:
        return self._post("/session/command", {"session_id": session_id, "command": command})

    def close(self, session_id: str, reason: str = "client_disconnect") -> None:
        self._post("/session/close", {"session_id": session_id, "reason": reason})

    def _post(self, path: str, payload: dict) -> dict | None:
        try:
            r = self.http.post(f"{self.base}{path}", json=payload, timeout=API_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            log.warning("El orquestador devolvio %s en %s", r.status_code, path)
        except requests.RequestException as exc:
            log.warning("Fallo llamando al orquestador %s: %s", path, exc)
        return None


agent = AgentClient()


# -- paramiko server interface ----------------------------------------------
class DecoyServer(paramiko.ServerInterface):
    """Accepts every credential and records it via the orchestrator."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.event = threading.Event()

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        log.warning("[ALERTA SOC] Credenciales capturadas - usuario='%s' clave='%s'",
                    username, password)
        agent.auth(self.session_id, username, password, "password")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        # Reject once so the client falls back to password and reveals it,
        # which is the higher-value artefact for the SOC.
        fingerprint = key.get_fingerprint().hex()
        log.warning("[ALERTA SOC] Clave publica ofrecida - usuario='%s' fp=%s",
                    username, fingerprint)
        agent.auth(self.session_id, username, f"publickey:{fingerprint}", "publickey")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        """Non-interactive `ssh host 'cmd'`. Common in automated attacks."""
        self.exec_command = command.decode("utf-8", errors="ignore")
        self.event.set()
        return True


# -- interactive shell -------------------------------------------------------
class ShellSession:
    """Line editor and command loop over one paramiko channel."""

    def __init__(self, chan: paramiko.Channel, session_id: str, prompt: str) -> None:
        self.chan = chan
        self.session_id = session_id
        self.prompt = prompt
        self.buffer = ""
        self.history: list[str] = []
        self.history_pos = 0

    def send(self, text: str) -> None:
        self.chan.send(text.replace("\n", "\r\n"))

    def run(self) -> str:
        self.send(self.prompt)
        while True:
            try:
                data = self.chan.recv(4096)
            except (socket.timeout, OSError):
                return "client_disconnect"
            if not data:
                return "client_disconnect"

            for char in data.decode("utf-8", errors="ignore"):
                action = self._handle_char(char)
                if action:
                    return action

    def _handle_char(self, char: str) -> str | None:
        if char in ("\r", "\n"):
            self.chan.send("\r\n")
            command = self.buffer.strip()
            self.buffer = ""
            if command:
                self.history.append(command)
                self.history_pos = len(self.history)
            if command in ("exit", "logout", "quit"):
                self.send("logout\n")
                return "user_exit"
            if command:
                self._dispatch(command)
            self.chan.send(self.prompt)
            return None

        if char in ("\x7f", "\x08"):  # backspace / delete
            if self.buffer:
                self.buffer = self.buffer[:-1]
                self.chan.send("\b \b")
            return None

        if char == "\x03":  # Ctrl+C
            self.chan.send("^C\r\n")
            self.buffer = ""
            self.chan.send(self.prompt)
            return None

        if char == "\x04":  # Ctrl+D
            if not self.buffer:
                self.send("logout\n")
                return "user_eof"
            return None

        if char == "\x0c":  # Ctrl+L
            self.chan.send("\x1b[H\x1b[2J")
            self.chan.send(self.prompt + self.buffer)
            return None

        if char == "\t":  # tab completion is not emulated; a real bash beeps
            self.chan.send("\a")
            return None

        if char == "\x1b":  # start of an escape sequence (arrow keys)
            return None
        if char in ("[", "A", "B", "C", "D") and not self.buffer.endswith(char):
            # Arrow-key tails arrive as separate bytes; swallowing them is
            # better than printing "^[[A" the way a broken honeypot does.
            pass

        if char.isprintable():
            self.buffer += char
            self.chan.send(char)
        return None

    def _dispatch(self, command: str) -> None:
        result = agent.command(self.session_id, command)
        if result is None:
            # Orchestrator unreachable. Fail into a shell-shaped error rather
            # than hanging or printing a stack trace.
            self.send(f"bash: {command.split()[0]}: command not found\n")
            return

        output = result.get("output", "")
        if output:
            self.send(output.rstrip("\n") + "\n")
        self.prompt = result.get("prompt", self.prompt)


# -- connection handling -----------------------------------------------------
def handle_connection(client: socket.socket, addr: tuple[str, int],
                      host_key: paramiko.RSAKey) -> None:
    src_ip, src_port = addr[0], addr[1]
    log.info("Conexion entrante desde %s:%s", src_ip, src_port)

    opened = agent.open(src_ip, src_port)
    if opened is None:
        log.error("No se pudo abrir sesion en el orquestador; se cierra la conexion")
        client.close()
        return

    session_id = opened["session_id"]
    transport = None
    reason = "client_disconnect"

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)
        server = DecoyServer(session_id)
        transport.start_server(server=server)

        chan = transport.accept(30)
        if chan is None:
            reason = "no_channel"
            return

        server.event.wait(10)
        chan.settimeout(600)

        exec_command = getattr(server, "exec_command", None)
        if exec_command:
            # Non-interactive invocation: run it, return, close.
            result = agent.command(session_id, exec_command)
            if result and result.get("output"):
                chan.send(result["output"].replace("\n", "\r\n") + "\r\n")
            chan.send_exit_status(0)
            reason = "exec_request"
            return

        chan.send(opened.get("banner", "").replace("\n", "\r\n") + "\r\n")
        shell = ShellSession(chan, session_id, opened.get("prompt", "# "))
        reason = shell.run()

    except (paramiko.SSHException, OSError, EOFError) as exc:
        log.info("Sesion %s terminada: %s", session_id[:8], exc)
        reason = "protocol_error"
    finally:
        agent.close(session_id, reason)
        if transport is not None:
            try:
                transport.close()
            except Exception:  # noqa: BLE001 - teardown must never raise
                pass
        try:
            client.close()
        except OSError:
            pass
        _session_semaphore.release()
        log.info("Sesion %s cerrada (%s)", session_id[:8], reason)


def start_server() -> None:
    if not agent.wait_ready():
        log.error("El orquestador nunca estuvo listo; abortando")
        raise SystemExit(1)

    host_key = load_host_key()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    sock.listen(100)
    log.info("Senuelo SSH escuchando en 0.0.0.0:%d (banner: %s)", LISTEN_PORT, SSH_BANNER)

    while True:
        try:
            client, addr = sock.accept()
        except OSError as exc:
            log.error("accept() fallo: %s", exc)
            continue

        if not _session_semaphore.acquire(blocking=False):
            # Connection flooding is a plausible attack against the decoy
            # itself; shed load instead of exhausting the container.
            log.warning("Limite de sesiones alcanzado; se rechaza %s", addr[0])
            client.close()
            continue

        threading.Thread(target=handle_connection, args=(client, addr, host_key),
                         daemon=True).start()


if __name__ == "__main__":
    start_server()
