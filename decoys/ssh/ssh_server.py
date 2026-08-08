import socket
import threading
import paramiko
import requests
import time

OLLAMA_URL = "http://ollama-llm:11434/api/generate"
MODEL_NAME = "qwen2.5-coder:3b"

# Clave RSA para el servidor SSH falso
HOST_KEY = paramiko.RSAKey.generate(2048)

class FakeSSHServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        print(f"[!] [ALERTA SOC] Intento de acceso SSH - Usuario: '{username}' | Clave: '{password}'")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

def query_llm(cmd_prompt):
    payload = {
        "model": MODEL_NAME,
        "prompt": f"System: You are an SSH bash terminal on Ubuntu 22.04 LTS. Output ONLY raw stdout/stderr for the user command. Do not add markdown formatting, explanations, or quotes.\nUser: {cmd_prompt}\nAssistant:",
        "stream": False
    }
    try:
        start = time.time()
        res = requests.post(OLLAMA_URL, json=payload, timeout=5)
        elapsed = time.time() - start
        print(f"[*] Latencia LLM: {elapsed:.3f}s")
        if res.status_code == 200:
            return res.json().get('response', '').strip() + "\r\n"
    except Exception as e:
        print(f"[-] Error llamando a LLM: {e}")
    return "bash: command not found\r\n"

def handle_connection(client_socket):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)
    server = FakeSSHServer()
    
    try:
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan is None:
            return
        
        chan.send("Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)\r\n\r\n")
        chan.send("root@ubuntu-srv:~# ")
        
        buffer = ""
        while True:
            data = chan.recv(1024).decode('utf-8', errors='ignore')
            if not data:
                break
            
            for char in data:
                if char == '\r' or char == '\n':
                    chan.send("\r\n")
                    cmd = buffer.strip()
                    if cmd == "exit":
                        chan.close()
                        return
                    elif cmd:
                        response = query_llm(cmd)
                        chan.send(response)
                    chan.send("root@ubuntu-srv:~# ")
                    buffer = ""
                elif char == '\x07': # Ctrl+C
                    chan.send("\r\nroot@ubuntu-srv:~# ")
                    buffer = ""
                else:
                    buffer += char
                    chan.send(char) # Echo
    except Exception as e:
        print(f"[-] Conexión cerrada: {e}")
    finally:
        transport.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 22))
    server_socket.listen(100)
    print("[*] Trampa SSH (Decoy) escuchando en el puerto 22...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"\n[+] Conexión entrante desde {addr[0]}:{addr[1]}")
        client_thread = threading.Thread(target=handle_connection, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    start_server()