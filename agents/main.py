import time
import requests

OLLAMA_URL = "http://ollama-llm:11434/api/generate"
MODEL_NAME = "qwen2.5-coder:3b"

def test_llm_latency(cmd_prompt):
    payload = {
        "model": MODEL_NAME,
        "prompt": f"System: You are an SSH Linux terminal on Ubuntu 22.04. Output only raw stdout for the command.\nUser: {cmd_prompt}\nAssistant:",
        "stream": False
    }
    start = time.time()
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=10)
        elapsed = time.time() - start
        if response.status_code == 200:
            output = response.json().get('response', '').strip()
            print(f"[+] Comando: '{cmd_prompt}' | Latencia: {elapsed:.3f}s\nSalida:\n{output}\n{'-'*40}")
        else:
            print(f"[-] Error en Ollama: {response.status_code}")
    except Exception as e:
        print(f"[-] Error de conexión: {e}")

if __name__ == "__main__":
    print("[*] Esperando inicialización del servicio...")
    time.sleep(3)
    test_llm_latency("whoami")
    test_llm_latency("ls -la /var/www/html")