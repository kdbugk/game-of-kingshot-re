"""
run_button_hook.py

Sobe o proxy MITM + hook de botões Unity em paralelo.

O que faz:
  - Thread 1: mitmdump na porta 8081 (captura HTTP/S do jogo)
  - Thread 2: Frida com button_hook.js (captura cliques e validações de botões)
  - Correlaciona eventos Frida com requisições HTTP pelo timestamp

Pré-requisitos:
  - CA do mitmproxy instalado no device (rodar mitm_setup.py após cada reboot)
  - Proxy WiFi configurado: 192.168.0.84:8081
  - frida-server rodando no device: adb forward tcp:37555 tcp:37555

Uso:
  python run_button_hook.py
"""

import frida
import subprocess
import threading
import time
import sys
import os
from pathlib import Path
from datetime import datetime

# ── configuração ──────────────────────────────────────────────────────────────

APP_ID       = "com.run.tower.defense"
FRIDA_HOST   = "127.0.0.1:37555"
JS_SCRIPT    = "button_hook.js"

PROXY_HOST   = "192.168.0.84"
PROXY_PORT   = 8081
MITMDUMP_EXE = r"C:\Users\prs\AppData\Local\Python\pythoncore-3.14-64\Scripts\mitmdump.exe"

ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_BTN   = f"button_events_{ts}.log"
LOG_HTTP  = f"http_traffic_{ts}.log"
LOG_MITM  = f"http_traffic_{ts}.mitm"

# ── logger compartilhado ──────────────────────────────────────────────────────

t_start = time.time()
_log_lock = threading.Lock()

btn_log  = open(LOG_BTN,  "w", encoding="utf-8")
http_log = open(LOG_HTTP, "w", encoding="utf-8")

def elapsed():
    return f"{time.time() - t_start:.6f}"

def log_btn(msg):
    line = f"[{elapsed()}] [BTN] {msg}"
    with _log_lock:
        print(line)
        btn_log.write(line + "\n")
        btn_log.flush()

def log_http(msg):
    line = f"[{elapsed()}] [HTTP] {msg}"
    with _log_lock:
        print(line)
        http_log.write(line + "\n")
        http_log.flush()

def log_sys(msg):
    line = f"[{elapsed()}] [SYS] {msg}"
    with _log_lock:
        print(line)
        btn_log.write(line + "\n")
        btn_log.flush()

# ── addon mitmproxy (escrito em disco, passado com -s) ───────────────────────

MITM_ADDON = """
import mitmproxy.http
from mitmproxy import ctx
import time

_t0 = time.time()

def elapsed():
    return f"{time.time() - _t0:.6f}"

def request(flow: mitmproxy.http.HTTPFlow):
    url  = flow.request.pretty_url
    meth = flow.request.method
    body = flow.request.get_content()
    body_hex = body[:256].hex() if body else ''
    ctx.log.info(f"REQ  {elapsed()}  {meth} {url}  body={len(body)}B  {body_hex[:80]}")

def response(flow: mitmproxy.http.HTTPFlow):
    url  = flow.request.pretty_url
    code = flow.response.status_code
    body = flow.response.get_content()
    ct   = flow.response.headers.get('content-type', '')
    try:
        preview = body[:400].decode('utf-8', errors='replace')
    except Exception:
        preview = body[:200].hex()
    ctx.log.info(f"RESP {elapsed()}  {code} {url}  [{ct}]  {preview[:200]}")
"""

addon_path = Path(f"mitm_addon_{ts}.py")
addon_path.write_text(MITM_ADDON, encoding="utf-8")

# ── thread do mitmdump ────────────────────────────────────────────────────────

mitm_proc   = None
mitm_thread = None

def run_mitmdump():
    global mitm_proc
    cmd = [
        MITMDUMP_EXE,
        "--listen-host", "0.0.0.0",
        "--listen-port", str(PROXY_PORT),
        "--ssl-insecure",
        "-w", LOG_MITM,
        "-s", str(addon_path),
        "--set", "termlog_verbosity=info",
    ]
    log_sys(f"Iniciando mitmdump: porta {PROXY_PORT}  log={LOG_MITM}")
    mitm_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace"
    )
    try:
        for line in mitm_proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            # Separa linhas geradas pelo addon (REQ/RESP) das do mitmdump interno
            if line.startswith("REQ ") or line.startswith("RESP "):
                log_http(line)
            else:
                log_sys(f"[mitmdump] {line}")
    except Exception as e:
        log_sys(f"[mitmdump] erro leitura: {e}")

def start_mitmdump():
    global mitm_thread
    mitm_thread = threading.Thread(target=run_mitmdump, daemon=True, name="mitmdump")
    mitm_thread.start()
    # Aguarda o proxy estar pronto (heurística: 2s)
    time.sleep(2)
    log_sys(f"Proxy HTTP pronto em {PROXY_HOST}:{PROXY_PORT}")

def stop_mitmdump():
    global mitm_proc
    if mitm_proc:
        mitm_proc.terminate()
        try:
            mitm_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mitm_proc.kill()
        mitm_proc = None
        log_sys("mitmdump encerrado")

# ── frida / button hook ───────────────────────────────────────────────────────

def on_message(message, data):
    t = message.get("type")
    if t == "send":
        payload = message.get("payload", {})
        if isinstance(payload, dict) and payload.get("type") == "button_event":
            tag   = payload.get("tag", "?")
            label = payload.get("label", "?")
            extra = payload.get("extra", "")
            n     = payload.get("n", 0)
            log_btn(f"#{n:04d}  {tag:<14}  \"{label}\"  {extra}")
        else:
            log_btn(str(payload))
    elif t == "log":
        log_btn(str(message.get("payload", "")))
    elif t == "error":
        log_btn("[ERR] " + str(message.get("stack", message)))

def run_frida():
    log_sys(f"Conectando ao device Frida em {FRIDA_HOST}...")
    device  = frida.get_device_manager().add_remote_device(FRIDA_HOST)
    log_sys(f"Device: {device}")

    src = Path(JS_SCRIPT).read_text(encoding="utf-8")
    pid = device.spawn([APP_ID])
    log_sys(f"Spawned {APP_ID}  pid={pid}")

    session = device.attach(pid)
    script  = session.create_script(src)
    script.on("message", on_message)
    script.load()

    device.resume(pid)
    log_sys(f"App resumida. pid={pid}")
    log_sys("Navegue pelos menus e clique em botões. Ctrl+C para encerrar.\n")

    session.on("detached", lambda r: log_sys(f"Sessao Frida encerrada: {r}"))
    return session

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    log_sys(f"=== run_button_hook.py  ts={ts} ===")
    log_sys(f"Logs: {LOG_BTN}  {LOG_HTTP}  {LOG_MITM}")
    log_sys("")

    # 1. Sobe o proxy em background
    start_mitmdump()

    # 2. Sobe o Frida
    session = run_frida()

    # 3. Loop principal
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_sys("Encerrado pelo usuário")
    finally:
        log_sys(f"Uptime: {time.time() - t_start:.1f}s")
        log_sys(f"Eventos de botão: {LOG_BTN}")
        log_sys(f"Tráfego HTTP:     {LOG_HTTP}")
        log_sys(f"MITM binário:     {LOG_MITM}  (mitmweb --rfile {LOG_MITM})")

        stop_mitmdump()

        try:
            session.detach()
        except Exception:
            pass

        btn_log.close()
        http_log.close()
        addon_path.unlink(missing_ok=True)

if __name__ == "__main__":
    main()
