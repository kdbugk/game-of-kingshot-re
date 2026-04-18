"""
run_ssl_unpin.py

SSL unpinning + captura MITM completa.

O que faz:
  1. Inicia mitmdump em background (porta 8081)
  2. Injeta ssl_unpin.js no app via Frida (spawn mode)
  3. Loga tráfego HTTP descriptografado + eventos de bypass

Pré-requisitos:
  - CA do mitmproxy instalado no device: python mitm_setup.py
  - Proxy WiFi: 192.168.0.84:8081
  - frida-server no device: adb forward tcp:37555 tcp:37555

Uso:
  python run_ssl_unpin.py

Logs gerados:
  unpin_<ts>.log     — eventos Frida (bypasses + erros)
  http_<ts>.log      — requests/responses descriptografados
  http_<ts>.mitm     — binário para mitmweb
"""

import frida
import subprocess
import threading
import time
import sys
from pathlib import Path
from datetime import datetime

# ── configuração ──────────────────────────────────────────────────────────────

APP_ID       = "com.run.tower.defense"
FRIDA_HOST   = "127.0.0.1:37555"
JS_SCRIPT    = "ssl_unpin.js"
PROXY_HOST   = "192.168.0.84"
PROXY_PORT   = 8081
MITMDUMP_EXE = r"C:\Users\prs\AppData\Local\Python\pythoncore-3.14-64\Scripts\mitmdump.exe"

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FRIDA = f"unpin_{ts}.log"
LOG_HTTP  = f"http_{ts}.log"
LOG_MITM  = f"http_{ts}.mitm"

# ── logger ────────────────────────────────────────────────────────────────────

t_start  = time.time()
_lock    = threading.Lock()
frida_f  = open(LOG_FRIDA, "w", encoding="utf-8")
http_f   = open(LOG_HTTP,  "w", encoding="utf-8")

def elapsed():
    return f"{time.time() - t_start:.3f}"

def log(prefix, msg, file=None):
    line = f"[{elapsed()}] [{prefix}] {msg}"
    with _lock:
        print(line)
        f = file or frida_f
        f.write(line + "\n")
        f.flush()

# ── addon mitmproxy ───────────────────────────────────────────────────────────

ADDON_SRC = f"""
import mitmproxy.http
from mitmproxy import ctx
import time, os

_t0 = time.time()
_http_f = open({repr(LOG_HTTP)}, 'a', encoding='utf-8')

def _w(msg):
    line = f"[{{time.time()-_t0:.3f}}] [HTTP] {{msg}}"
    _http_f.write(line + '\\n')
    _http_f.flush()
    ctx.log.info(msg)

def request(flow: mitmproxy.http.HTTPFlow):
    url  = flow.request.pretty_url
    meth = flow.request.method
    body = flow.request.get_content()
    hdrs = dict(flow.request.headers)
    interesting = {{k:v for k,v in hdrs.items()
                   if k.lower() in ('authorization','x-token','token',
                                    'cookie','x-uid','x-device-id')}}
    _w(f"REQ  {{meth}} {{url}}")
    if interesting:
        _w(f"     headers: {{interesting}}")
    if body:
        try:
            preview = body[:600].decode('utf-8', errors='replace')
        except Exception:
            preview = body[:300].hex()
        _w(f"     body({{len(body)}}B): {{preview[:400]}}")

def response(flow: mitmproxy.http.HTTPFlow):
    url  = flow.request.pretty_url
    code = flow.response.status_code
    body = flow.response.get_content()
    ct   = flow.response.headers.get('content-type', '')
    try:
        preview = body[:800].decode('utf-8', errors='replace')
    except Exception:
        preview = body[:300].hex()
    _w(f"RESP {{code}} {{url}}  [{{ct}}]  {{len(body)}}B")
    if preview.strip():
        _w(f"     {{preview[:600]}}")
"""

addon_path = Path(f"_unpin_addon_{ts}.py")
addon_path.write_text(ADDON_SRC, encoding="utf-8")

# ── mitmdump ──────────────────────────────────────────────────────────────────

mitm_proc = None

def run_mitmdump():
    global mitm_proc
    cmd = [
        MITMDUMP_EXE,
        "--listen-host", "0.0.0.0",
        "--listen-port", str(PROXY_PORT),
        "--ssl-insecure",
        "-w", LOG_MITM,
        "-s", str(addon_path),
        "--set", "termlog_verbosity=warn",  # silencia spam interno do mitmdump
    ]
    log("SYS", f"mitmdump: porta {PROXY_PORT}  mitm={LOG_MITM}")
    mitm_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace"
    )
    for line in mitm_proc.stdout:
        line = line.rstrip()
        if line:
            log("MITM", line)

def start_mitmdump():
    t = threading.Thread(target=run_mitmdump, daemon=True, name="mitmdump")
    t.start()
    time.sleep(2)
    log("SYS", f"Proxy pronto em {PROXY_HOST}:{PROXY_PORT}")

def stop_mitmdump():
    if mitm_proc:
        mitm_proc.terminate()
        try:    mitm_proc.wait(timeout=5)
        except: mitm_proc.kill()
        log("SYS", "mitmdump encerrado")

# ── frida callbacks ───────────────────────────────────────────────────────────

def on_message(message, data):
    t = message.get("type")
    if t == "send":
        log("FRIDA", str(message.get("payload", "")))
    elif t == "log":
        log("FRIDA", str(message.get("payload", "")))
    elif t == "error":
        log("ERR", str(message.get("stack", message)))

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    log("SYS", f"=== run_ssl_unpin.py  ts={ts} ===")
    log("SYS", f"Logs: {LOG_FRIDA}  {LOG_HTTP}  {LOG_MITM}")
    log("SYS", "")

    start_mitmdump()

    log("SYS", f"Conectando Frida em {FRIDA_HOST}...")
    device  = frida.get_device_manager().add_remote_device(FRIDA_HOST)
    log("SYS", f"Device: {device}")

    src = Path(JS_SCRIPT).read_text(encoding="utf-8")
    pid = device.spawn([APP_ID])
    log("SYS", f"Spawned {APP_ID}  pid={pid}")

    session = device.attach(pid)
    script  = session.create_script(src)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    log("SYS", f"App resumida  pid={pid}")
    log("SYS", "Faça login no jogo. Ctrl+C para encerrar.\n")

    session.on("detached", lambda r: log("SYS", f"Sessão Frida encerrada: {r}"))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("SYS", "Encerrado")
    finally:
        log("SYS", f"Uptime: {time.time()-t_start:.1f}s")
        log("SYS", f"HTTP log:   {LOG_HTTP}")
        log("SYS", f"MITM file:  {LOG_MITM}")
        log("SYS", f"Frida log:  {LOG_FRIDA}")
        log("SYS", f"mitmweb:    mitmweb --rfile {LOG_MITM}")
        stop_mitmdump()
        try:    session.detach()
        except: pass
        frida_f.close()
        http_f.close()
        addon_path.unlink(missing_ok=True)

if __name__ == "__main__":
    main()
