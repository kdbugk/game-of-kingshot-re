"""
mitmdump_capture.py

Captura e loga o tráfego HTTPS do com.run.tower.defense via mitmproxy.

Pré-requisitos:
  - CA do mitmproxy instalado como sistema no device (rodar mitm_setup.py)
  - Proxy WiFi configurado no Android para 192.168.0.84:8080

Uso:
  python mitmdump_capture.py

Saída:
  - Console: requests/responses em tempo real
  - traffic_<timestamp>.mitm: arquivo binário (abrível no mitmweb)
  - traffic_<timestamp>.log: log texto com headers e body resumido
"""

import subprocess
import sys
import time
import threading
from pathlib import Path
from datetime import datetime

PROXY_HOST = "192.168.0.84"
PROXY_PORT = 8081
MITMDUMP   = r"C:\Users\prs\AppData\Local\Python\pythoncore-3.14-64\Scripts\mitmdump.exe"
APP_ID     = "com.run.tower.defense"

ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_BIN = f"traffic_{ts}.mitm"
LOG_TXT = f"traffic_{ts}.log"

log = open(LOG_TXT, "w", encoding="utf-8")
t_start = time.time()

def elapsed():
    return f"{time.time() - t_start:.1f}s"

def tee(msg):
    line = f"[{elapsed()}] {msg}"
    print(line)
    log.write(line + "\n")
    log.flush()

# Script inline do mitmproxy para filtrar e formatar
ADDON_SCRIPT = r"""
import mitmproxy.http
from mitmproxy import ctx

TARGET_APP_HINTS = [
    "run", "tower", "defense", "centurygame", "netease",
    "besthttp", "unity", "cdn"
]

def request(flow: mitmproxy.http.HTTPFlow):
    url = flow.request.pretty_url
    method = flow.request.method
    host = flow.request.host
    body = flow.request.get_content()
    body_preview = body[:200].hex() if body else ""
    ctx.log.info(f"REQ  {method} {url}")
    if body:
        ctx.log.info(f"     body({len(body)}B): {body_preview}{'...' if len(body)>200 else ''}")

def response(flow: mitmproxy.http.HTTPFlow):
    url = flow.request.pretty_url
    status = flow.response.status_code
    body = flow.response.get_content()
    ct = flow.response.headers.get("content-type", "")
    body_preview = ""
    if body:
        try:
            body_preview = body[:500].decode("utf-8", errors="replace")
        except:
            body_preview = body[:200].hex()
    ctx.log.info(f"RESP {status} {url} [{ct}]")
    if body_preview:
        ctx.log.info(f"     body({len(body)}B): {body_preview[:300]}{'...' if len(body_preview)>300 else ''}")
"""

addon_path = Path("mitm_addon.py")
addon_path.write_text(ADDON_SCRIPT, encoding="utf-8")

def main():
    tee(f"Iniciando captura MITM — proxy {PROXY_HOST}:{PROXY_PORT}")
    tee(f"Log binário: {LOG_BIN}")
    tee(f"Log texto:   {LOG_TXT}")
    tee("Configure o proxy WiFi do Android para " + f"{PROXY_HOST}:{PROXY_PORT}")
    tee("Inicie o jogo e navegue pelos menus. Ctrl+C para encerrar.\n")

    cmd = [
        MITMDUMP,
        "--listen-host", "0.0.0.0",
        "--listen-port", str(PROXY_PORT),
        "--ssl-insecure",            # aceita qualquer cert upstream (nosso próprio CA já está instalado no device)
        "-w", LOG_BIN,               # salva tráfego bruto
        "-s", str(addon_path),       # addon de logging
        "--set", "termlog_verbosity=info",
    ]

    tee(f"cmd: {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace"
    )

    try:
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                tee(line)
    except KeyboardInterrupt:
        tee("Encerrado pelo usuário")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        tee(f"Uptime total: {elapsed()}")
        tee(f"Tráfego salvo em: {LOG_BIN}")
        tee(f"Para analisar offline: mitmweb --rfile {LOG_BIN}")
        log.close()
        addon_path.unlink(missing_ok=True)

if __name__ == "__main__":
    main()
