"""
run_gateway_capture.py

Captura o tráfego TCP da porta 30101 (game gateway) via tcpdump no device.
Salva .pcap e tenta identificar o protocolo (TLS vs plain vs WebSocket).

Uso:
  python run_gateway_capture.py

Depois analise com Wireshark:
  Abra o .pcap e filtre por: tcp.port == 30101
"""

import subprocess, sys, time, os
from pathlib import Path
from datetime import datetime

ADB  = "adb"
PORT = 30101
ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
PCAP_DEVICE = f"/sdcard/gateway_{ts}.pcap"
PCAP_LOCAL  = f"gateway_{ts}.pcap"
LOG         = f"gateway_{ts}.log"

log     = open(LOG, "w", encoding="utf-8")
t_start = time.time()

def elapsed():
    return f"{time.time() - t_start:.1f}s"

def tee(msg):
    line = f"[{elapsed()}] {msg}"
    print(line)
    log.write(line + "\n")
    log.flush()

def analyze_pcap(path):
    """Tenta ler o .pcap com scapy ou dpkt para identificar o protocolo."""
    tee(f"\nAnalisando {path}...")
    try:
        import dpkt
        with open(path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            pkts = list(pcap)
        tee(f"Total de pacotes: {len(pkts)}")

        tls_count = 0
        ws_count  = 0
        raw_count = 0
        sizes     = []

        for ts_pkt, buf in pkts:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip  = eth.data
                tcp = ip.data
                payload = bytes(tcp.data)
                if not payload:
                    continue
                sizes.append(len(payload))
                # TLS: começa com 0x16 0x03 (Content Type: Handshake ou Application Data)
                if payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
                    tls_count += 1
                # WebSocket: GET / HTTP (upgrade) ou frame WS (0x81, 0x82...)
                elif payload[:3] == b'GET' or payload[0] in (0x81, 0x82, 0x88, 0x89):
                    ws_count += 1
                else:
                    raw_count += 1
                    if raw_count <= 3:
                        tee(f"  raw payload[{len(payload)}B]: {payload[:32].hex()} | {payload[:32]!r}")
            except Exception:
                continue

        tee(f"  TLS:       {tls_count} pacotes")
        tee(f"  WebSocket: {ws_count} pacotes")
        tee(f"  Raw/outro: {raw_count} pacotes")
        if sizes:
            tee(f"  Tamanhos:  min={min(sizes)} max={max(sizes)} avg={sum(sizes)//len(sizes)}")

        if tls_count > raw_count and tls_count > ws_count:
            tee("\n  PROTOCOLO: TLS sobre TCP — conteudo cifrado")
            tee("  Para ver: precisa hookar SSL_read/SSL_write via Frida (gateway_hook.js)")
        elif ws_count > 0:
            tee("\n  PROTOCOLO: WebSocket — pode ter upgrade HTTP capturavel")
        else:
            tee("\n  PROTOCOLO: Binario custom ou XOR — analise os bytes raw acima")

    except ImportError:
        tee("dpkt nao instalado. Para analise automatica: pip install dpkt")
        tee(f"Abra {path} no Wireshark e filtre: tcp.port == {PORT}")

def main():
    tee(f"Iniciando captura na porta {PORT}...")
    tee(f"PCAP device: {PCAP_DEVICE}")
    tee(f"PCAP local:  {PCAP_LOCAL}")
    tee("Abra o jogo e entre em uma batalha. Ctrl+C para encerrar.\n")

    cmd = [ADB, "shell", "su", "-c",
           f"tcpdump -i any -s 0 port {PORT} -w {PCAP_DEVICE}"]
    tee(f"cmd: {' '.join(cmd)}")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        while True:
            line = proc.stdout.readline()
            if line:
                tee(line.rstrip())
            elif proc.poll() is not None:
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        tee("Encerrando captura...")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        tee(f"\nPull do PCAP...")
        result = subprocess.run(
            [ADB, "pull", PCAP_DEVICE, PCAP_LOCAL],
            capture_output=True, text=True
        )
        tee(result.stdout.strip() or result.stderr.strip())

        if Path(PCAP_LOCAL).exists() and Path(PCAP_LOCAL).stat().st_size > 0:
            tee(f"PCAP salvo: {PCAP_LOCAL} ({Path(PCAP_LOCAL).stat().st_size} bytes)")
            analyze_pcap(PCAP_LOCAL)
        else:
            tee("PCAP vazio — nenhuma conexao na porta 30101 foi capturada")
            tee("Certifique-se de entrar em uma batalha durante a captura")

        tee(f"\nUptime: {elapsed()}")
        tee(f"Wireshark: abra {PCAP_LOCAL} e filtre por 'tcp.port == {PORT}'")
        log.close()

if __name__ == "__main__":
    main()
