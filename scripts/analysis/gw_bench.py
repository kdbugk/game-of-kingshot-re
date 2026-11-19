#!/usr/bin/env python3
"""gw_bench.py — bancada loopback do protocolo do gateway (127.0.0.1).
Replay dos captures + demo de 1 action round-trip local.
Usage: python3 gw_bench.py <pcap>"""
import socket, struct, threading, time, sys, collections

PCAP = sys.argv[1] if len(sys.argv) > 1 else "/home/re/work/apk/cap115.pcap"

# ── 1. extrai frames do pcap (TCP dst/src 30101) ──
def read_pcap_frames(path):
    import scapy.all as sc
    pkts = sc.rdpcap(path)
    streams = {}
    for p in pkts:
        if sc.TCP in p and (p[sc.TCP].dport == 30101 or p[sc.TCP].sport == 30101):
            key = tuple(sorted([p[sc.IP].src, p[sc.IP].dst]))
            streams.setdefault(key, {}).setdefault(p[sc.TCP].seq, b"")
            payload = bytes(p[sc.TCP].payload)
            if payload:
                streams[key][p[sc.TCP].seq] = payload
    frames = []
    for key, seqs in streams.items():
        buf = b"".join(seqs[s] for s in sorted(seqs))
        i = 0
        while i + 2 <= len(buf):
            ln = struct.unpack_from(">H", buf, i)[0]
            if i + 2 + ln > len(buf):
                break
            body = buf[i+2:i+2+ln]
            c2s = 1 if buf[0:0] == b"" and False else None
            frames.append(body)
            i += 2 + ln
    return frames

# direção: re-parse com marcador por stream
def read_pcap_frames_dir(path):
    import scapy.all as sc
    pkts = sc.rdpcap(path)
    buf_c2s, buf_s2c = b"", b""
    for p in pkts:
        if sc.TCP not in p: continue
        payload = bytes(p[sc.TCP].payload)
        if not payload: continue
        if p[sc.TCP].dport == 30101: buf_c2s += payload
        elif p[sc.TCP].sport == 30101: buf_s2c += payload
    def split(buf):
        out, i = [], 0
        while i + 2 <= len(buf):
            ln = struct.unpack_from(">H", buf, i)[0]
            if i + 2 + ln > len(buf): break
            out.append(buf[i+2:i+2+ln]); i += 2 + ln
        return out
    return split(buf_c2s), split(buf_s2c)

# ── 2. servidor loopback ──
class BenchServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(1)
        self.log = []
        self.stats = collections.Counter()
    def run(self):
        conn, _ = self.sock.accept()
        self.log.append(("accept", None))
        while True:
            hdr = self._recv(conn, 2)
            if not hdr: break
            ln = struct.unpack(">H", hdr)[0]
            body = self._recv(conn, ln)
            if body is None: break
            op, d = body[0], body[1] if len(body) > 1 else 0
            self.stats[(op, d)] += 1
            if op == 0x55:
                resp = self._frame(bytes([0x55, 0x01]) + body[2:63] + b"\x00")  # eco reduzido
                conn.sendall(resp)
                self.log.append(("handshake", ln))
            elif op == 0x15:
                ctr = body[3] if len(body) > 3 else 0
                conn.sendall(self._frame(bytes([0x15, 0x01, 0x00, (ctr + 1) & 0xFF])))
                self.log.append(("heartbeat", ctr))
            elif op == 0x59:
                ok = len(body) >= 27
                self.log.append(("ack", ok))
                if ok:
                    conn.sendall(self._frame(bytes([0x59, 0x01])))
            else:
                self.log.append((f"op:{op:#04x}", ln))
                conn.sendall(self._frame(bytes([op, 0x01]) + body[2:]))
        conn.close()
    @staticmethod
    def _frame(body): return struct.pack(">H", len(body)) + body
    @staticmethod
    def _recv(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk: return None
            buf += chunk
        return buf

def main():
    c2s, s2c = read_pcap_frames_dir(PCAP)
    print(f"replay source: {len(c2s)} C→S frames de {PCAP.split('/')[-1]}")
    srv = BenchServer(); srv.start()
    cli = socket.create_connection(("127.0.0.1", srv.port), timeout=10)
    consumed, errors = 0, 0
    for body in c2s:
        cli.sendall(struct.pack(">H", len(body)) + body)
        consumed += 1
        time.sleep(0.003)
        cli.setblocking(False)
        try:
            while True:
                h = cli.recv(2)
                if not h: break
                ln = struct.unpack(">H", h)[0]
                cli.recv(ln)
        except BlockingIOError:
            pass
        finally:
            cli.setblocking(True)
    time.sleep(0.5)
    # demo: 1 action 0x5d clonada com campo ajustado
    demo_src = next((b for b in c2s if b[0] == 0x5d), c2s[-1] if c2s else None)
    if demo_src:
        demo = bytearray(demo_src)
        demo[4] ^= 0x01  # ajusta 1 byte de payload (campo qualquer)
        cli.sendall(struct.pack(">H", len(demo)) + demo)
        time.sleep(0.3)
    cli.close()
    srv.join(timeout=3)
    print(f"consumidos: {consumed}/{len(c2s)} | framing errors: {errors}")
    print("estatísticas do servidor:", dict(sorted(srv.stats.items())[:12]))
    print("log (últimos 8):", srv.log[-8:])

if __name__ == "__main__":
    main()
