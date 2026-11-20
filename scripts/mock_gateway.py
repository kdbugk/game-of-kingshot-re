#!/usr/bin/env python3
"""mock_gateway.py v0 — servidor-lab do protocolo do gateway (Kingshot RE).
O cliente real (via iptables DNAT no celular) conecta aqui; seguimos o transcript
da cap115 (cold-start completo) como roteiro. LOGA tudo que o cliente manda.

Usage: python3 mock_gateway.py [porta]
"""
import socket, struct, threading, time, pickle, sys, collections, os

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 30101
TRANSCRIPT = "/home/re/work/apk/gw_transcript115.pkl"
LOGDIR = "/home/re/work/apk/mock_sessions"
os.makedirs(LOGDIR, exist_ok=True)

frames = pickle.load(open(TRANSCRIPT, "rb"))  # [(t, dir, bytes)]
C2S = [(t, f) for t, d, f in frames if d == "C>S"]
S2C = [(t, f) for t, d, f in frames if d == "S>C"]
print(f"[mock] transcript: {len(C2S)} C>S / {len(S2C)} S>C")

def frame(body):
    return struct.pack(">H", len(body)) + body

class Session:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.log = open(f"{LOGDIR}/sess_{int(time.time())}_{addr[0]}.txt", "w")
        self.rx = collections.Counter()
        self.c2s_i = 0  # posição no transcript C>S
        self.cursors = {}  # (op,b1) -> próximo índice no S2C a considerar
        self.t0 = None
        self.burst_sent = False

    def note(self, msg):
        self.log.write(msg + "\n"); self.log.flush()

    def recv_frame(self):
        hdr = b""
        while len(hdr) < 2:
            c = self.conn.recv(2 - len(hdr))
            if not c: return None
            hdr += c
        ln = struct.unpack(">H", hdr)[0]
        body = b""
        while len(body) < ln:
            c = self.conn.recv(ln - len(body))
            if not c: return None
            body += c
        return body

    def send(self, f, why=""):
        try:
            self.conn.sendall(frame(f))
            self.note(f"[TX {why}] {f.hex()}")
        except Exception as e:
            self.note(f"[TX-ERR {why}] {e}")

    def match_reply(self, req):
        """respostas em sequência por família (op,b1): consome o transcript S2C na ordem"""
        op = (req[0], req[1] if len(req) > 1 else 0)
        idx = self.cursors.get(op, 0)
        s2c_same = [f for t, d, f in frames if d == "S>C" and (f[0], f[1] if len(f) > 1 else 0) == (op[0], op[1] ^ 0x20 if False else (0x75 if op[0] == 0x5d else op[1]))]
        # mapa de resposta: 5d/02->75/02 (cap115) ; mesmo op senão
        rop = {0x5d: 0x75, 0x15: 0x15, 0x55: 0x55, 0x1d: 0x1d}.get(op[0], op[0])
        rb1 = {0x02: 0x02}.get(op[1], op[1])
        cands = [f for t, d, f in frames if d == "S>C" and (f[0], f[1] if len(f) > 1 else 0) == (rop, rb1)]
        if not cands:
            cands = [f for t, d, f in frames if d == "S>C" and (f[0], f[1] if len(f) > 1 else 0) == (op[0], op[1])]
        if not cands:
            return None
        r = cands[min(idx, len(cands) - 1)]
        self.cursors[op] = idx + 1
        return r

    def initial_burst(self):
        """push do estado inicial (1d/01 etc) como no cold-start, com timing relativo"""
        tstart = None
        sent = 0
        for (t, d, f) in frames:
            if d != "S>C": continue
            if t > 60: break  # só o primeiro minuto (burst inicial + settle)
            if (f[0], f[1] if len(f) > 1 else 0) == (0x15, 0x01): continue  # heartbeats vêm on-demand
            if tstart is None:
                tstart = t; time.sleep(0.05)
            else:
                dt = t - tstart
                if dt > 0.01: time.sleep(min(dt, 0.25))
                tstart = t
            self.send(f, f"burst@{t:.2f}")
            sent += 1
        self.note(f"[burst] {sent} frames")

    def run(self):
        self.note(f"[conn] {self.addr}")
        burst_thread = None
        while True:
            req = self.recv_frame()
            if req is None:
                self.note("[disconnect]")
                break
            now = time.time() if self.t0 is None else time.time()
            if self.t0 is None: self.t0 = time.time()
            self.rx[(req[0], req[1] if len(req) > 1 else 0)] += 1
            self.note(f"[RX] {req.hex()}")
            op = (req[0], req[1] if len(req) > 1 else 0)
            if op == (0x55, 0x02):
                # handshake: resposta gravada (64B) — versão/token do transcript
                resp = next(f for t, d, f in frames if d == "S>C" and f[0] == 0x55)
                self.send(resp, "handshake")
                # dispara o burst de estado inicial em paralelo
                threading.Thread(target=self.initial_burst, daemon=True).start()
            elif op == (0x15, 0x02):
                # heartbeat: eco com o corpo registrado (pong)
                resp = next((f for t, d, f in frames if d == "S>C" and f[0] == 0x15), None)
                if resp: self.send(resp, "pong")
            else:
                m = self.match_reply(req)
                if m is not None:
                    self.send(m, "match")
                else:
                    self.note(f"[no-reply] op={op[0]:02x}/{op[1]:02x} len={len(req)}")
        self.log.close()

def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(4)
    print(f"[mock] ouvindo 0.0.0.0:{PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=Session(conn, addr).run, daemon=True).start()

if __name__ == "__main__":
    main()
