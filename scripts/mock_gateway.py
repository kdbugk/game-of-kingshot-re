#!/usr/bin/env python3
"""mock_gateway.py v3 — servidor-lab do protocolo do gateway (Kingshot RE).
v3: timeline completa do transcript + respostas por família com ID TRANSPLANTADO
do request vivo (offsets aprendidos do transcript) — o cliente casa resposta por id.

Usage: python3 mock_gateway.py [porta]"""
import socket, struct, threading, time, pickle, sys, collections, os

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 30101
TRANSCRIPT = "/home/re/work/apk/gw_transcript115.pkl"
LOGDIR = "/home/re/work/apk/mock_sessions"
os.makedirs(LOGDIR, exist_ok=True)

frames = pickle.load(open(TRANSCRIPT, "rb"))
S2C = [(t, f) for t, d, f in frames if d == "S>C"]

def frame(body):
    return struct.pack(">H", len(body)) + body

# mapa de famílias: (reqop,reqb1) -> (respop,respb1, req_off, resp_off, id_len)
FAMILY = {
    (0x15, 0x02): (0x15, 0x01, 3, 3, 1),   # heartbeat -> pong (id em [3])
    (0x5d, 0x02): (0x55, 0x02, 4, 3, 1),   # comando -> resposta (id 1B: req[4]->resp[3])
    (0x1d, 0x03): (0x15, 0x03, 4, 3, 2),   # kind-03 -> kind-03 (id 2B: req[4:6]->resp[3:5])
    (0x1d, 0x02): (0x1d, 0x01, 4, 3, 1),
    (0x59, 0x02): (0x55, 0x02, 4, 3, 1),
}

class Session:
    def __init__(self, conn, addr):
        self.conn = conn; self.addr = addr
        self.log = open(f"{LOGDIR}/sess_{int(time.time()*10)}.txt", "w")
        self.cursors = {}
        self.req_n = 0

    def note(self, m):
        self.log.write(m + "\n"); self.log.flush()

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
            self.conn.sendall(frame(f)); self.note(f"[TX {why}] {f.hex()}")
        except Exception as e:
            self.note(f"[TX-ERR {why}] {e}")

    def next_recorded(self, respop, respb1, tag=None):
        idx = self.cursors.get((respop, respb1), 0)
        cands = [f for t, d, f in frames if d == "S>C" and f[0] == respop and (f[1] if len(f) > 1 else 0) == respb1]
        if not cands: return None, idx
        # preferencia por tag no resp[2:4]? responses nao carregam tag; usa ordem
        r = cands[min(idx, len(cands) - 1)]
        self.cursors[(respop, respb1)] = idx + 1
        return r, idx

    def transplant_id(self, req, resp):
        fam = FAMILY.get((req[0], req[1] if len(req) > 1 else 0))
        if not fam: return resp
        ro, so, L = fam[2], fam[3], fam[4]
        if len(req) >= ro + L and len(resp) >= so + L:
            resp = resp[:so] + req[ro:ro+L] + resp[so+L:]
        return resp

    def full_timeline(self):
        tprev = None
        for t, f in S2C:
            if tprev is not None:
                dt = t - tprev
                if dt > 0: time.sleep(min(dt, 0.5))
            tprev = t
            self.send(f, f"tl@{t:.2f}")
            if t > 70:  # primeira fase do timeline chega ate 70s; resto sob demanda
                break

    def run(self):
        self.note(f"[conn] {self.addr}")
        tl = None
        while True:
            req = self.recv_frame()
            if req is None:
                self.note("[disconnect]"); break
            self.req_n += 1
            op = (req[0], req[1] if len(req) > 1 else 0)
            self.note(f"[RX #{self.req_n}] {req.hex()}")
            if op == (0x55, 0x02):
                resp = next(f for t, d, f in frames if d == "S>C" and f[0] == 0x55)
                self.send(resp, "handshake")
                if tl is None:
                    tl = threading.Thread(target=self.full_timeline, daemon=True)
                    tl.start()
                continue
            fam = FAMILY.get(op)
            if fam:
                rec, idx = self.next_recorded(fam[0], fam[1])
                if rec is not None:
                    resp = self.transplant_id(req, bytearray(rec))
                    self.send(bytes(resp), f"fam{op[0]:02x}/{op[1]:02x}#{idx}")
                    continue
            self.note(f"[no-fam] {op[0]:02x}/{op[1]:02x} len={len(req)}")
        self.log.close()

def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT)); srv.listen(4)
    print(f"[mock v3] ouvindo 0.0.0.0:{PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=Session(conn, addr).run, daemon=True).start()

if __name__ == "__main__":
    main()
