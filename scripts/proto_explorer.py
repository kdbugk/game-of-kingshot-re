#!/usr/bin/env python3
"""proto_explorer.py — estudo do mecanismo de envio: conecta ao gateway de produção
com a identidade real do transcript, faz login, 2 heartbeats e UMA consulta leve.
Single-shot (sem loops), apenas mensagens que o cliente real manda no login normal."""
import sys, os, socket, json, pickle, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sproto_lib as L

HOST = sys.argv[1] if len(sys.argv) > 1 else "3.33.245.139"
PORT = 30101
TRANSCRIPT = "/home/re/work/apk/gw_transcript115.pkl"

S = L.default_schema()
sock = socket.create_connection((HOST, PORT), timeout=8)
peer = L.Peer(S)
sess = 0

def recvn(n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c: raise ConnectionError("fim")
        b += c
    return b

def read_msgs(timeout=3.0, max=20):
    """lê tudo que chegar na janela"""
    out = []
    sock.settimeout(timeout)
    end = time.time() + timeout
    while len(out) < max and time.time() < end:
        try:
            hdr = recvn(2)
            body = recvn(int.from_bytes(hdr, "big"))
            out.append(peer.parse(body, "S>C"))
        except socket.timeout:
            break
    return out

def req(name, obj):
    global sess
    sess += 1
    sock.sendall(L.frame(L.build_request(S, name, obj, sess, key=peer.key)))
    peer.note_request(sess, name)

print(f"[explorer] conectado a {HOST}:{PORT}")

# 1) LOGIN — identidade real (transcript)
tr = pickle.load(open(TRANSCRIPT, "rb"))
P0 = L.Peer(S)
login_obj = None
for t, d, raw in tr:
    if d == "C>S":
        m = P0.parse(raw, d)
        if m["name"] == "loginauth":
            login_obj = m["obj"]; break
req("loginauth", login_obj)
print("[enviado] loginauth (seu token/dispositivo do transcript)")
for m in read_msgs(4.0):
    if m["kind"] == "resp":
        print("[resposta]", m["name"], json.dumps(m["obj"], ensure_ascii=False)[:200])
        sk = m["obj"].get("secret_key")
        if isinstance(sk, str) and len(sk) == 8: peer.key = bytes.fromhex(sk)
        elif isinstance(sk, (bytes, bytearray)): peer.key = bytes(sk)

# 2) heartbeat x2 (o cliente manda a cada ~4s)
for i in range(2):
    time.sleep(2.0)
    req("req_heartbeat", {})
    print("[enviado] req_heartbeat")
    for m in read_msgs(2.0):
        if m["kind"] == "resp":
            print("[resposta]", m["name"], json.dumps(m["obj"], ensure_ascii=False)[:100])

# 3) UMA consulta leve e normal (agenda — o cliente pede no boot)
req("req_schedule_info", {})
print("[enviado] req_schedule_info")
for m in read_msgs(3.0):
    if m["kind"] == "resp":
        print("[resposta]", m["name"], json.dumps(m["obj"], ensure_ascii=False)[:200])

sock.close()
print("[explorer] desconectado — fim do estudo (single-shot)")
