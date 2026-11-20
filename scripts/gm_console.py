#!/usr/bin/env python3
"""gm_console.py — console de GM do lab: executa comandos admin contra O NOSSO mock_v4.
Login sproto real -> heartbeat -> comandos GM (req_cheat_*) -> respostas decodificadas."""
import sys, os, socket, json, pickle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sproto_lib as L

HOST, PORT = "127.0.0.1", 30101
TRANSCRIPT = "/home/re/work/apk/gw_transcript115.pkl"

S = L.default_schema()
sock = socket.create_connection((HOST, PORT), timeout=5)
peer = L.Peer(S)
sess = 0

def recvn(n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c: raise ConnectionError("fim")
        b += c
    return b

def read_msg():
    hdr = recvn(2)
    body = recvn(int.from_bytes(hdr, "big"))
    return peer.parse(body, "S>C")

def req(name, obj):
    global sess
    sess += 1
    sock.sendall(L.frame(L.build_request(S, name, obj, sess, key=peer.key)))
    peer.note_request(sess, name)
    return read_msg()

# 1) login com o objeto real do transcript
tr = pickle.load(open(TRANSCRIPT, "rb"))
P0 = L.Peer(S)
login_obj = None
for t, d, raw in tr:
    if d == "C>S":
        m = P0.parse(raw, d)
        if m["name"] == "loginauth":
            login_obj = m["obj"]; break
print("== login:", json.dumps(login_obj, ensure_ascii=False)[:120], "...")
r = req("loginauth", login_obj)
sk = r["obj"].get("secret_key")
print("== resposta login:", json.dumps(r["obj"], ensure_ascii=False)[:160])
if isinstance(sk, str) and len(sk) == 8:
    peer.key = bytes.fromhex(sk); print("== secret_key da sessão:", sk)
elif isinstance(sk, (bytes, bytearray)):
    peer.key = bytes(sk); print("== secret_key da sessão:", sk.hex())

# 2) heartbeat
r = req("req_heartbeat", {})
print("== heartbeat:", r["name"], json.dumps(r["obj"], ensure_ascii=False)[:60])

# 3) COMANDOS GM (contra o NOSSO servidor)
r = req("req_cheat_add", {"data": [{"id": 101, "num": 100000}, {"id": 102, "num": 500000}]})
print("== GM req_cheat_add 100k gems + 500k comida ->", r["name"], r["obj"])

r = req("req_cheat_set_hero_lev", {"id": 1001, "lev": 75})
print("== GM req_cheat_set_hero_lev (heroi 1001 -> 75) ->", r["name"], r["obj"])

r = req("req_heartbeat", {})
print("== heartbeat final:", r["obj"])
print("== DONE — comandos executados NO NOSSO SERVIDOR")
