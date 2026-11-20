#!/usr/bin/env python3
"""test_ext_live.py — valida ao vivo que as extensões carregaram e respondem."""
import sys, os, socket, json, pickle, time
sys.path.insert(0, "/home/re/work/apk")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sproto_lib as L
import mock_v4, threading

PORT = 30113
ready = []
t = threading.Thread(target=mock_v4.serve, kwargs=dict(
    port=PORT, ready=ready, fixture="/home/re/work/apk/fixture_v4.json",
    integrate=True, state="/tmp/ext_live_test.json"), daemon=True)
t.start(); time.sleep(4)

S = L.default_schema(); P = L.Peer(S)
sock = socket.create_connection(("127.0.0.1", PORT), timeout=8)
sess = 0
def recvn(n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c: raise ConnectionError
        b += c
    return b
def read_msgs(tmo=3):
    out = []; sock.settimeout(tmo); end = time.time() + tmo
    while time.time() < end:
        try: out.append(P.parse(recvn(int.from_bytes(recvn(2), "big")), "S>C"))
        except socket.timeout: break
    return out
def req(n, o):
    global sess
    sess += 1
    sock.sendall(L.frame(L.build_request(S, n, o, sess, key=P.key)))
    P.note_request(sess, n)
    for m in read_msgs(3):
        if m["kind"] == "resp" and m["name"] == n:
            return m["obj"]
    return None

tr = pickle.load(open("/home/re/work/apk/gw_transcript115.pkl", "rb"))
P0 = L.Peer(S); lo = None
for t_, d, raw in tr:
    if d == "C>S":
        m = P0.parse(raw, d)
        if m["name"] == "loginauth": lo = m["obj"]; break
r = req("loginauth", lo)
sk = r.get("secret_key")
if isinstance(sk, str) and len(sk) == 8: P.key = bytes.fromhex(sk)
elif isinstance(sk, (bytes, bytearray)): P.key = bytes(sk)
req("req_loaddata", {})

TESTS = [
    ("req_alliance_init_data", {}),
    ("req_alliance_members", {}),
    ("req_chat_get_token", {}),
    ("req_world_map_info", {}),
    ("req_find_goods_start_chapter", {"chapter_id": 1}),
    ("req_climbtower_challenge", {"id": 40021, "formation_prefab": [{"id": 1, "prefab": {"soldier": [{"k": 21000, "v": 100}]}}]}),
    ("req_climbtower_challenge", {"id": 40021, "formation_prefab": [{"id": 1, "prefab": {"soldier": [{"k": 21000, "v": 100}]}}]}),  # replay → 16807
]
ok = 0; total = 0
for name, obj in TESTS:
    total += 1
    r = req(name, obj)
    if r is not None:
        ok += 1
        code = r.get("code", "?")
        print(f"  OK  {name:<40} code={code}")
    else:
        print(f"  FAIL {name}")
print(f"\n{ok}/{total} respostas recebidas")
sock.close()
