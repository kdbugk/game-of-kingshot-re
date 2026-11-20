#!/usr/bin/env python3
"""Valida: para cada comando com receita real tratado pelo h_default, a resposta do mock bate com a receita
(estaticos iguais; dinamicos = epoch rebaseado em now) e os pushes estaveis chegam."""
import sys, os, json, socket, threading, time, pickle
HERE = os.path.dirname(os.path.abspath(__file__)); MS = os.path.join(HERE, "..", "mockserver")
sys.path.insert(0, MS)
import sproto_lib as L, mock_v4
ready = []; stop = threading.Event()
threading.Thread(target=mock_v4.serve, kwargs=dict(port=30105, fixture=os.path.join(MS, "fixture_v4.json"), log=lambda s: None, ready=ready, stop=stop), daemon=True).start()
while not ready: time.sleep(0.05)
S = L.default_schema(); sock = socket.create_connection(("127.0.0.1", ready[0]), timeout=2); peer = L.Peer(S); sess = 0
def recvn(n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c: raise ConnectionError
        b += c
    return b
def read(): return peer.parse(recvn(int.from_bytes(recvn(2), "big")), "S>C")
def req(name, obj, quiet=0.4):
    global sess; sess += 1
    sock.sendall(L.frame(L.build_request(S, name, obj, sess, key=peer.key))); peer.note_request(sess, name)
    resp = None; pushes = []
    sock.settimeout(2)
    while True:
        try: r = read()
        except socket.timeout: break
        if r["kind"] == "resp": resp = r["obj"]; sock.settimeout(quiet)
        else: pushes.append((r["name"], r["obj"]))
        if resp is not None and not pushes and quiet: pass
    return resp, pushes
def strip(o, parts):
    """remove o caminho dinamico de o (copia); [] = todos os elementos"""
    if not parts or not isinstance(o, dict): return
    k = parts[0]; lst = k.endswith("[]"); k = k.rstrip("[]") if lst else k
    if k not in o: return
    if len(parts) == 1: o.pop(k); return
    v = o[k]
    for e in (v if lst and isinstance(v, list) else [v]): strip(e, parts[1:])
def flat(o, p=""):
    r = {}
    if isinstance(o, dict):
        for k, v in o.items(): r.update(flat(v, f"{p}.{k}"))
    elif isinstance(o, list):
        for i, v in enumerate(o): r.update(flat(v, f"{p}[{i}]"))
    else: r[p] = o
    return r
def epochs(o):
    return {p: v for p, v in flat(o).items() if isinstance(v, int) and 1.7e9 < v < 1.9e9}

tr = pickle.load(open(os.path.join(MS, "gw_transcript115.pkl"), "rb")); P0 = L.Peer(S)
for t, d, raw in tr:
    if d == "C>S":
        m = P0.parse(raw, d)
        if m["name"] == "loginauth": lo = m["obj"]; break
r, _ = req("loginauth", lo, 0.3); peer.key = bytes.fromhex(r["secret_key"])
R = json.load(open(os.path.join(HERE, "recipes.json"), encoding="utf8"))
cmds = sorted(c for c, v in R.items() if v["response"] is not None and c not in mock_v4.Session.H and c != "loginauth")
ok = bad = 0
def chk(c, cond, msg):
    global ok, bad
    if cond: ok += 1; print("PASS", c, msg)
    else: bad += 1; print("FAIL", c, msg)
for c in cmds:
    rec = R[c]; resp, pushes = req(c, rec["req_exemplo"])
    exp = json.loads(json.dumps(rec["response"])); got = json.loads(json.dumps(resp or {}))
    dyn = rec.get("_dynamic") or []
    for p in dyn: strip(exp, p.split(".")); strip(got, p.split("."))
    chk(c, exp == got, "estaticos iguais (%d campos dinamicos ignorados)" % len(dyn))
    if dyn and rec.get("_ref_time"):
        ge = epochs(resp); now = time.time(); bad_e = []
        for p, v in epochs(rec["response"]).items():
            if p not in ge: continue
            want = now + (v - rec["_ref_time"])
            if abs(ge[p] - want) > 5: bad_e.append(p)
        chk(c, not bad_e, "dinamicos (epoch) rebaseados em now() %s" % (bad_e or ""))
    names = [n for n, _ in pushes]
    want = [n for n, _ in rec["pushes"]]
    chk(c, all(names.count(n) >= want.count(n) for n in set(want)), "pushes estaveis %s" % want)
stop.set()
print("RESULT RECIPES: %d OK, %d FAIL, %d comandos" % (ok, bad, len(cmds)))
sys.exit(1 if bad else 0)
