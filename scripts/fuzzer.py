#!/usr/bin/env python3
"""fuzzer.py — dispara os 1888 fixtures contra mock_v4 (--state) e classifica cobertura."""
import sys, os, json, socket, time, pickle, subprocess, tempfile, collections
MS = r"C:/Users/prs/work/mockserver"; sys.path.insert(0, MS)
import sproto_lib as L
PORT = 30103; HERE = os.path.dirname(os.path.abspath(__file__))
FIX = json.load(open(r"C:/Users/prs/projects/game-of-kingshot-re/protocols/fixtures_all.json"))
S = L.default_schema()
TR = pickle.load(open(MS + "/gw_transcript115.pkl", "rb")); P0 = L.Peer(S)
LOGIN = next(P0.parse(raw, d)["obj"] for t, d, raw in TR if d == "C>S" and P0.parse(raw, d)["name"] == "loginauth")
MODS = {}
for ln in open(r"C:/Users/prs/projects/game-of-kingshot-re/protocols/MSGMAP.tsv", encoding="utf8").read().splitlines()[1:]:
    p = ln.split("\t")
    if len(p) >= 4: MODS[p[2]] = p[3]

class Cli:
    def __init__(s):
        s.sock = socket.create_connection(("127.0.0.1", PORT), timeout=8); s.peer = L.Peer(S); s.sess = 0
    def recvn(s, n):
        b = b""
        while len(b) < n:
            c = s.sock.recv(n - len(b))
            if not c: raise ConnectionError("fim")
            b += c
        return b
    def read(s): return s.peer.parse(s.recvn(int.from_bytes(s.recvn(2), "big")), "S>C")
    def send(s, name, obj):
        s.sess += 1
        s.sock.sendall(L.frame(L.build_request(S, name, obj or {}, s.sess, key=s.peer.key))); s.peer.note_request(s.sess, name)
    def req(s, name, obj=None, to=8):
        s.sock.settimeout(to); s.send(name, obj); pushes = []
        while True:
            r = s.read()
            if r["kind"] == "resp": return r["obj"], pushes
            pushes.append(r)
    def fresh(s):
        o, _ = s.req("loginauth", LOGIN); s.peer.key = bytes.fromhex(o["secret_key"]); s.req("req_loaddata")

def start(state):
    p = subprocess.Popen([sys.executable, "-u", MS + "/mock_v4.py", "--port", str(PORT), "--key", "ecbabcb9", "--state", state],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try: socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close(); return p
        except OSError: time.sleep(0.1)
    raise RuntimeError("mock nao subiu")

def fire(c, name, obj):
    """-> dict resultado. Pode levantar ConnectionError (desync)."""
    c.sess += 1
    try: c.sock.sendall(L.frame(L.build_request(S, name, obj or {}, c.sess, key=c.peer.key))); c.peer.note_request(c.sess, name)
    except (KeyError, Exception) as e:
        if isinstance(e, OSError): raise ConnectionError(str(e))
        c.sess -= 1; return {"cls": "build_error", "err": repr(e)[:100]}
    pushes = []; resp = None; end = time.time() + 2.0
    c.sock.settimeout(0.3)
    while time.time() < end:
        try: r = c.read()
        except socket.timeout:
            if resp is not None or pushes and time.time() > end - 1.6: break
            continue
        except ConnectionError: raise
        except OSError as e: raise ConnectionError(str(e))
        except Exception as e: return {"cls": "parse_error", "err": repr(e)[:100], "pushes": [p["name"] for p in pushes]}
        if r["kind"] == "resp": resp = r["obj"]; end = min(end, time.time() + 0.3)
        else: pushes.append(r)
    pn = [p["name"] for p in pushes]
    if resp is None: return {"cls": "no_response", "pushes": pn}
    code = resp.get("code") if isinstance(resp, dict) else None
    if code is None: cls = "responded_nocode"
    elif code == 0: cls = "code0"
    else: cls = "rule_code"
    return {"cls": cls, "code": code, "pushes": pn}

def main():
    tmp = tempfile.mkdtemp(prefix="fuzz_"); n = 0; res = {}; names = list(FIX)
    mock = start(os.path.join(tmp, "a0.json")); c = None
    def reconnect(i):
        nonlocal c, mock
        if mock.poll() is not None: mock = start(os.path.join(tmp, f"a{i}.json"))
        for _ in range(3):
            try:
                if c: c.sock.close()
            except Exception: pass
            try: c = Cli(); c.fresh(); return True
            except Exception: time.sleep(0.5)
        return False
    reconnect(0)
    for i, name in enumerate(names):
        if i and i % 100 == 0:
            mock.kill(); mock.wait(); mock = start(os.path.join(tmp, f"a{i}.json")); reconnect(i)
        if name == "loginauth": res[name] = {"cls": "skipped_login"}; continue
        try: r = fire(c, name, FIX[name])
        except ConnectionError as e:
            r = {"cls": "desync", "err": str(e)[:80]}; reconnect(i)
        except Exception as e:
            r = {"cls": "desync", "err": repr(e)[:80]}; reconnect(i)
        if r["cls"] == "parse_error": reconnect(i)
        r["module"] = MODS.get(name, "?"); res[name] = r
        if i % 100 == 0: print(i, name, r["cls"], flush=True)
    mock.kill()
    json.dump(res, open(HERE + "/coverage_full.json", "w"), indent=1)
    json.dump({k: v["cls"] for k, v in res.items()}, open(HERE + "/coverage.json", "w"), indent=1)
    print(collections.Counter(v["cls"] for v in res.values()))
if __name__ == "__main__": main()
