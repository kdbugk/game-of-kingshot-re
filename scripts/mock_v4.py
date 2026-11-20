#!/usr/bin/env python3
"""mock_v4.py — mock gateway sproto-REAL (Kingshot 1.14.27). Sem replay de bytes: toda mensagem é
objeto tipado -> sproto_lib.enc_struct -> 0-pack (-> XOR 4B quando o request veio com ud.crypt_method=1).

Uso:  python mock_v4.py [--port 30101] [--key ecbabcb9|random] [--fixture fixture_v4.json]
      python mock_v4.py --export-fixture   # gera fixture_v4.json a partir de gw_transcript115.pkl
Transporte: uint16 BE de comprimento + frame sproto-packed (igual v3).
Ciclo: loginauth -> resp (com secret_key = chave XOR da sessão!) ; loaddata -> burst de ~N notify_* tipados
       + resp {code:0}; demais requests -> handler sintético ou template tipado ou default {code:0}.
"""
import socket, threading, time, sys, os, json, argparse, struct, random
import sproto_lib as L

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_T0 = 1795057408        # servertime do cap115; relógio sintético = T0 + segundos desde o start

def export_fixture(path, transcript=os.path.join(HERE, "gw_transcript115.pkl")):
    import pickle
    S = L.default_schema(); fr = pickle.load(open(transcript, "rb")); P = L.Peer(S)
    fx = {"login_resp": None, "burst": [], "templates": {}, "player_base": None, "client_data": None}
    for t, d, raw in fr:
        m = P.parse(raw, d)
        if m["kind"] == "resp":
            fx["templates"].setdefault(m["name"], m["obj"])
            if m["name"] == "loginauth" and fx["login_resp"] is None: fx["login_resp"] = m["obj"]
            if m["name"] == "req_players_base_info_with_permission": fx["player_base"] = m["obj"]["result"][0]
        elif m["kind"] == "push" and t <= 5.0:
            fx["burst"].append([m["name"], m["obj"]])
        elif m["kind"] == "req" and m["name"] == "req_save_client_data" and fx["client_data"] is None:
            fx["client_data"] = m["obj"]
    json.dump(fx, open(path, "w", encoding="utf8"), ensure_ascii=False)
    return fx

class Session:
    def __init__(self, conn, addr, S, fx, key, log):
        self.conn, self.addr, self.S, self.fx, self.key, self.log = conn, addr, S, fx, key, log
        self.peer = L.Peer(S, key); self.t0 = time.time(); self.n = 0
        self.stats = {}
        self.gm_items = {}   # GM (lab): inventário do sandbox
        self.gm_hero = {}    # GM (lab): níveis de herói do sandbox

    def now(self): return SERVER_T0 + int(time.time() - self.t0)

    def recv_exact(self, n):
        b = b""
        while len(b) < n:
            c = self.conn.recv(n - len(b))
            if not c: return None
            b += c
        return b

    def send(self, raw): self.conn.sendall(L.frame(raw))

    def reply(self, m, obj):
        ud = m["hdr"].get("ud")      # o servidor real ECOA o ud do request (crypt_length inclusive)
        self.send(L.build_response(self.S, m["name"], obj, m["hdr"]["session"], ud=ud, key=self.key))

    # ---- handlers sintéticos
    def h_loginauth(self, m):
        r = dict(self.fx["login_resp"]) if self.fx else {"code": 0, "serverid": 931, "uid": 40444746}
        r["secret_key"] = self.key.hex()
        r["server_ts"] = self.now()
        if "underage_info" in r: r["underage_info"] = dict(r["underage_info"], server_ts=self.now())
        r["code"] = 0
        self.reply(m, r)

    def h_loaddata(self, m):
        for name, obj in (self.fx["burst"] if self.fx else []):
            obj = json.loads(json.dumps(obj))
            if name == "notify_game_init": obj["servertime"] = self.now()
            self.send(L.build_push(self.S, name, obj))
        self.reply(m, {"code": 0})

    def h_heartbeat(self, m): self.reply(m, {"time": self.now()})
    def h_opinion(self, m): self.reply(m, {"code": 0})
    def h_save(self, m): self.reply(m, {"code": 0})

    def h_players(self, m):
        tpl = (self.fx or {}).get("player_base") or {"lv": 1, "image": 1009, "kid": 931, "stove_lv": 39}
        res = []
        for u in m["obj"].get("uids", []):
            p = dict(tpl); p["uid"] = u; p["nickName"] = "Mock%d" % u; res.append(p)
        self.reply(m, {"code": 0, "overload": 0, "result": res})

    # ---- GM (lab): comandos admin contra ESTE servidor (sandbox nosso)
    def h_chat_token(self, m):
        # rtmcode!=0 = chat RTM indisponivel (esperamos que o cliente desista e siga)
        self.reply(m, {"code": 0, "rtmcode": 1, "token": ""})

    def h_cheat_add(self, m):
        items = m["obj"].get("data") or []
        for it in items:
            if isinstance(it, dict):
                iid = it.get("id", it.get("type", it.get("item", "?")))
                num = it.get("num", it.get("count", it.get("n", 1)))
                self.gm_items[str(iid)] = self.gm_items.get(str(iid), 0) + (num if isinstance(num, int) else 1)
        self.log(f"[GM] req_cheat_add: {json.dumps(items, ensure_ascii=False)[:200]} -> inventario={self.gm_items}")
        self.reply(m, {"code": 0})

    def h_cheat_hero(self, m):
        o = m["obj"]; self.gm_hero[str(o.get("id"))] = o.get("lev")
        self.log(f"[GM] req_cheat_set_hero_lev: {o} -> herois={self.gm_hero}")
        self.reply(m, {"code": 0})

    def h_default(self, m):
        tpl = ((self.fx or {}).get("templates") or {}).get(m["name"])
        if tpl is not None: self.reply(m, tpl); self.stats["tpl"] = self.stats.get("tpl", 0) + 1; return
        spec = self.S.c2s_by_name[m["name"]]["response"]
        fields = self.S.fields_of(spec)
        self.stats["dflt"] = self.stats.get("dflt", 0) + 1
        if spec is None: return                     # protocolo sem response: não responde
        self.reply(m, {"code": 0} if any(f["name"] == "code" for f in fields) else {})

    H = {"loginauth": h_loginauth, "req_loaddata": h_loaddata, "req_heartbeat": h_heartbeat,
         "req_trigger_opinion": h_opinion, "req_save_client_data": h_save,
         "req_players_base_info_with_permission": h_players,
         "req_cheat_add": h_cheat_add, "req_cheat_set_hero_lev": h_cheat_hero,
         "req_chat_get_token": h_chat_token}

    def run(self):
        try:
            while True:
                hdr = self.recv_exact(2)
                if hdr is None: break
                raw = self.recv_exact(struct.unpack(">H", hdr)[0])
                if raw is None: break
                self.n += 1
                try:
                    m = self.peer.parse(raw, "C>S")
                except Exception as e:
                    self.log(f"[parse-fail #{self.n}] {e!r} {raw[:24].hex()}"); continue
                self.stats[m["name"]] = self.stats.get(m["name"], 0) + 1
                self.log(f"[RX #{self.n}] {m['name']} s={m['hdr'].get('session')} {json.dumps(m['obj'], ensure_ascii=False)[:100]}")
                self.H.get(m["name"], Session.h_default)(self, m)
        except (ConnectionError, OSError) as e:
            self.log(f"[conn-err] {e}")
        finally:
            self.log(f"[end] {self.stats}"); self.conn.close()

def serve(port=30101, key=None, fixture=None, log=print, ready=None, stop=None):
    S = L.default_schema()
    fx = json.load(open(fixture, encoding="utf8")) if fixture and os.path.exists(fixture) else None
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1" if ready is not None else "0.0.0.0", port)); srv.listen(8)
    if ready is not None: ready.append(srv.getsockname()[1]); srv.settimeout(0.2)
    log(f"[mock v4] porta {srv.getsockname()[1]} fixture={'sim' if fx else 'NAO'}")
    while not (stop and stop.is_set()):
        try: conn, addr = srv.accept()
        except socket.timeout: continue
        k = key or bytes(random.randrange(256) for _ in range(4))
        threading.Thread(target=Session(conn, addr, S, fx, k, log).run, daemon=True).start()
    srv.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=30101)
    ap.add_argument("--key", default="random")
    ap.add_argument("--fixture", default=os.path.join(HERE, "fixture_v4.json"))
    ap.add_argument("--export-fixture", action="store_true")
    a = ap.parse_args()
    if a.export_fixture:
        fx = export_fixture(a.fixture); print("fixture:", a.fixture, "burst", len(fx["burst"]), "templates", len(fx["templates"])); sys.exit()
    serve(a.port, None if a.key == "random" else bytes.fromhex(a.key), a.fixture)
