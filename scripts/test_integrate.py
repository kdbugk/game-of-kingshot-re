#!/usr/bin/env python3
"""test_integrate.py — integracao mock_v4 + server_state/rules/timers. Sobe o mock REAL (subprocess, CLI) na 30102
com --state temporario e fala sproto_lib como o gm_console. Restart de verdade (kill + novo processo)."""
import sys, os, json, socket, time, pickle, subprocess, tempfile, shutil
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
sys.path.append(os.path.join(HERE, "..", "server"))
import sproto_lib as L
import server_rules as R, server_timers as T

PORT = 30102
S = L.default_schema()
TR = pickle.load(open(os.path.join(HERE, "gw_transcript115.pkl"), "rb")); P0 = L.Peer(S)
LOGIN = next(P0.parse(raw, d)["obj"] for t, d, raw in TR if d == "C>S" and P0.parse(raw, d)["name"] == "loginauth")

class Mock:
    def __init__(self, state, *extra):
        self.p = subprocess.Popen([sys.executable, "-u", os.path.join(HERE, "mock_v4.py"), "--port", str(PORT), "--key", "ecbabcb9",
                                   "--state", state, *extra], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(100):
            try: socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close(); break
            except OSError: time.sleep(0.1)
        else: raise RuntimeError("mock nao subiu")
    def stop(self): self.p.kill(); self.p.wait()

class Cli:
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", PORT), timeout=8); self.peer = L.Peer(S); self.sess = 0
    def recvn(self, n):
        b = b""
        while len(b) < n:
            c = self.sock.recv(n - len(b))
            if not c: raise ConnectionError("fim")
            b += c
        return b
    def read(self): return self.peer.parse(self.recvn(int.from_bytes(self.recvn(2), "big")), "S>C")
    def req(self, name, obj=None):
        self.sess += 1
        self.sock.sendall(L.frame(L.build_request(S, name, obj or {}, self.sess, key=self.peer.key))); self.peer.note_request(self.sess, name)
        pushes = []
        while True:
            r = self.read()
            if r["kind"] == "resp": return r["obj"], pushes
            pushes.append(r)
    def login(self):
        o, _ = self.req("loginauth", LOGIN); self.peer.key = bytes.fromhex(o["secret_key"]); return o
    def loaddata(self): return self.req("req_loaddata")
    def close(self): self.sock.close()

OK = BAD = 0
def check(name, cond, extra=""):
    global OK, BAD
    if cond: OK += 1
    else: BAD += 1
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))

def balance(pushes, rid):
    for p in pushes:
        if p["name"] == "notify_resource_init":
            for d in p["obj"].get("data", []):
                if d["id"] == rid: return d.get("count", 0)
    return None
def pnames(pushes): return [p["name"] for p in pushes]

tmp = tempfile.mkdtemp(prefix="integ_"); state = os.path.join(tmp, "account.json")
mock = Mock(state)
try:
    # ---- 1. sequenciador: shop_info ANTES do loaddata (sessao nova) -> 2
    c = Cli(); c.login()
    o, _ = c.req("req_shop_info", {"shop_id": 301}); check("shop_info antes do loaddata -> code 2", o.get("code") == 2, o)
    o, _ = c.req("req_climbtower_challenge", {"id": 40021}); check("acao (climbtower) antes do loaddata -> code 2", o.get("code") == 2, o)
    o, _ = c.req("req_heartbeat"); check("heartbeat liberado antes do loaddata", "time" in o, o)
    # ---- 2. login -> loaddata ok
    o, push = c.loaddata(); check("loaddata code 0", o.get("code") == 0, o)
    check("loaddata: snapshot da conta (>=20 notifies, resource_init+shelter)", len(push) >= 20 and "notify_resource_init" in pnames(push)
          and "notify_shelter_info" in pnames(push), len(push))
    d0 = balance(push, 102) or 0
    o, _ = c.req("req_shop_info", {"shop_id": 301}); check("shop_info depois do loaddata -> code 0 + goods", o.get("code") == 0 and o["info"]["goods"], o)
    # ---- 3. climbtower 2x
    o, _ = c.req("req_climbtower_challenge", {"id": 40021}); check("climbtower_challenge 1a -> code 0", o.get("code") == 0, o)
    o, _ = c.req("req_climbtower_challenge", {"id": 40021}); check("climbtower_challenge 2a -> 16807", o.get("code") == 16807, o)
    o, _ = c.req("req_climbtower_challenge", {"id": 40022}); check("climbtower outro nivel (40022) -> code 0", o.get("code") == 0, o)
    # ---- 4. shop_buy
    o, pu = c.req("req_shop_buy", {"shop_id": 301, "goods_id": 3, "count": 1}); check("shop_buy sem preco/limite folgado -> code 0", o.get("code") == 0 and o["goods"]["buy_count"] == 1, o)
    o, pu = c.req("req_shop_buy", {"shop_id": 301, "goods_id": 5, "count": 3}); check("shop_buy ate o limite (3/3) -> code 0", o.get("code") == 0, o)
    o, _ = c.req("req_shop_buy", {"shop_id": 301, "goods_id": 5, "count": 1}); check("shop_buy alem do limite -> 702", o.get("code") == 702, o)
    o, _ = c.req("req_shop_buy", {"shop_id": 301, "goods_id": 99, "count": 1}); check("shop_buy slot inexistente -> 701", o.get("code") == 701, o)
    o, pu = c.req("req_shop_buy", {"shop_id": 301, "goods_id": 2, "count": 1})
    check("shop_buy com preco (3750 de 109) -> code 0 + notify_resource_update del", o.get("code") == 0 and "notify_resource_update" in pnames(pu), (o, pnames(pu)))
    o, _ = c.req("req_shop_buy", {"shop_id": 1601, "goods_id": 4, "count": 1}); check("shop_buy sem saldo (10000 de 117, tem 1000) -> 51", o.get("code") == 51, o)
    o, _ = c.req("req_shop_buy", {"shop_id": 301, "goods_id": 3, "count": 0}); check("shop_buy count 0 -> 2", o.get("code") == 2, o)
    # ---- 5. hang-up 2x
    o, _ = c.req("req_get_hang_up_reward"); check("hang_up_reward 1a -> code 0", o.get("code") == 0, o)
    o, _ = c.req("req_get_hang_up_reward")
    check("hang_up_reward 2a -> err_hang_up_reward_interval_not_enough (4004)", o.get("code") == R.code("err_hang_up_reward_interval_not_enough") == 4004, o)
    # ---- 6. online / daily / mail / td
    o, _ = c.req("req_receive_online_reward"); check("online_reward 1a ok", o.get("code") == 0, o)
    o, _ = c.req("req_receive_online_reward"); check("online_reward 2a -> 6151", o.get("code") == 6151, o)
    o, _ = c.req("req_get_all_dailyquest_award", {"quest_ids": []}); check("daily_award 1a ok", o.get("code") == 0, o)
    o, _ = c.req("req_get_all_dailyquest_award", {"quest_ids": []}); check("daily_award 2a -> 905", o.get("code") == 905, o)
    o, _ = c.req("req_mail_receive", {"mailid": 123}); check("mail_receive 1a ok", o.get("code") == 0, o)
    o, _ = c.req("req_mail_receive", {"mailid": 123}); check("mail_receive 2a -> 1202", o.get("code") == 1202, o)
    o, _ = c.req("req_td_event_start_stage", {}); o2, _ = c.req("req_td_event_settle_stage", {"is_win": True})
    o3, _ = c.req("req_td_event_settle_stage", {"is_win": True})
    check("td_settle 1a ok / 2a (mesmo start) -> 6158", o2.get("code") == 0 and o3.get("code") == 6158, (o2, o3))
    # ---- 7. save do cliente
    o, _ = c.req("req_save_client_data", {"data": {"law_point": 4242, "survivor": [{"sid": 1, "res601": 7}]}}); check("save_client_data code 0", o.get("code") == 0, o)
    # ---- 8. fila de obra (duracao real da cfg)
    t0 = int(time.time()); bid, qid = 302, 10001
    o, pu = c.req("req_upgrade_building", {"bid": bid, "qid": qid})
    c.sock.settimeout(3); qn = None
    try:
        while qn is None:
            r = c.read()                                   # notify_queue_update vem logo apos a resp
            if r["name"] == "notify_queue_update": qn = r["obj"]["queue_map"][0]
    except (socket.timeout, OSError): pass
    want = T.build_time(bid, 24)
    check("upgrade_building -> code 0 + notify_queue_update ocupada com duracao REAL da cfg",
          o.get("code") == 0 and qn and qn.get("total_time") == want and abs(qn["end_time"] - t0 - want) <= 2, (o, qn, want))
    o, _ = c.req("req_upgrade_building", {"bid": bid, "qid": qid}); check("upgrade na fila ocupada -> err_queue_busy (73)", o.get("code") == 73, o)
    c.close()
    # ---- 9. persistencia entre restarts (kill + novo processo)
    mock.stop(); time.sleep(0.3)
    sv = json.load(open(state, encoding="utf8"))
    check("account.json gravado (law_point do save do cliente = 4242)", sv.get("law_point") == 4242, sv.get("law_point"))
    mock = Mock(state)
    c = Cli(); c.login(); o, push = c.loaddata()
    check("restart: loaddata ok", o.get("code") == 0)
    d1 = balance(push, 102)
    check("restart: recurso 102 persistido (credito de hang/online/td/mail > inicial)", d1 is not None and d1 > d0 + 200000, (d0, d1))
    check("restart: gasto da loja persistido (109 = 26700 - 3750)", balance(push, 109) == 26700 - 3750, balance(push, 109))
    o, _ = c.req("req_climbtower_challenge", {"id": 40021}); check("restart: climbtower 40021 continua 16807", o.get("code") == 16807, o)
    o, _ = c.req("req_shop_buy", {"shop_id": 301, "goods_id": 5, "count": 1}); check("restart: contador da loja persiste -> 702", o.get("code") == 702, o)
    o, _ = c.req("req_get_all_dailyquest_award", {"quest_ids": []}); check("restart: daily continua 905", o.get("code") == 905, o)
    qs = next(p["obj"] for p in push if p["name"] == "notify_queue_info")["queue_map"]
    q1 = next(q for q in qs if q["qid"] == qid)
    check("restart: fila de obra persistida (end_time futuro, 302)", q1.get("end_time", 0) > t0 + want - 5, q1)
    o, _ = c.req("req_upgrade_building", {"bid": bid, "qid": qid}); check("restart: fila segue ocupada -> 73", o.get("code") == 73, o)
    c.close(); mock.stop(); time.sleep(0.3)

    # ---- 10. conclusao de obra (scale 0): timer -> notify_building_upgrade_finish; nivel persiste
    st2 = os.path.join(tmp, "b.json"); mock = Mock(st2, "--build-time-scale", "0")
    c = Cli(); c.login(); c.loaddata()
    o, pu = c.req("req_upgrade_building", {"bid": 302, "qid": 10001}); check("scale 0: upgrade code 0", o.get("code") == 0, o)
    got = []; c.sock.settimeout(3)
    try:
        while "notify_building_upgrade_finish" not in got: got.append(c.read()["name"])
    except (socket.timeout, OSError): pass
    check("obra conclui via timer: notify_building_upgrade_finish", "notify_building_upgrade_finish" in got, got)
    c.close(); c = Cli(); c.login(); _, push = c.loaddata()
    sh = next(p["obj"] for p in push if p["name"] == "notify_shelter_info")
    lv = next(b["base"]["lv"] for b in sh["building_info"] if b["bid"] == 302)
    check("nivel 302 = 24 no snapshot apos login novo", lv == 24, lv)
    c.close(); mock.stop()
finally:
    try: mock.stop()
    except Exception: pass
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\nRESULT INTEGRATE: {OK}/{OK + BAD} checks OK")
sys.exit(0 if BAD == 0 else 1)
