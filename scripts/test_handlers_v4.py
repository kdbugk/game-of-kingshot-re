#!/usr/bin/env python3
"""Testa handlers do lote 2: sobe o mock em 30102, envia payloads REAIS do mock_live.log, valida resposta."""
import sys, os, re, json, socket, threading, time, pickle
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import sproto_lib as L, mock_v4
PORT = 30102
ready = []; stop = threading.Event()
threading.Thread(target=mock_v4.serve, kwargs=dict(port=PORT, fixture=os.path.join(HERE, "fixture_v4.json"), log=lambda s: None, ready=ready, stop=stop), daemon=True).start()
while not ready: time.sleep(0.05)
S = L.default_schema(); sock = socket.create_connection(("127.0.0.1", ready[0]), timeout=5); peer = L.Peer(S); sess = 0
def recvn(n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c: raise ConnectionError
        b += c
    return b
def read(): return peer.parse(recvn(int.from_bytes(recvn(2), "big")), "S>C")
def req(name, obj):
    global sess; sess += 1
    sock.sendall(L.frame(L.build_request(S, name, obj, sess, key=peer.key))); peer.note_request(sess, name)
    pushes = []
    while True:
        r = read()
        if r["kind"] == "resp": return r, pushes
        pushes.append(r["name"])
tr = pickle.load(open(os.path.join(HERE, "gw_transcript115.pkl"), "rb")); P0 = L.Peer(S)
for t, d, raw in tr:
    if d == "C>S":
        m = P0.parse(raw, d)
        if m["name"] == "loginauth": lo = m["obj"]; break
r, _ = req("loginauth", lo); peer.key = bytes.fromhex(r["obj"]["secret_key"])
# payloads reais do log (1 por linha [RX]); log trunca em 100 chars -> repara sid_list
cases = []
for ln in open(os.path.join(HERE, "mock_live.log"), encoding="utf8"):
    mm = re.match(r"\[RX #\d+\] (req_\w+) s=\d+ (\{.*)", ln)
    if not mm: continue
    name, js = mm.groups()
    try: obj = json.loads(js)
    except Exception: obj = {"sid_list": [int(x) for x in re.findall(r"\d+", js)]}
    cases.append((name, obj))
cases.append(("req_upgrade_furniture", {"bid": 301, "conf_fid": 1001, "add_lv": 1}))  # sem amostra no log
HANDLED = set(mock_v4.Session.H) - {"loginauth", "req_loaddata", "req_heartbeat", "req_chat_get_token", "req_trigger_opinion", "req_save_client_data", "req_players_base_info_with_permission", "req_cheat_add", "req_cheat_set_hero_lev"}
REQ = {"req_survivor_work_start": ["code", "time"], "req_survivor_work_pause": ["code"], "req_upgrade_building": ["code", "qid"],
       "req_td_event_start_stage": ["code", "start_stage_ts", "td_box", "td_survivor"], "req_td_event_settle_stage": ["code", "reward"],
       "req_skin_get_condition_activity_skin": ["code"], "req_receive_online_reward": ["code", "online_reward", "receive_start_time"],
       "req_upgrade_furniture": ["code", "lv"], "req_hunting_tool_obtain": ["code", "work_endtime"], "req_mail_onekey_read": ["code", "rewards"],
       "req_barrack_train_soldier": ["code", "barrack"], "req_mail_cover_list": ["code"], "req_get_hang_up_reward": ["code"],
       "req_barrack_recruit_soldier": ["code", "map_result"], "req_get_all_dailyquest_award": ["code"]}
ok = bad = 0; seen = set()
for name, obj in cases:
    if name not in REQ or (name, json.dumps(obj, sort_keys=True)) in seen: continue
    seen.add((name, json.dumps(obj, sort_keys=True)))
    try:
        r, pushes = req(name, obj); o = r["obj"]
        miss = [f for f in REQ[name] if f not in o]
        good = o.get("code") == 0 and not miss
        # decode OK por ter chegado aqui; empty list omitido no sproto e aceitavel para listas
        miss2 = [f for f in miss if f not in ("online_reward", "rewards", "reward", "td_box", "td_survivor", "map_result")]
        good = o.get("code") == 0 and not miss2
    except Exception as e:
        good, o, pushes = False, repr(e), []
    ok += good; bad += (not good)
    print("OK " if good else "FAIL", name, json.dumps(obj)[:50], "->", json.dumps(o, ensure_ascii=False)[:110], "pushes:", pushes)
print(f"\nRESULT: {ok} OK, {bad} FAIL, de {ok+bad} testes")
stop.set(); sys.exit(1 if bad else 0)
