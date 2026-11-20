#!/usr/bin/env python3
"""Lote 3: sobe o mock em 30102, reenvia payloads REAIS do mock_live.log (repara os truncados em 100 chars),
valida code:0, campos obrigatorios e pushes esperados (todos decodificados pelo schema)."""
import sys, os, re, json, socket, threading, time, pickle
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import sproto_lib as L, mock_v4
ready = []; stop = threading.Event()
threading.Thread(target=mock_v4.serve, kwargs=dict(port=30102, fixture=os.path.join(HERE, "fixture_v4.json"), log=lambda s: None, ready=ready, stop=stop), daemon=True).start()
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
def req(name, obj, settle=0.3):
    global sess; sess += 1
    sock.sendall(L.frame(L.build_request(S, name, obj, sess, key=peer.key))); peer.note_request(sess, name)
    pushes = []; resp = None
    while True:
        r = read()
        if r["kind"] == "resp": resp = r
        else: pushes.append((r["name"], r["obj"]))
        if resp is not None:
            sock.settimeout(settle)
            try:
                while True:
                    r = read(); pushes.append((r["name"], r["obj"]))
            except (socket.timeout, TimeoutError): pass
            sock.settimeout(5); return resp, pushes
tr = pickle.load(open(os.path.join(HERE, "gw_transcript115.pkl"), "rb")); P0 = L.Peer(S)
for t, d, raw in tr:
    if d == "C>S":
        m = P0.parse(raw, d)
        if m["name"] == "loginauth": lo = m["obj"]; break
r, _ = req("loginauth", lo); peer.key = bytes.fromhex(r["obj"]["secret_key"])
real = {}
for ln in open(os.path.join(HERE, "mock_live.log"), encoding="utf8"):
    mm = re.match(r"\[RX #\d+\] (req_\w+) s=\d+ (\{.*)", ln)
    if mm: real.setdefault(mm.group(1), mm.group(2))
def ints(name, key): return [int(x) for x in re.findall(r'"%s": (\d+)' % key, real.get(name, ""))]
def loadj(name, fallback):
    try: return json.loads(real[name])
    except Exception: return fallback
FID = ints("req_dorm_bed_obtain", "k") or [312000101, 313000102]
dorm = {"fid_map": [{"k": k, "v": 0} for k in FID]}
rank = {"list_type": [{"type": t, "ext": {"aid": 0}} for t in (ints("req_rank_info", "type") or [1, 2, 3])], "kid": 0}
shops = {"arr_id": [int(x) for x in re.findall(r"\d+", real.get("req_shop_info_array", "{}").split("[", 1)[-1])] or [2601, 1401, 101]}
mcl = loadj("req_mail_cover_list", {"first_type": 30, "beginidx": 1, "endidx": 40})
real_src = {"req_dorm_bed_obtain", "req_schedule_info", "req_rank_info", "req_arena_report", "req_shop_info_array", "req_mail_cover_list", "req_mail_type_info", "req_hunting_tool_obtain"}
def pnames(p): return [n for n, _ in p]
# (req, payload, campos resp obrigatorios, pushes esperados, validador extra)
T = [
 ("req_dorm_bed_obtain", dorm, ["code", "fid_work_end_time"], ["notify_resource_update", "notify_shelter_info"],
  lambda o, p: len(o["fid_work_end_time"]) == len(FID)),
 ("req_schedule_info", {}, ["qtime_id", "start_time", "server_time"], ["notify_schedule_update"], lambda o, p: o["server_time"] >= o["start_time"]),
 ("req_shop_info", {"shop_id": 2201}, ["code", "info"], [], lambda o, p: o["info"]["id"] == 2201 and len(o["info"]["goods"]) > 0),
 ("req_shop_info", {"shop_id": 777}, ["code", "info"], [], lambda o, p: o["info"]["id"] == 777 and all(g["buy_count"] == 0 for g in o["info"]["goods"])),
 ("req_shop_info_array", shops, ["code", "map_info"], [], lambda o, p: len(o["map_info"]) == len(shops["arr_id"]) and all(s["goods"] for s in o["map_info"])),
 ("req_rank_info", rank, ["code", "list_info"], [], lambda o, p: len(o["list_info"]) == len(rank["list_type"]) and all("top" in x for x in o["list_info"])),
 ("req_arena_report", {}, ["code", "reports"], [], lambda o, p: o["reports"][0]["win"] is True),
 ("req_unlock_module", {"module": 5}, ["code"], [], None),
 ("req_guide_set_step", {"id": 1, "step": 3}, ["code"], [], None),
 ("req_produced_resource_need_update", {}, ["code"], ["notify_produced_resource_update"], lambda o, p: any(d["count"] > 0 for d in p[0][1]["data"])),
 ("req_mail_type_info", {}, ["code"], ["notify_mail_type_info_syn"], lambda o, p: len(p[0][1]["infolist"]) > 0),
 ("req_mail_cover_list", mcl, ["code", "coverlist"], [], lambda o, p: len(o["coverlist"]) >= 2 and o["coverlist"][0]["attach_statue"] == 1),
 ("req_hunting_tool_obtain", {"sid": 1}, ["code", "work_endtime"], ["notify_resource_update", "notify_shelter_info", "notify_survivor_info"], lambda o, p: o["work_endtime"] > 0),
 ("req_hunting_tool_obtain", {"sid": 1}, ["code", "work_endtime"], ["notify_shelter_info"], lambda o, p: True),  # 2o ciclo (repetivel)
]
ok = bad = 0
for name, obj, need, want, chk in T:
    try:
        r, p = req(name, obj); o = r["obj"]
        miss = [f for f in need if f not in o]
        nm = pnames(p); missp = [w for w in want if w not in nm]
        good = (o.get("code", 0) == 0) and not miss and not missp and (chk is None or bool(chk(o, p)))
        why = "" if good else f" miss={miss} missp={missp} code={o.get('code')}"
    except Exception as e:
        good, o, p, why = False, repr(e), [], " EXC"
    ok += good; bad += (not good)
    print("OK  " if good else "FAIL", name, ("[real]" if name in real_src else "[synt]"), json.dumps(obj)[:40], "->", json.dumps(o, ensure_ascii=False)[:130], "pushes:", pnames(p), why)
print(f"\nRESULT L3: {ok} OK, {bad} FAIL, de {ok+bad} testes")
stop.set(); sys.exit(1 if bad else 0)
