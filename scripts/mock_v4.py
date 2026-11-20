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
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server"))   # modulos de estado/regras/tempo
try:
    import server_state as SS, server_rules as R, server_timers as T
    INTEGRATED = True
except ImportError as _e:                      # sem os modulos: mock volta ao comportamento antigo (burst cru)
    INTEGRATED = False

SHOWCASE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PUSH_NOW")

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

AUTO = {"on": True, "window": 5.0, "max": 8}   # --auto-notify on/off; dedup por notify (s); teto por req
AUTO_SKIP = {"req_heartbeat", "req_save_client_data", "req_chat_get_token", "req_cheat_add", "req_cheat_set_hero_lev",
             "req_trigger_opinion", "req_loaddata", "req_players_base_info_with_permission",
             "req_dun163_risk_check", "req_dun163_doubtful_check", "req_dun163_get_config",
             "req_dorm_bed_obtain", "req_schedule_info", "req_mail_type_info"}   # L3: handlers que ja empurram o proprio estado (auto re-pushava offline_info/survivor_info stale)
def load_req_notify(path=os.path.join(HERE, "MAPEAMENTO_REQ_NOTIFY.tsv")):
    d = {}
    if os.path.exists(path):
        for ln in open(path, encoding="utf8").read().splitlines()[1:]:
            r, mod, n, *_ = ln.split("	"); d.setdefault(r, []).append(n)
    return d
REQ_NOTIFY = load_req_notify()

HANG_MIN_INTERVAL = 60        # s entre claims de hang-up (errcodes nao tem *_already_get p/ hang: usa 4004 interval_not_enough)
ONLINE_INTERVAL = 3600        # receive_start_time do online reward
BUILD_SCALE = {"v": 1.0}      # --build-time-scale (duracao real da cfg x fator)
DEFAULT_STATE = os.path.join(HERE, "account.json")

class Ctx:
    """Estado compartilhado do servidor integrado: caminho de save, contas em memoria (1 por uid), lock global."""
    def __init__(self, state_path=DEFAULT_STATE, sequencer=True):
        self.state_path = state_path; self.sequencer = sequencer
        self.accts = {}; self.lock = threading.RLock()

    def path_for(self, uid): return self.state_path.format(uid=uid) if "{uid}" in self.state_path else self.state_path

    def account(self, uid, fx, log):
        if uid in self.accts: return self.accts[uid]
        path = self.path_for(uid); a = None
        if os.path.exists(path):
            try: a = SS.Account.load(path); log(f"[STATE] conta {uid} carregada de {path} (rev {a.meta.get('revision')})")
            except Exception as e: log(f"[STATE] {path} ilegivel ({e!r}) -> seed novo")
        if a is None:
            a = SS.Account.from_seed(fx); log(f"[STATE] conta {uid} criada do fixture -> {path}")
        self.accts[uid] = a
        return a

class Session:
    def __init__(self, conn, addr, S, fx, key, log, ctx=None):
        self.conn, self.addr, self.S, self.fx, self.key, self.log = conn, addr, S, fx, key, log
        self.ctx = ctx; self.acct = None; self.replay = None; self.qm = None; self.closed = False
        self.seq = R.Session() if (ctx and ctx.sequencer) else None
        self.lk = ctx.lock if ctx else threading.RLock()
        self.peer = L.Peer(S, key); self.t0 = time.time(); self.n = 0
        self.stats = {}
        self.gm_items = {}   # GM (lab): inventário do sandbox
        self.gm_hero = {}    # GM (lab): níveis de herói do sandbox
        self.last_push = {}; self.auto_pushed = []
        self.surv_work = set(); self.bld_lv = {}; self.fur_lv = {}
        self.fid_wet = {}    # L3: fid -> work_endtime (camas type1 / ferramentas de caca type18)
        self.prod_extra = {} # L3: recurso produzido -> acumulado (sandbox)
        self.mail_seq = 0

    def now(self): return int(time.time())   # relógio REAL (o T0 sintético mandava work_endtime no passado!)

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

    # ---- integracao: estado persistente / regras / filas
    def today(self): return time.strftime("%Y-%m-%d", time.localtime(self.now()))

    def persist(self):
        a = self.acct
        if a is None: return
        a.replay_done = self.replay.dump(); self.sync_queues()
        a.save(self.ctx.path_for(a.meta["uid"]))

    def replay_err(self, kind, key):
        """anti-replay: None (ok, ja marca como feito) ou codigo."""
        if self.replay is None: return None
        return self.replay.check_and_mark(kind, str(key))

    def give(self, items, push=False):
        """items [(id,count)] -> credita na conta (persistente). push=True tambem notifica o delta."""
        if self.acct is None: return
        self.acct.grant([(i, c) for i, c in items])
        if push: self.push_res_add(items)

    def init_account(self, uid):
        a = self.ctx.account(uid, self.fx, self.log); self.acct = a
        self.replay = R.ReplayRegistry()
        for k, v in (getattr(a, "replay_done", None) or {}).items():
            if k in R.REPLAY_ERR: self.replay._done[k] = set(v)
        if getattr(a, "replay_day", None) != self.today():       # virada de dia: zera recompensas diarias
            self.replay.reset_daily(); a.replay_day = self.today()
        self.qm = T.QueueManager()
        tasks = getattr(a, "queue_tasks", None) or {}
        for qid, st in a.queues.items():
            q = self.qm.add(qid, (st.get("base") or {}).get("qtype"))
            q.purchased_endtime = (st.get("base") or {}).get("purchased_endtime", -1)
            t = tasks.get(str(qid))
            if t and st.get("end_time"): q.task = dict(t)
        a.meta["login_ts"] = a.meta["last_login"] = self.now()
        self.persist()

    def sync_queues(self):
        a = self.acct
        if a is None or self.qm is None: return
        a.queue_tasks = {str(q.qid): q.task for q in self.qm.queues.values() if q.task}
        for qid, q in self.qm.queues.items():
            st = q.status(); d = dict(a.queues.get(qid, {})); d.pop("end_time", None); d.pop("total_time", None)
            d.update(qid=qid, status=st["status"], base={"qtype": q.qtype, "purchased_endtime": q.purchased_endtime})
            if q.task: d["end_time"] = st["end_time"]; d["total_time"] = st["total_time"]
            a.queues[qid] = d

    def settle_queues(self, push=True):
        """Conclui obras cujo end_time passou (online via timer, ou no login). Aplica nivel + notifies."""
        if self.acct is None: return
        with self.lk:
            for q in list(self.qm.queues.values()):
                if q.task and q.status()["status"] == T.STATUS_DONE:
                    pre = q.to_notify(); t = q.collect()
                    bid, lv = t.get("bid"), t.get("level")
                    if bid in self.acct.buildings and lv: self.acct.set_building_lv(bid, lv)
                    self.persist()
                    if push and not self.closed:
                        try:
                            self.push("notify_queue_update", pre)
                            self.push("notify_building_upgrade_finish", {"bid": bid, "lv": lv, "furniture_list": [], "mode": 0})
                            self.push("notify_queue_update", q.to_notify())
                            self.push_shelter()
                        except OSError: pass
                    self.log(f"[SBX] obra {bid} -> lv {lv} concluida (fila {q.qid})")

    # ---- handlers sintéticos
    def h_loginauth(self, m):
        r = dict(self.fx["login_resp"]) if self.fx else {"code": 0, "serverid": 931, "uid": 40444746}
        r["secret_key"] = self.key.hex()
        r["server_ts"] = self.now()
        if "underage_info" in r: r["underage_info"] = dict(r["underage_info"], server_ts=self.now())
        r["code"] = 0
        if self.ctx is not None and self.fx and INTEGRATED: self.init_account(r.get("uid", 0))
        if self.seq: self.seq.login_ok()
        self.reply(m, r)

    def h_loaddata(self, m):
        if self.acct is not None:
            self.settle_queues(push=False); self.persist()
            for name, obj in self.acct.snapshot_notifies(): self.send(L.build_push(self.S, name, obj))
            self.reply(m, {"code": 0}); return
        for name, obj in (self.fx["burst"] if self.fx else []):
            obj = json.loads(json.dumps(obj))
            if name == "notify_game_init": obj["servertime"] = self.now()
            self.send(L.build_push(self.S, name, obj))
        self.reply(m, {"code": 0})

    def h_heartbeat(self, m): self.reply(m, {"time": self.now()})
    def h_opinion(self, m): self.reply(m, {"code": 0})
    def h_save(self, m):
        if self.acct is not None:
            self.acct.apply_client_save(m["obj"]); self.persist()
        self.reply(m, {"code": 0})

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

    # ---- ACOES: handlers com recompensa real (sandbox generoso)
    def h_hangup(self, m):
        rew = [{"id": 102, "value": 100000}, {"id": 103, "value": 50000}, {"id": 105, "value": 20000}]
        if self.acct is not None:
            if self.now() - getattr(self.acct, "hang_last", 0) < HANG_MIN_INTERVAL:
                return self.reply(m, {"code": R.code("err_hang_up_reward_interval_not_enough")})
            self.acct.hang_last = self.now(); self.give([(r["id"], r["value"]) for r in rew]); self.persist()
        self.reply(m, {"code": 0, "hang_start_time": self.now() - 3600, "current_reward": rew, "expert_reward": []})

    def h_hangup_view(self, m):
        rew = [{"id": 102, "value": 100000}, {"id": 103, "value": 50000}]
        self.reply(m, {"open_hang_up_reward_view_time": self.now(), "current_reward": rew, "expert_reward": []})

    def h_online_reward(self, m):
        if self.acct is not None:
            if self.now() < getattr(self.acct, "online_next", 0):
                return self.reply(m, {"code": R.code("err_online_reward_not_exist")})
            self.acct.online_next = self.now() + ONLINE_INTERVAL
            self.give([(101, 500), (102, 20000)]); self.persist()
        self.reply(m, {"code": 0, "online_reward": [{"id": 101, "count": 500}, {"id": 102, "count": 20000}], "receive_start_time": self.now() + ONLINE_INTERVAL})

    def h_daily_award(self, m):
        e = self.replay_err("daily_all", "1")
        if e is not None: return self.reply(m, {"code": e})
        self.persist()
        self.reply(m, {"code": 0, "integral": 999, "geted_boxid": [], "expert_effect_map": []})

    def h_recruit(self, m):
        res = [{"code": 0, "bid": b, "soldier_id": 601, "soldier_num": 100} for b in (m["obj"].get("arr_bid") or [])]
        self.reply(m, {"code": 0, "map_result": res})

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

    # ---- LOTE 2: familias que o operador usou e nao funcionavam (sandbox generoso)
    def push(self, name, obj):
        self.send(L.build_push(self.S, name, obj)); self.last_push[name] = time.time()
        self.stats["push"] = self.stats.get("push", 0) + 1

    def push_survivor_info(self, sid=None, status=None):
        o = self.burst_tpl("notify_survivor_info")
        if o is None: return
        if sid is not None:
            for s in o.get("survivor_list", []):
                if s.get("sid") == sid and status is not None: s["status"] = status
        self.push("notify_survivor_info", o)

    def h_survivor_work_start(self, m):
        sid = m["obj"].get("sid"); self.surv_work.add(sid); self.reply(m, {"code": 0, "time": self.now()})
        self.push_survivor_info(sid, 2)

    def h_survivor_work_pause(self, m):
        for s in m["obj"].get("sid_list") or []: self.surv_work.discard(s)
        self.reply(m, {"code": 0})
        self.push_survivor_info()

    def burst_tpl(self, name):
        for n, o in self.burst_list():
            if n == name: return json.loads(json.dumps(o))
        return None

    def burst_list(self):
        """notifies base: snapshot da conta (estado vivo) se integrado; senao burst cru do fixture."""
        if self.acct is not None: return self.acct.snapshot_notifies()
        return (self.fx or {}).get("burst", [])

    def push_shelter(self):
        """Reenvia notify_shelter_info com work_endtime (camas/caca) e niveis de predio do sandbox aplicados."""
        o = self.burst_tpl("notify_shelter_info")
        if o is None: return
        for b in o.get("building_info", []):
            if self.acct is None and b.get("bid") in self.bld_lv: b["base"]["lv"] = self.bld_lv[b["bid"]]
            for f in b.get("base", {}).get("furniture", []) or []:
                if f.get("fid") in self.fid_wet: f["work_endtime"] = self.fid_wet[f["fid"]]
        self.push("notify_shelter_info", o)

    def push_res_add(self, items):
        self.push("notify_resource_update", {"type": "add", "data": [{"id": i, "count": c} for i, c in items]})

    def push_produced(self, items):
        tpl = {d["id"]: d for d in (self.burst_tpl("notify_produced_resource_init") or {}).get("data", [])}
        out = []
        for i, c in items:
            self.prod_extra[i] = self.prod_extra.get(i, 0) + c
            d = {"id": i, "count": tpl.get(i, {}).get("count", 0) + self.prod_extra[i]}
            if tpl.get(i, {}).get("workstations"): d["workstations"] = tpl[i]["workstations"]
            out.append(d)
        self.push("notify_produced_resource_update", {"data": out})

    def h_hunting_tool_obtain(self, m):
        # receita do servidor REAL (cap_combat2): push notify_produced_resource_update ANTES da resp
        sid = m["obj"].get("sid"); end = self.now() + 30
        self.push("notify_produced_resource_update", {"data": [{"id": 192, "count": 422569387}, {"id": 102, "count": 16887448}]})
        self.reply(m, {"code": 0, "work_endtime": end})
        fid = None
        for s_ in (self.burst_tpl("notify_survivor_info") or {}).get("survivor_list", []):
            if s_.get("sid") == sid: fid = s_.get("fid_work")
        if fid: self.fid_wet[fid] = end
        self.push_res_add([(101, 5000), (102, 20000)])
        self.push_shelter()
        self.push_survivor_info(sid, 2)

    # ---- LOTE 3
    def h_dorm_bed_obtain(self, m):
        end = self.now() + 30; res = []
        for kv in m["obj"].get("fid_map") or []:
            fid = kv.get("k"); self.fid_wet[fid] = end; res.append({"k": fid, "v": end})
        self.reply(m, {"code": 0, "fid_work_end_time": res})
        self.push_res_add([(101, 2000 * max(1, len(res))), (102, 5000 * max(1, len(res)))])
        self.push_shelter()

    def h_schedule_info(self, m):
        n = (self.now() - SERVER_T0) // 3600
        qid = (21 + n) % 24; st = SERVER_T0 - 13 + n * 3600
        self.reply(m, {"qtime_id": qid, "start_time": st, "server_time": self.now()})
        self.push("notify_schedule_update", {"qtime_id": qid, "start_time": st, "server_time": self.now()})

    def mk_shop(self, sid, ngoods=8):
        tpl = ((self.fx or {}).get("templates") or {})
        for g in (tpl.get("req_shop_info_array") or {}).get("map_info", []):
            if g.get("id") == sid: return json.loads(json.dumps(g))
        if (tpl.get("req_shop_info") or {}).get("info", {}).get("id") == sid: return json.loads(json.dumps(tpl["req_shop_info"]["info"]))
        # sintetico (padrao observado: conf_id = shop*100000 + 10000 + grid*100 + 1); buy_count=0 => sem limite consumido
        return {"id": sid, "refresh_times": 0, "first_refresh_time": 0, "expert_count": 0, "last_refresh_ts": self.now(),
                "goods": [{"id": g, "buy_count": 0, "grid_id": g, "conf_id": sid * 100000 + 10000 + g * 100 + 1} for g in range(1, ngoods + 1)]}

    def shop_of(self, sid):
        if self.acct is None: return self.mk_shop(sid)
        if sid not in self.acct.shops: self.acct.shops[sid] = self.mk_shop(sid)
        return json.loads(json.dumps(self.acct.shops[sid]))

    def h_shop_info(self, m): self.reply(m, {"code": 0, "info": self.shop_of(m["obj"].get("shop_id") or 101)})

    def h_shop_info_array(self, m):
        self.reply(m, {"code": 0, "map_info": [self.shop_of(i) for i in (m["obj"].get("arr_id") or [])]})

    def h_shop_buy(self, m):
        if self.acct is None: return self.h_default(m)
        o = m["obj"]; sid, gid, cnt = o.get("shop_id"), o.get("goods_id"), o.get("count", 1)
        self.shop_of(sid)                                   # garante a loja na conta
        g = next((x for x in self.acct.shops[sid]["goods"] if x["id"] == gid), None)
        if g is None:                                       # fallback: goods_id = conf_id de algum slot da loja
            g = next((x for x in self.acct.shops[sid]["goods"] if x.get("conf_id") == gid), None)
        conf = g["conf_id"] if g else gid                   # goods_id = slot da loja (id) ou conf_id
        if g is None: return self.reply(m, {"code": R.code("err_shop_not_found_goods")})
        e = R.check_shop_buy(sid, conf, cnt, g.get("buy_count", 0))        # 701 / 702 / 2
        cfg = R.GOODS.get(str(conf)) or {}
        custo = {}
        if e is None and cfg.get("price") and cfg.get("currency") is not None:
            custo = {int(cfg["currency"]): int(cfg["price"]) * cnt}
            e = R.apply_cost({**self.acct.resources, **self.acct.backpack}, custo)      # 51 se faltar saldo
        if e is not None: return self.reply(m, {"code": e})
        if custo: self.acct.spend(custo)
        self.acct.shop_buy(sid, g["id"], cnt); gid = g["id"]
        item = cfg.get("item_id")
        if item: self.acct.grant([(item, cnt)])
        self.persist()
        if custo: self.push("notify_resource_update", {"type": "del", "data": [{"id": i, "count": c} for i, c in custo.items()]})
        if item: self.push("notify_backpack_update", {"type": "add", "data": [{"id": item, "count": cnt}]})
        self.reply(m, {"code": 0, "goods": next((x for x in self.acct.shops[sid]["goods"] if x["id"] == gid), {"id": gid, "conf_id": conf, "buy_count": cnt})})

    def h_rank_info(self, m):
        out = []; now = self.now()
        for i, rt in enumerate(m["obj"].get("list_type") or []):
            t = rt.get("type", 1)
            out.append({"type": t, "ext": dict(rt.get("ext") or {"aid": 0}), "self_rank": 1, "count": 100,
                        "top": {"key": 40444746, "value": [999999999 - t, now]}, "self_value": [999999999 - t, now]})
        self.reply(m, {"code": 0, "list_info": out})

    def h_arena_report(self, m):
        t = self.now()
        self.reply(m, {"code": 0, "reports": [{"id": 1, "atk_id": 40444746, "atk_score_origin": 1000, "atk_score_new": 1030,
            "def_type": 1, "def_id": 1, "def_score_origin": 1000, "def_score_new": 970, "win": True, "revenged": False,
            "atk_attack_power": 5000000, "atk_defence_power": 4000000, "def_defence_power": 1000000, "time": t - 600}]})

    def h_ok(self, m): self.reply(m, {"code": 0})

    def h_produced_need_update(self, m):
        self.reply(m, {"code": 0})
        self.push_produced([(102, 100000), (103, 50000), (195, 20000)])

    def h_mail_type_info(self, m):
        self.reply(m, {"code": 0})
        o = self.burst_tpl("notify_mail_type_info_syn") or {"infolist": []}
        for it in o["infolist"]: it["can_get_attach"] = 1; it["un_readnum"] = max(it.get("un_readnum", 0), 2)
        self.push("notify_mail_type_info_syn", o)

    def mk_mail(self, ft, st):
        self.mail_seq += 1; mid = 10238564363977120 + self.mail_seq
        return {"mailid": mid, "mailid_new": str(mid), "isread": 0, "send_time": self.now() - 60 * self.mail_seq, "first_type": ft,
                "second_type": st, "attach_statue": 1, "deadline": 0, "iscollect": 0, "attach_deadline": 0, "param": "80"}

    def h_mail_cover_list(self, m):
        o = m["obj"]; ft = o.get("first_type") or 10
        b, e = o.get("beginidx") or 1, o.get("endidx") or 40
        lst = [self.mk_mail(ft, 1), self.mk_mail(ft, 1)][: max(0, e - b + 1)]
        tpl = ((self.fx or {}).get("templates") or {}).get("req_mail_cover_list", {}).get("coverlist", [])
        lst += [c for c in tpl if c.get("first_type") == ft][:1]
        self.reply(m, {"code": 0, "coverlist": lst})

    def h_upgrade_building(self, m):
        o = m["obj"]; bid = o.get("bid"); qid = o.get("qid") or 10001
        if self.acct is not None:
            q = self.qm.queues.get(qid) or self.qm.add(qid)
            if q.busy(): return self.reply(m, {"code": R.code("err_queue_busy")})
            lv = max(self.acct.building_lv(bid), 0) + 1
            try: dur = T.build_time(bid, lv)
            except KeyError: dur = 1; self.log(f"[SBX] sem costTime p/ build {bid} lv {lv}: 1s")
            dur = int(dur * BUILD_SCALE["v"])
            q.start(bid, qid, dur, level=lv); self.persist()
            self.reply(m, {"code": 0, "qid": qid, "expert_reduce_time": 0})
            self.push("notify_queue_update", q.to_notify())
            self.log(f"[SBX] building {bid} -> lv {lv} em {dur}s (fila {qid})")
            tm = threading.Timer(dur + 0.2, self.settle_queues); tm.daemon = True; tm.start()
            return
        base = ((self.fx or {}).get("player_base") or {}).get("stove_lv", 1) if bid == 301 else 1
        lv = self.bld_lv.get(bid, base) + 1; self.bld_lv[bid] = lv
        self.reply(m, {"code": 0, "qid": qid, "expert_reduce_time": 0})
        t = self.now()
        # UI depende de notify_*: fila ocupada -> obra concluida (instantanea no sandbox) -> fila livre
        self.push("notify_queue_update", {"queue_map": [{"qid": qid, "status": 2, "end_time": t + 1, "total_time": 1, "base": {"qtype": 1, "purchased_endtime": -1}}]})
        self.push("notify_building_upgrade_finish", {"bid": bid, "lv": lv, "furniture_list": [], "mode": 0})
        self.push("notify_queue_update", {"queue_map": [{"qid": qid, "status": 1, "base": {"qtype": 1, "purchased_endtime": -1}}]})
        self.log(f"[SBX] building {bid} -> lv {lv}")

    def h_upgrade_furniture(self, m):
        o = m["obj"]; k = (o.get("bid"), o.get("conf_fid"))
        lv = self.fur_lv.get(k, 1) + max(1, o.get("add_lv") or 1); self.fur_lv[k] = lv
        self.reply(m, {"code": 0, "lv": lv})

    def h_td_start(self, m):
        if self.acct is not None: self.acct.td_start_ts = self.now(); self.persist()
        box = [{"box_id": i, "pos": {"x": 3 + i, "y": 4}, "reward": [{"id": 102, "count": 50000}]} for i in (1, 2, 3)]
        self.reply(m, {"code": 0, "start_stage_ts": self.now(), "td_box": box,
                       "td_survivor": [{"type": 1, "sid": [1, 2, 3, 4]}, {"type": 2, "sid": [6, 203, 205]}]})

    def h_td_settle(self, m):
        win = bool(m["obj"].get("is_win"))
        rew = [{"id": 101, "count": 500}, {"id": 102, "count": 200000}, {"id": 103, "count": 100000}, {"id": 105, "count": 50000}] if win else [{"id": 102, "count": 10000}]
        if self.acct is not None:
            st = getattr(self.acct, "td_start_ts", 0)          # 1 settle por start_stage; sem start previo = livre (sandbox)
            e = self.replay_err("reward_generic", f"td:{st}") if st else None
            if e is not None: return self.reply(m, {"code": e})
            self.give([(r["id"], r["count"]) for r in rew]); self.persist()
        self.reply(m, {"code": 0, "reward": rew})

    def h_skin_cond(self, m): self.reply(m, {"code": 0, "show_skins": [], "sale_type_skins": []})

    def h_mail_onekey(self, m):
        self.reply(m, {"code": 0, "rewards": [{"id": 101, "count": 100}, {"id": 102, "count": 50000}], "readlist": []})

    def h_train(self, m):
        o = m["obj"]; t = self.now()
        self.reply(m, {"code": 0, "barrack": {"bid": 0, "soldier_id": o.get("soldier_id"), "soldier_num": o.get("soldier_num"),
                                              "finish_ts": t + 1, "total_time": 1, "from_soldier_id": 0, "qid": 0}})

    def h_cover(self, m): self.reply(m, {"code": 0, "coverlist": []})

    # ---- AUTO-NOTIFY: após qualquer req_ respondido, re-pusha os notify_* do MESMO módulo Lua (templates do burst)
    def auto_reflect(self, req):
        if not AUTO["on"] or req in AUTO_SKIP or not req.startswith("req_"): return
        names = REQ_NOTIFY.get(req)
        if not names: return
        burst = self.burst_idx()
        now = time.time(); sent = 0
        for n in names:
            if n not in burst: self.stats["auto_notpl"] = self.stats.get("auto_notpl", 0) + 1; continue
            if now - self.last_push.get(n, 0) < AUTO["window"]: self.stats["auto_dedup"] = self.stats.get("auto_dedup", 0) + 1; continue
            if sent >= AUTO["max"]: self.stats["auto_cap"] = self.stats.get("auto_cap", 0) + 1; break
            self.push(n, json.loads(json.dumps(burst[n]))); sent += 1
            self.auto_pushed.append((req, n)); self.stats["auto"] = self.stats.get("auto", 0) + 1
        if sent: self.log(f"[AUTO] {req} -> {sent} notify")

    def burst_idx(self):
        if self.acct is not None or not hasattr(self, "_bidx"):
            self._bidx = {}
            for n, o in self.burst_list(): self._bidx.setdefault(n, o)
        return self._bidx

    def h_default(self, m):
        tpl = ((self.fx or {}).get("templates") or {}).get(m["name"])
        if tpl is not None: self.reply(m, tpl); self.stats["tpl"] = self.stats.get("tpl", 0) + 1; return
        spec = self.S.c2s_by_name[m["name"]]["response"]
        fields = self.S.fields_of(spec)
        self.stats["dflt"] = self.stats.get("dflt", 0) + 1
        if spec is None: return                     # protocolo sem response: não responde
        self.reply(m, {"code": 0} if any(f["name"] == "code" for f in fields) else {})

    def h_mail_receive(self, m):
        # PROVA VISUAL: claim de anexo -> popup de recompensa
        rew = [{"id": 101, "count": 999}, {"id": 102, "count": 99999}, {"id": 272, "count": 50}]
        if self.acct is not None:
            o = m["obj"]; e = self.replay_err("mail_attach", o.get("mailid_new") or o.get("mailid"))
            if e is not None: return self.reply(m, {"code": e})
            self.give([(r["id"], r["count"]) for r in rew]); self.persist()
        self.reply(m, {"code": 0, "rewards": rew})
        self.push("notify_backpack_update", {"type": "add", "data": [{"count": 50, "id": 272}]})

    def h_climbtower(self, m):
        # PROVA VISUAL: o servidor 'disputa' a batalha (shape real da produção, vitória)
        o = m["obj"]; fid = o.get("id", 40021)
        if self.acct is not None:
            e = self.replay_err("climbtower_level", fid)
            if e is not None: return self.reply(m, {"code": e})
            self.give([(272, 100), (271, 5)]); self.acct.tower_pass(4, fid + 1); self.persist()
        atk = {"formation_id": 1, "soldier_info": [{"k": 21000, "v": 51400}, {"k": 31000, "v": 46276}, {"k": 11000, "v": 21048}]}
        df = {"formation_id": 1, "soldier_info": [{"v": 0, "k": 1242000}, {"v": 0, "k": 1243000}, {"v": 0, "k": 1241000}]}
        self.reply(m, {"code": 0, "is_win": True,
                       "normal_reward": [{"id": 272, "count": 100}, {"id": 271, "count": 5}],
                       "battle_result": {"atk_power": 20761488, "def_power": 12355200,
                                          "round_result": [{"ret": 1, "atk": atk, "def": df}]},
                       "formation_prefab": [{"id": 1, "prefab": {"soldier": [{"k": 21000, "v": 51400}, {"k": 31000, "v": 51400}, {"k": 11000, "v": 51400}]}}]})
        self.push("notify_climbtower_currency_update", {"currency": 99999})
        self.push("notify_backpack_update", {"type": "add", "data": [{"count": 1, "id": 500230}, {"count": 100, "id": 272}]})
        self.push("notify_climbtower_tower_update", {"total_passed_cnt": 200, "tower_info": {"id": 4, "daily_fail": 0, "sweep_cnt": 0, "unread_report_cnt": 0, "completed_cnt": 1, "cur_passed_level": fid + 1, "his_passed_level": fid + 1}})

    H = {"loginauth": h_loginauth, "req_loaddata": h_loaddata, "req_heartbeat": h_heartbeat,
         "req_trigger_opinion": h_opinion, "req_save_client_data": h_save,
         "req_players_base_info_with_permission": h_players,
         "req_cheat_add": h_cheat_add, "req_cheat_set_hero_lev": h_cheat_hero,
         "req_chat_get_token": h_chat_token,
         "req_get_hang_up_reward": h_hangup, "req_open_hang_up_reward_view": h_hangup_view,
         "req_receive_online_reward": h_online_reward, "req_get_all_dailyquest_award": h_daily_award,
         "req_barrack_recruit_soldier": h_recruit,
         "req_survivor_work_start": h_survivor_work_start, "req_survivor_work_pause": h_survivor_work_pause,
         "req_hunting_tool_obtain": h_hunting_tool_obtain, "req_upgrade_building": h_upgrade_building,
         "req_upgrade_furniture": h_upgrade_furniture, "req_td_event_start_stage": h_td_start,
         "req_td_event_settle_stage": h_td_settle, "req_skin_get_condition_activity_skin": h_skin_cond,
         "req_mail_onekey_read": h_mail_onekey, "req_barrack_train_soldier": h_train,
         "req_dorm_bed_obtain": h_dorm_bed_obtain, "req_schedule_info": h_schedule_info,
         "req_shop_info": h_shop_info, "req_shop_buy": h_shop_buy, "req_shop_info_array": h_shop_info_array, "req_rank_info": h_rank_info,
         "req_arena_report": h_arena_report, "req_unlock_module": h_ok, "req_guide_set_step": h_ok,
         "req_mail_receive": h_mail_receive, "req_climbtower_challenge": h_climbtower,
         "req_produced_resource_need_update": h_produced_need_update, "req_mail_type_info": h_mail_type_info,
         "req_mail_cover_list": h_mail_cover_list}

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
                with self.lk:
                    if self.seq is not None and m["name"] != "loginauth":
                        cod = self.seq.check(m["name"])          # sequenciador: acao antes do loaddata -> 2
                        if cod is not None:
                            self.log(f"[SEQ] {m['name']} bloqueado: code {cod}"); self.reply(m, {"code": cod}); continue
                    try:
                        self.H.get(m["name"], Session.h_default)(self, m)
                        self.auto_reflect(m["name"])
                    except (ConnectionError, OSError): raise
                    except Exception as e:
                        import traceback; self.log(f"[handler-err] {m['name']}: {e!r}\n{traceback.format_exc()}")
        except (ConnectionError, OSError) as e:
            self.log(f"[conn-err] {e}")
        finally:
            self.closed = True
            self.log(f"[end] {self.stats}"); self.conn.close()

def serve(port=30101, key=None, fixture=None, log=print, ready=None, stop=None, integrate=False, state=DEFAULT_STATE, sequencer=True):
    S = L.default_schema()
    fx = json.load(open(fixture, encoding="utf8")) if fixture and os.path.exists(fixture) else None
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1" if ready is not None else "0.0.0.0", port)); srv.listen(8)
    if ready is not None: ready.append(srv.getsockname()[1]); srv.settimeout(0.2)
    log(f"[mock v4] porta {srv.getsockname()[1]} fixture={'sim' if fx else 'NAO'}")

    ctx = Ctx(state, sequencer) if (integrate and INTEGRATED and fx) else None
    log(f"[mock v4] integracao={'ON state=' + state if ctx else 'OFF'} sequencer={'ON' if ctx and sequencer else 'OFF'}")
    live = {"sess": None}  # sessao mais recente (para o showcase)

    def showcase_loop():
        while not (stop and stop.is_set()):
            time.sleep(0.5)
            try:
                if os.path.exists(SHOWCASE_FILE):
                    os.remove(SHOWCASE_FILE)
                    s = live.get("sess")
                    if s is not None:
                        s.push("notify_produced_resource_update", {"data": [
                            {"id": 102, "count": 999999999},
                            {"id": 103, "count": 888888888},
                            {"id": 105, "count": 777777777}]})
                        s.push("notify_backpack_update", {"type": "add", "data": [{"count": 99, "id": 271}, {"count": 999, "id": 500230}]})
                        log("[SHOWCASE] pushes enviados pra sessao ativa")
            except Exception as e:
                log(f"[showcase-err] {e!r}")
    threading.Thread(target=showcase_loop, daemon=True).start()
    while not (stop and stop.is_set()):
        try: conn, addr = srv.accept()
        except socket.timeout: continue
        k = key or bytes(random.randrange(256) for _ in range(4))
        _s = Session(conn, addr, S, fx, k, log, ctx)
        live["sess"] = _s
        threading.Thread(target=_s.run, daemon=True).start()
    srv.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=30101)
    ap.add_argument("--key", default="random")
    ap.add_argument("--fixture", default=os.path.join(HERE, "fixture_v4.json"))
    ap.add_argument("--export-fixture", action="store_true")
    ap.add_argument("--auto-notify", choices=["on", "off"], default="on")
    ap.add_argument("--auto-window", type=float, default=5.0)
    ap.add_argument("--auto-max", type=int, default=8)
    ap.add_argument("--state", default=DEFAULT_STATE, help="JSON da conta (aceita {uid}); default work/mockserver/account.json")
    ap.add_argument("--no-state", action="store_true", help="desliga integracao (burst cru do fixture, sem regras/persistencia)")
    ap.add_argument("--no-sequencer", action="store_true", help="integra estado/regras mas nao exige loaddata antes de acoes")
    ap.add_argument("--build-time-scale", type=float, default=1.0, help="fator sobre a duracao real de obra da cfg (0=instantaneo)")
    a = ap.parse_args()
    BUILD_SCALE["v"] = a.build_time_scale
    AUTO.update(on=a.auto_notify == "on", window=a.auto_window, max=a.auto_max)
    if a.export_fixture:
        fx = export_fixture(a.fixture); print("fixture:", a.fixture, "burst", len(fx["burst"]), "templates", len(fx["templates"])); sys.exit()
    serve(a.port, None if a.key == "random" else bytes.fromhex(a.key), a.fixture, integrate=not a.no_state, state=a.state, sequencer=not a.no_sequencer)
