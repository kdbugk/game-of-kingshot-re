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

class Session:
    def __init__(self, conn, addr, S, fx, key, log):
        self.conn, self.addr, self.S, self.fx, self.key, self.log = conn, addr, S, fx, key, log
        self.peer = L.Peer(S, key); self.t0 = time.time(); self.n = 0
        self.stats = {}
        self.gm_items = {}   # GM (lab): inventário do sandbox
        self.gm_hero = {}    # GM (lab): níveis de herói do sandbox
        self.last_push = {}; self.auto_pushed = []
        self.surv_work = set(); self.bld_lv = {}; self.fur_lv = {}
        self.fid_wet = {}    # L3: fid -> work_endtime (camas type1 / ferramentas de caca type18)
        self.prod_extra = {} # L3: recurso produzido -> acumulado (sandbox)
        self.mail_seq = 0

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

    # ---- ACOES: handlers com recompensa real (sandbox generoso)
    def h_hangup(self, m):
        rew = [{"id": 102, "value": 100000}, {"id": 103, "value": 50000}, {"id": 105, "value": 20000}]
        self.reply(m, {"code": 0, "hang_start_time": self.now() - 3600, "current_reward": rew, "expert_reward": []})

    def h_hangup_view(self, m):
        rew = [{"id": 102, "value": 100000}, {"id": 103, "value": 50000}]
        self.reply(m, {"open_hang_up_reward_view_time": self.now(), "current_reward": rew, "expert_reward": []})

    def h_online_reward(self, m):
        self.reply(m, {"code": 0, "online_reward": [{"id": 101, "count": 500}, {"id": 102, "count": 20000}], "receive_start_time": self.now() + 3600})

    def h_daily_award(self, m):
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
        tpl = None
        for n, o in (self.fx or {}).get("burst", []):
            if n == "notify_survivor_info": tpl = o; break
        if tpl is None: return
        o = json.loads(json.dumps(tpl))
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
        for n, o in (self.fx or {}).get("burst", []):
            if n == name: return json.loads(json.dumps(o))
        return None

    def push_shelter(self):
        """Reenvia notify_shelter_info com work_endtime (camas/caca) e niveis de predio do sandbox aplicados."""
        o = self.burst_tpl("notify_shelter_info")
        if o is None: return
        for b in o.get("building_info", []):
            if b.get("bid") in self.bld_lv: b["base"]["lv"] = self.bld_lv[b["bid"]]
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
        # ciclo de caca = so esta req (nao existe hunting_start): obtain -> work_endtime da ferramenta (furniture type18)
        # volta ao futuro curto (30s) via notify_shelter_info; recompensa em recurso; sobrevivente fica em status 2
        sid = m["obj"].get("sid"); end = self.now() + 30
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

    def h_shop_info(self, m): self.reply(m, {"code": 0, "info": self.mk_shop(m["obj"].get("shop_id") or 101)})

    def h_shop_info_array(self, m):
        self.reply(m, {"code": 0, "map_info": [self.mk_shop(i) for i in (m["obj"].get("arr_id") or [])]})

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
        box = [{"box_id": i, "pos": {"x": 3 + i, "y": 4}, "reward": [{"id": 102, "count": 50000}]} for i in (1, 2, 3)]
        self.reply(m, {"code": 0, "start_stage_ts": self.now(), "td_box": box,
                       "td_survivor": [{"type": 1, "sid": [1, 2, 3, 4]}, {"type": 2, "sid": [6, 203, 205]}]})

    def h_td_settle(self, m):
        win = bool(m["obj"].get("is_win"))
        rew = [{"id": 101, "count": 500}, {"id": 102, "count": 200000}, {"id": 103, "count": 100000}, {"id": 105, "count": 50000}] if win else [{"id": 102, "count": 10000}]
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
        if not hasattr(self, "_bidx"):
            self._bidx = {}
            for n, o in (self.fx or {}).get("burst", []): self._bidx.setdefault(n, o)
        return self._bidx

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
         "req_shop_info": h_shop_info, "req_shop_info_array": h_shop_info_array, "req_rank_info": h_rank_info,
         "req_arena_report": h_arena_report, "req_unlock_module": h_ok, "req_guide_set_step": h_ok,
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
                self.H.get(m["name"], Session.h_default)(self, m)
                self.auto_reflect(m["name"])
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
    ap.add_argument("--auto-notify", choices=["on", "off"], default="on")
    ap.add_argument("--auto-window", type=float, default=5.0)
    ap.add_argument("--auto-max", type=int, default=8)
    a = ap.parse_args()
    AUTO.update(on=a.auto_notify == "on", window=a.auto_window, max=a.auto_max)
    if a.export_fixture:
        fx = export_fixture(a.fixture); print("fixture:", a.fixture, "burst", len(fx["burst"]), "templates", len(fx["templates"])); sys.exit()
    serve(a.port, None if a.key == "random" else bytes.fromhex(a.key), a.fixture)
