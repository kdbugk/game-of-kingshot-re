#!/usr/bin/env python3
"""server_state.py — ESTADO de contas do servidor de jogo offline (standalone, stdlib).

Account guarda os subsistemas inferidos dos pushes reais (burst do fixture_v4) e sabe:
  * Account.from_seed(fixture)        -> popula tudo a partir do burst (+ templates/login_resp)
  * account.apply_client_save(obj)    -> ingere req_save_client_data (law_point, survivor[res601..607])
  * account.grant(items) / spend(items) / can_afford(items)  (spend = check + débito atômico -> bool)
  * account.snapshot_notifies()       -> [(nome, obj)] re-push do estado completo (na ordem do seed)
  * account.save(path) / Account.load(path)  JSON, escrita atômica (tmp + os.replace)

Princípio: cada subsistema guarda a STRUCT COMPLETA do schema (não só alguns campos), então o
snapshot regenera o notify sem perda. Notifies sem modelo tipado (alianças, eventos, etc.) ficam em
`raw` e são re-emitidos como vieram (passthrough), para o cliente continuar recebendo o burst inteiro.
Tempo real: int(time.time()) em meta/servertime/last_refresh.
"""
import copy, json, os, time

def now(): return int(time.time())

RES_LIMIT = 1000   # ids < 1000 = recursos (resource_init: 101..119,192..195); >= 1000 = mochila

# ---- notify -> subsistema (documentado também no RELATORIO.md) -------------------------------
QUEST_GROUPS = {   # notify de quests -> grupo
    "notify_quests": "main", "notify_dailyquests": "daily", "notify_growthquests": "growth",
    "notify_chapterquests": "chapter", "notify_homestead_quests": "homestead",
    "notify_google_achievement_quests": "google",
}
MODELED = {"notify_game_init", "notify_base_info", "notify_resource_init", "notify_backpack_init",
           "notify_shelter_info", "notify_queue_info", "notify_survivor_info", "notify_hero_init",
           "notify_mail_type_info_syn", "notify_climbtower_tower_brief_info", "notify_offline_info",
           "notify_clientsave_data", "notify_law_info", *QUEST_GROUPS}


def _norm_items(items):
    """Aceita {id:count}, [(id,count)], [{'id':..,'count':..}] -> dict id->count agregado (>0)."""
    out = {}
    if isinstance(items, dict):
        it = items.items()
    else:
        it = []
        for x in items:
            if isinstance(x, dict): it.append((x["id"], x.get("count", 1)))
            else: it.append((x[0], x[1]))
    for i, c in it:
        i, c = int(i), int(c)
        if c < 0: raise ValueError("count negativo")
        if c: out[i] = out.get(i, 0) + c
    return out


class Account:
    def __init__(self, uid=0):
        self.meta = {"uid": uid, "created_at": now(), "last_login": now(), "saved_at": 0, "revision": 0}
        self.base = {}              # notify_base_info completo (lv, nickName, power, kid, ...)
        self.game_init = {}         # notify_game_init (servertime/open_time/zero_time/...)
        self.resources = {}         # id -> count   (notify_resource_init)
        self.backpack = {}          # id -> count   (notify_backpack_init)
        self.buildings = {}         # bid -> struct {bid, base{lv,status,mode,furniture[...]}}
        self.queues = {}            # qid -> struct (fila de construção/pesquisa/...; qtype em base)
        self.survivors = {}         # sid -> struct {sid,status,img_id,name_id,fid_source,fid_work}
        self.survivor_extra = {}    # guide_selected/switch/riot_data/num_map
        self.survivor_res = {}      # sid -> {res601..607} (do save do cliente)
        self.law_point = 0
        self.heroes = {}            # id -> struct {id,lev,star,skills[],...}
        self.quests = {}            # grupo -> {"quests": {id: struct}, "finishs": [..], "extra": {..}}
        self.mails = []             # list[cover] (req_mail_cover_list.coverlist)
        self.mail_types = {}        # type -> {type,num,un_readnum,can_get_attach,last_time}
        self.tower = {"currency": 0, "towers": {}, "total_passed_cnt": 0}   # id -> struct
        self.shops = {}             # shop_id -> struct (goods[].buy_count, refresh_times...)
        self.offline = {}           # notify_offline_info
        self.law_info = {}          # notify_law_info.law_info
        self.client_save = {}       # último client_data cru ingerido
        self.raw = {}               # nome -> [obj,...] passthrough (não modelado)
        self.order = []             # ordem do burst (nomes, c/ repetição)

    # ------------------------------------------------------------------ seed
    @classmethod
    def from_seed(cls, fx):
        """fx = dict do fixture_v4.json (ou caminho)."""
        if isinstance(fx, (str, os.PathLike)):
            with open(fx, encoding="utf8") as f: fx = json.load(f)
        a = cls(uid=(fx.get("login_resp") or {}).get("uid", 0))
        for name, obj in fx["burst"]:
            a._ingest_push(name, copy.deepcopy(obj))
        tpl = fx.get("templates", {})
        mi = (tpl.get("req_shop_info_array") or {}).get("map_info") or []
        for s in mi: a.shops[s["id"]] = copy.deepcopy(s)
        for m in (tpl.get("req_mail_cover_list") or {}).get("coverlist") or []:
            a.mails.append(copy.deepcopy(m))
        if fx.get("client_data") and not a.client_save:
            a.apply_client_save(fx["client_data"])
        a.meta["uid"] = a.base.get("uid", a.meta["uid"])
        a.meta["created_at"] = a.base.get("register_time", a.meta["created_at"])
        a.meta["last_login"] = now()
        return a

    def _ingest_push(self, name, o):
        self.order.append(name)
        if name == "notify_game_init": self.game_init = o
        elif name == "notify_base_info": self.base = o
        elif name == "notify_resource_init":
            self.resources = {d["id"]: d.get("count", 0) for d in o.get("data", [])}
        elif name == "notify_backpack_init":
            self.backpack = {d["id"]: d.get("count", 0) for d in o.get("data", [])}
        elif name == "notify_shelter_info":
            for b in o.get("building_info", []): self.buildings[b["bid"]] = b
        elif name == "notify_queue_info":
            for q in o.get("queue_map", []): self.queues[q["qid"]] = q
        elif name == "notify_survivor_info":
            for s in o.get("survivor_list", []): self.survivors[s["sid"]] = s
            self.survivor_extra = {k: v for k, v in o.items() if k != "survivor_list"}
        elif name == "notify_hero_init":
            for h in o.get("data", []): self.heroes[h["id"]] = h
        elif name == "notify_mail_type_info_syn":
            for m in o.get("infolist", []): self.mail_types[m["type"]] = m
        elif name == "notify_climbtower_tower_brief_info":
            self.tower["currency"] = o.get("currency", 0)
            for t in o.get("towers", []): self.tower["towers"][t["id"]] = t
        elif name == "notify_offline_info": self.offline = o
        elif name == "notify_law_info": self.law_info = o.get("law_info", {})
        elif name == "notify_clientsave_data": self.apply_client_save(o)
        elif name in QUEST_GROUPS:
            g = self.quests.setdefault(QUEST_GROUPS[name], {"quests": {}, "finishs": [], "extra": {}})
            for q in o.get("quests", []): g["quests"][q["id"]] = q
            for f in o.get("finishs", []):
                if f not in g["finishs"]: g["finishs"].append(f)
            g["extra"].update({k: v for k, v in o.items() if k not in ("quests", "finishs")})
        else:
            self.raw.setdefault(name, []).append(o)

    # ------------------------------------------------------------------ save do cliente
    def apply_client_save(self, obj):
        """obj = client_data ({'law_point','survivor':[{sid,res601..}]}) ou {'data': client_data}."""
        d = obj.get("data", obj)
        self.client_save = copy.deepcopy(d)
        if "law_point" in d: self.law_point = d["law_point"]
        n = 0
        for s in d.get("survivor", []):
            self.survivor_res[s["sid"]] = {k: v for k, v in s.items() if k != "sid"}
            n += 1
        self._touch()
        return n

    # ------------------------------------------------------------------ economia
    def _store(self, i): return self.resources if i < RES_LIMIT else self.backpack

    def balance(self, i): return self._store(int(i)).get(int(i), 0)

    def can_afford(self, items):
        return all(self.balance(i) >= c for i, c in _norm_items(items).items())

    def grant(self, items):
        """Credita itens; devolve lista [(id,count_novo)] alterados (para notify_*_update)."""
        ch = []
        for i, c in _norm_items(items).items():
            st = self._store(i); st[i] = st.get(i, 0) + c; ch.append((i, st[i]))
        self._touch(); return ch

    def spend(self, items):
        """check + débito atômico. True se debitou; False (sem alterar nada) se saldo insuficiente."""
        need = _norm_items(items)
        if not all(self.balance(i) >= c for i, c in need.items()): return False
        for i, c in need.items():
            st = self._store(i); st[i] -= c
            if st[i] == 0 and i >= RES_LIMIT: del st[i]   # mochila: item zerado some; recurso fica em 0
        self._touch(); return True

    # ------------------------------------------------------------------ prédios / sobreviventes / mails / torre / lojas
    def building_lv(self, bid):
        b = self.buildings.get(bid); return b["base"]["lv"] if b else 0

    def set_building_lv(self, bid, lv):
        self.buildings[bid]["base"]["lv"] = lv; self._touch()

    def survivor_status(self, sid): return self.survivors.get(sid, {}).get("status")

    def add_mail(self, mail):
        m = dict(mail); m.setdefault("mailid", int(time.time() * 1000)); m.setdefault("send_time", now())
        m.setdefault("isread", 0); self.mails.append(m)
        t = self.mail_types.setdefault(m.get("first_type", 10), {"type": m.get("first_type", 10), "num": 0, "un_readnum": 0,
                                                                  "can_get_attach": 0, "last_time": 0})
        t["num"] += 1; t["un_readnum"] += 1; t["last_time"] = m["send_time"]; self._touch(); return m

    def read_mail(self, mailid):
        for m in self.mails:
            if m["mailid"] == mailid and not m.get("isread"):
                m["isread"] = 1
                t = self.mail_types.get(m.get("first_type"))
                if t and t["un_readnum"] > 0: t["un_readnum"] -= 1
                self._touch(); return True
        return False

    def tower_pass(self, tid, level_id):
        t = self.tower["towers"].setdefault(tid, {"id": tid, "daily_fail": 0, "cur_passed_level": 0, "sweep_cnt": 0})
        t["cur_passed_level"] = level_id
        if level_id > t.get("his_passed_level", 0): t["his_passed_level"] = t["passed_level_id"] = level_id
        self.tower["total_passed_cnt"] += 1; self._touch(); return t

    def shop_buy(self, shop_id, goods_id, n=1):
        for g in self.shops[shop_id]["goods"]:
            if g["id"] == goods_id: g["buy_count"] = g.get("buy_count", 0) + n; self._touch(); return g["buy_count"]
        raise KeyError(goods_id)

    def shop_refresh(self, shop_id):
        s = self.shops[shop_id]; s["refresh_times"] = s.get("refresh_times", 0) + 1
        s["last_refresh_ts"] = now()
        for g in s["goods"]: g["buy_count"] = 0
        self._touch()

    def quest_progress(self, qid, progress, group="main"):
        g = self.quests.setdefault(group, {"quests": {}, "finishs": [], "extra": {}})
        g["quests"].setdefault(qid, {"id": qid})["progress"] = progress; self._touch()

    def _touch(self):
        self.meta["revision"] += 1; self.meta["touched_at"] = now()

    # ------------------------------------------------------------------ snapshot (re-push)
    def snapshot_notifies(self):
        """Lista [(nome, obj)] do estado COMPLETO, na ordem do burst. Modelados regenerados do estado;
        o resto é passthrough de `raw`. servertime sempre em tempo real."""
        out, emitted, raw_i = [], set(), {}
        for name in self.order:
            if name in MODELED:
                if name in emitted: continue
                emitted.add(name)
                o = self._build(name)
                if o is not None: out.append((name, o))
            else:
                i = raw_i.get(name, 0); raw_i[name] = i + 1
                lst = self.raw.get(name, [])
                if i < len(lst): out.append((name, copy.deepcopy(lst[i])))
        return out

    def _build(self, name):
        if name == "notify_game_init":
            g = dict(self.game_init); g["servertime"] = now(); return g
        if name == "notify_base_info": return copy.deepcopy(self.base)
        if name == "notify_resource_init":
            return {"data": [{"id": i, "count": c} for i, c in self.resources.items()]}
        if name == "notify_backpack_init":
            return {"data": [{"id": i, "count": c} for i, c in self.backpack.items()]}
        if name == "notify_shelter_info": return {"building_info": copy.deepcopy(list(self.buildings.values()))}
        if name == "notify_queue_info": return {"queue_map": copy.deepcopy(list(self.queues.values()))}
        if name == "notify_survivor_info":
            return {**copy.deepcopy(self.survivor_extra), "survivor_list": copy.deepcopy(list(self.survivors.values()))}
        if name == "notify_hero_init": return {"data": copy.deepcopy(list(self.heroes.values()))}
        if name == "notify_mail_type_info_syn": return {"infolist": copy.deepcopy(list(self.mail_types.values()))}
        if name == "notify_climbtower_tower_brief_info":
            return {"currency": self.tower["currency"], "towers": copy.deepcopy(list(self.tower["towers"].values()))}
        if name == "notify_offline_info": return copy.deepcopy(self.offline)
        if name == "notify_law_info": return {"law_info": copy.deepcopy(self.law_info)}
        if name == "notify_clientsave_data":
            d = copy.deepcopy(self.client_save); d["law_point"] = self.law_point
            sv = []
            for sid, r in self.survivor_res.items(): sv.append({"sid": sid, **r})
            if sv: d["survivor"] = sv
            return {"data": d}
        if name in QUEST_GROUPS:
            g = self.quests.get(QUEST_GROUPS[name])
            if g is None: return None
            return {**copy.deepcopy(g["extra"]), "quests": copy.deepcopy(list(g["quests"].values())),
                    "finishs": copy.deepcopy(g["finishs"])}
        return None

    # ------------------------------------------------------------------ persistência
    _INT_KEYED = ("resources", "backpack", "buildings", "queues", "survivors", "survivor_res", "heroes",
                  "mail_types", "shops")

    def to_dict(self):
        d = {k: v for k, v in self.__dict__.items()}
        d["tower"] = {**self.tower, "towers": {str(k): v for k, v in self.tower["towers"].items()}}
        d["quests"] = {g: {**v, "quests": {str(k): q for k, q in v["quests"].items()}} for g, v in self.quests.items()}
        for k in self._INT_KEYED: d[k] = {str(i): v for i, v in d[k].items()}
        return d

    @classmethod
    def from_dict(cls, d):
        a = cls()
        for k, v in d.items(): setattr(a, k, v)
        for k in cls._INT_KEYED: setattr(a, k, {int(i): v for i, v in d[k].items()})
        a.tower = {**d["tower"], "towers": {int(k): v for k, v in d["tower"]["towers"].items()}}
        a.quests = {g: {**v, "quests": {int(k): q for k, q in v["quests"].items()}} for g, v in d["quests"].items()}
        return a

    def save(self, path):
        self.meta["saved_at"] = now()
        tmp = f"{path}.tmp{os.getpid()}"
        with open(tmp, "w", encoding="utf8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf8") as f: return cls.from_dict(json.load(f))

    def summary(self):
        return {"resources": len(self.resources), "backpack": len(self.backpack), "buildings": len(self.buildings),
                "queues": len(self.queues), "survivors": len(self.survivors), "survivor_res": len(self.survivor_res),
                "heroes": len(self.heroes), "quest_groups": {g: len(v["quests"]) for g, v in self.quests.items()},
                "mails": len(self.mails), "mail_types": len(self.mail_types), "towers": len(self.tower["towers"]),
                "shops": len(self.shops), "raw_notifies": sum(len(v) for v in self.raw.values())}
