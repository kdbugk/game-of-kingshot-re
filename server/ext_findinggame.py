#!/usr/bin/env python3
"""ext_findinggame.py - handlers reais do modulo FINDINGGAME (minigame "procure os objetos", req_find_goods_*).

Contrato: HANDLERS = {"req_x": fun}; fun(session, m) usa session.reply/push/account/now(); nunca lanca.
Modelo (cfg find_*.json): single-player por capitulos/fases (find_chapter/find_level/find_map_item),
energia (814, init 60), dicas gratis, tempo, grade/infinito de progresso (find_grade/find_config),
dupla (find_two_config/find_two_reward) com sala + parceiro-bot (offline), rank sintetico.
Anti-replay: server_rules.ReplayRegistry kinds 'findinggame' (rodada), 'findinggame_grade',
'findinggame_daily', 'findinggame_task' (registrados em runtime em REPLAY_ERR; server_rules.py intocado).
Estado: account.ext_state['fg'] (em memoria; ver RELATORIO_MISC)."""
from extkit import (cfg, pairs, items, err, now, st, me, grant, once, rsp, push, handler, obj, rng, schema)

ACT_SINGLE, ACT_TWO = 2967001, 2968001
ENERGY_ITEM = 814
HANDLERS = {}


def reg(name):
    def d(fn):
        HANDLERS[name] = handler(fn)
        return fn
    return d


# ---------------------------------------------------------------- cfg
def _conf():
    c = cfg("find_config")
    return next(iter(c.values()), {}) if c else {}


def _two():
    c = cfg("find_two_config")
    return next(iter(c.values()), {}) if c else {}


def _chapters():
    c = cfg("find_chapter")
    return [c[k] for k in sorted(c, key=int)]


def _levels(chapter_id):
    c = cfg("find_level")
    return [(k, c[k]) for k in sorted(c, key=int) if c[k].get("belong_chapter") == chapter_id and k != "9999"]


def _map_items(map_res, diff):
    c = cfg("find_map_item")
    return sorted(int(k) for k, v in c.items() if v.get("map_resource") == map_res and v.get("item_difficulty_id") == diff)


def _init():
    cf = _conf()
    e = pairs(cf.get("energy_init_num")) or [(ENERGY_ITEM, 60)]
    return {"energy": e[0][1] if e else 60, "progress": 0, "received_grade": 0, "received_inf": 0,
            "ch": 0, "lv": 0, "started": False, "scene": None, "round": 0, "daily_score": 0,
            "received_daily": 0, "rooms": {}, "room": None, "records": [], "tasks": 0}


def S(s):
    return st(s, "fg", _init)


# ---------------------------------------------------------------- single-player
def _chapter_struct(g, with_scene=True):
    chs = _chapters()
    ch = chs[min(g["ch"], len(chs) - 1)] if chs else {}
    o = {"chapter_map": ch.get("chpater_number", g["ch"] + 1), "chapter_id": ch.get("chapter_id", 101),
         "chapter_level": g["lv"] + 1, "chapter_started": g["started"], "chapter_inf_items": [],
         "chapter_pass_all": g["ch"] >= len(chs), "energy": g["energy"]}
    if with_scene and g["scene"]:
        o["scene"] = _scene_struct(g["scene"])
    return o


def _scene_struct(sc):
    return {"target_items": [{"item_id": i, "mark": bool(mk)} for i, mk in sc["targets"].items()],
            "stop_ts": sc["stop_ts"], "free_prompt": sc["free_prompt"], "error_punish_ts": 0,
            "extra_time_cnt": sc["extra"], "tip_item_id": sc["tip"], "tip_cnt": sc["tip_cnt"],
            "in_time_option": False, "xxx_key": sc["key"], "train_time": 0}


def _build_scene(s, g):
    chs = _chapters()
    if g["ch"] >= len(chs):
        return None
    ch = chs[g["ch"]]
    lvs = _levels(ch.get("chapter_id"))
    if not lvs:
        return None
    key, lv = lvs[min(g["lv"], len(lvs) - 1)]
    map_res = cfg("find_map").get(str(ch.get("chapter_id")), {}).get("map_resource", 1)
    r = rng(int(key) * 7919 + g["round"])
    ids = []
    for diff, n in sorted((lv.get("new_item_number") or {}).items(), key=lambda x: int(x[0])):
        pool = _map_items(map_res, int(diff)) or list(range(101, 140))
        ids += r.sample(pool, min(int(n), len(pool)))
    ids = ids or [101, 102, 103]
    g["round"] += 1
    return {"level_key": key, "targets": {i: False for i in ids}, "stop_ts": 0, "free_prompt": lv.get("free_prompt", 2),
            "extra": 0, "tip": 0, "tip_cnt": 0, "key": "k%08x" % r.getrandbits(32), "limit": lv.get("level_challenge_time", 60),
            "cost_energy": lv.get("cost_energy", 0), "round": g["round"], "settled": False}


@reg("req_find_goods_start_chapter")
def start_chapter(s, m):
    g = S(s)
    if g["ch"] >= len(_chapters()):
        return rsp(s, m, err("err_find_goods_all_chapter_pass"))
    if g["started"]:
        return rsp(s, m, err("err_find_goods_chapter_started"))
    g["started"] = True
    g["lv"] = 0
    rsp(s, m)


@reg("req_find_goods_scene_start")
def scene_start(s, m):
    g = S(s)
    if g["ch"] >= len(_chapters()):
        return rsp(s, m, err("err_find_goods_all_chapter_pass"))
    if not g["started"]:
        return rsp(s, m, err("err_find_goods_chapter_not_start"))
    if g["scene"] and not g["scene"]["settled"]:      # retomada idempotente
        return rsp(s, m, scene=_scene_struct(g["scene"]))
    sc = _build_scene(s, g)
    if sc is None:
        return rsp(s, m, err("err_find_goods_no_scene"))
    if g["energy"] < sc["cost_energy"]:
        return rsp(s, m, err("err_find_goods_not_enough_energy"))
    g["energy"] -= sc["cost_energy"]
    g["scene"] = sc
    rsp(s, m, scene=_scene_struct(sc))


@reg("req_find_goods_scene_time_begin")
def time_begin(s, m):
    g = S(s)
    sc = g["scene"]
    if not sc:
        return rsp(s, m, err("err_find_goods_no_scene"))
    if sc["stop_ts"]:
        return rsp(s, m, err("err_find_goods_has_scene_time_begin"))
    sc["stop_ts"] = now(s) + sc["limit"]
    rsp(s, m, stop_ts=sc["stop_ts"], server_time=now(s))


@reg("req_find_goods_scene_mark")
def scene_mark(s, m):
    g = S(s)
    sc = g["scene"]
    o = obj(m)
    if not sc or sc["settled"]:
        return rsp(s, m, err("err_find_goods_no_scene"))
    if not sc["stop_ts"]:
        return rsp(s, m, err("err_find_goods_not_scene_time_begin"))
    if now(s) > sc["stop_ts"] + 2:
        return rsp(s, m, err("err_find_goods_scene_over"))
    iid = o.get("item_id")
    if iid not in sc["targets"]:
        return rsp(s, m, err("err_find_goods_not_in_target_group"))
    sc["targets"][iid] = True
    if sc["tip"] == iid:
        sc["tip"] = 0
    d = _scene_struct(sc)
    rsp(s, m, target_items=d["target_items"], free_prompt=d["free_prompt"], extra_time_cnt=d["extra_time_cnt"],
        tip_item_id=d["tip_item_id"], tip_cnt=d["tip_cnt"], server_time=now(s))


@reg("req_find_goods_scene_tip")
def scene_tip(s, m):
    g = S(s)
    sc = g["scene"]
    iid = obj(m).get("item_id")
    if not sc:
        return rsp(s, m, err("err_find_goods_no_scene"))
    if sc["tip"]:
        return rsp(s, m, err("err_find_goods_already_has_tip_item"))
    if sc["free_prompt"] <= 0:
        return rsp(s, m, err("err_find_goods_no_free_prompt_cnt"))
    left = [i for i, mk in sc["targets"].items() if not mk]
    if not left:
        return rsp(s, m, err("err_find_goods_no_tip_item"))
    sc["free_prompt"] -= 1
    sc["tip"] = iid if iid in left else left[0]
    sc["tip_cnt"] += 1
    rsp(s, m)


@reg("req_find_goods_over_option")
def over_option(s, m):
    """Tempo acabou: option 1 = +tempo (extra), outro = desistir (zera a cena)."""
    g = S(s)
    sc = g["scene"]
    opt = obj(m).get("option", 0)
    if not sc:
        return rsp(s, m, err("err_find_goods_no_scene"))
    if opt == 1:
        sc["extra"] += 1
        sc["stop_ts"] = max(sc["stop_ts"], now(s)) + 30
        return rsp(s, m, stop_ts=sc["stop_ts"], extra_time_cnt=sc["extra"], free_prompt=sc["free_prompt"],
                   chapter=_chapter_struct(g, False), scene=_scene_struct(sc))
    g["scene"] = None
    rsp(s, m, stop_ts=0, extra_time_cnt=0, free_prompt=0, chapter=_chapter_struct(g, False))


@reg("req_find_goods_settle")
def settle(s, m):
    g = S(s)
    sc = g["scene"]
    if not sc:
        return rsp(s, m, err("err_find_goods_no_scene"))
    if not all(sc["targets"].values()):
        return rsp(s, m, err("err_find_goods_not_all_item_found"))
    e = once(s, "findinggame", "%s:%s:%s" % (sc["level_key"], sc["round"], me(s)["uid"]), "err_find_goods_round_already_settled")
    if e:
        return rsp(s, m, e)
    sc["settled"] = True
    chs = _chapters()
    ch = chs[g["ch"]]
    lvs = _levels(ch.get("chapter_id"))
    g["progress"] += max(10, 5 * len(sc["targets"]))
    g["scene"] = None
    g["lv"] += 1
    if g["lv"] >= len(lvs):        # capitulo completo: recompensa de arquivo + exp
        grant(s, pairs(ch.get("file_rewards")))
        g["progress"] += ch.get("file_experience", 0)
        g["ch"] += 1
        g["lv"] = 0
        g["started"] = False
    push(s, "notify_find_goods_progress_num", progress_num=g["progress"])
    rsp(s, m, chapter=_chapter_struct(g, False), pass_level=True)


# ---------------------------------------------------------------- progresso / recompensas
def _grades():
    c = cfg("find_grade")
    return [c[k] for k in sorted(c, key=int)]


@reg("req_find_goods_progress_grade_reward")
def grade_reward(s, m):
    g = S(s)
    gr = [x for x in _grades() if x["grade"] > g["received_grade"] and x.get("stra_progress", 0) <= g["progress"]]
    if not gr:
        return rsp(s, m, err("err_find_goods_grade_reward_received" if g["received_grade"] else "err_find_goods_grade_not_reach"))
    tot = {}
    for x in gr:
        e = once(s, "findinggame_grade", x["grade"], "err_find_goods_grade_reward_received")
        if e:
            continue
        for i, c in pairs(x.get("rewards")):
            tot[i] = tot.get(i, 0) + c
    g["received_grade"] = gr[-1]["grade"]
    grant(s, tot.items())
    rsp(s, m, received_grade=g["received_grade"])


@reg("req_find_goods_progress_infinite_receive")
def infinite_receive(s, m):
    g = S(s)
    cf = _conf()
    gr = _grades()
    top = gr[-1].get("stra_progress", 0) if gr else 0
    step = cf.get("ex_point", 2800) or 2800
    avail = (g["progress"] - top) // step if g["progress"] >= top else 0
    if avail <= g["received_inf"]:
        return rsp(s, m, err("err_find_goods_no_inf_extra_reward"))
    n = avail - g["received_inf"]
    g["received_inf"] = avail
    rw = grant(s, [(i, c * n) for i, c in pairs(cf.get("infinite_rewards"))])
    rsp(s, m, received_infinite=g["received_inf"], rewards=rw)


@reg("req_find_goods_daily_score_reward")
def daily_score_reward(s, m):
    g = S(s)
    c = cfg("find_two_reward")
    prev = g["received_daily"]
    tot = {}
    top = prev
    for k in sorted(c, key=int):
        if int(k) > prev and c[k].get("integral", 1 << 30) <= g["daily_score"]:
            e = once(s, "findinggame_daily", "%s:%s" % (me(s)["uid"], k), "err_find_goods_no_daily_reward", daily=True)
            top = int(k)
            if e:
                continue
            for i, n in pairs(c[k].get("scores_rewards")):
                tot[i] = tot.get(i, 0) + n
    if top == prev:
        return rsp(s, m, err("err_find_goods_no_daily_reward"))
    g["received_daily"] = top
    grant(s, tot.items())
    rsp(s, m, received_daily_reward=top, prev_received=prev)


@reg("req_find_goods_task_reward")
def task_reward(s, m):
    g = S(s)
    n = 0
    done = []
    cur = _conf().get("find_currency_id", 620287)
    for q in obj(m).get("quest_id_list") or []:
        if once(s, "findinggame_task", q, "err_find_goods_no_task_component", daily=True) is None:
            n += 1
            done.append(q)
            grant(s, [(cur, 10)])
    g["tasks"] += n
    rsp(s, m, result=done)


@reg("req_find_goods_rank_info")
def rank_info(s, m):
    g = S(s)
    o = obj(m)
    r = rng(o.get("rank_type", 0) * 100 + o.get("day", 0))
    base = 9000 if o.get("rank_type", 0) else 40000
    lst = [{"team_id": "T%05d" % r.randint(1, 99999), "score": base - i * r.randint(150, 400)} for i in range(10)]
    mine = {"team_id": "T%05d" % (me(s)["uid"] % 100000), "score": g["daily_score"]}
    rank = 1 + sum(1 for x in lst if x["score"] > mine["score"]) if mine["score"] else 0
    rsp(s, m, rank_info={"rank_list": lst, "self_data": mine, "self_rank": rank},
        general_detail=[{"k": 1, "v": g["daily_score"]}, {"k": 2, "v": g["progress"]}])


@reg("req_update_find_goods_server_time")
def server_time(s, m):
    rsp(s, m, time=now(s))


# ---------------------------------------------------------------- dupla (salas)
BOT_UID = 900001


def _member(pos, u, ready=0, score=0):
    return {"position": pos, "uid": u["uid"], "kid": u["kid"], "nickName": u["nickName"], "abbr": u.get("abbr", ""),
            "daily_max_score": score, "ready_ts": ready, "score": score, "error_punish_ts": 0, "offline": False, "mark_count": 0}


def _room_info(r):
    o = {"room_id": r["id"], "create_ts": r["create_ts"], "room_member": [dict(x) for x in r["members"]]}
    if r.get("scene"):
        o["room_scene"] = _room_scene(r)
    return o


def _room_scene(r):
    sc = r["scene"]
    return {"target_items": [{"item_id": i, "mark": bool(v)} for i, v in sc["targets"].items()], "inf_items": [],
            "rate_gear": sc["gear"], "gear_trigger_ms": 0, "room_map_id": sc["map"], "room_level_id": sc["level"],
            "begin_ts": sc["begin"], "stop_ts": sc["stop"], "xxx_key": sc["key"], "round": sc["round"]}


def _new_room(s, g, with_bot=True):
    u = me(s)
    t = now(s)
    rid = "R%d%03d" % (t, len(g["rooms"]) % 1000)
    r = {"id": rid, "create_ts": t, "members": [_member(1, u)], "scene": None, "chat": 0, "owner": u["uid"]}
    if with_bot:
        r["members"].append(_member(2, {"uid": BOT_UID, "kid": u["kid"], "nickName": "Rastreador", "abbr": ""}, ready=t))
    g["rooms"][rid] = r
    g["room"] = rid
    return r


def _myroom(g):
    return g["rooms"].get(g["room"]) if g["room"] else None


def _mem(r, uid):
    return next((x for x in r["members"] if x["uid"] == uid), None)


@reg("req_find_goods_create_room")
def create_room(s, m):
    g = S(s)
    if _myroom(g):
        return rsp(s, m, err("err_find_goods_has_in_room"))
    r = _new_room(s, g, with_bot=False)
    rsp(s, m, room_info=_room_info(r))


@reg("req_find_goods_join_room")
def join_room(s, m):
    g = S(s)
    rid = obj(m).get("room_id")
    r = g["rooms"].get(rid)
    if _myroom(g):
        return rsp(s, m, err("err_find_goods_has_in_room"))
    if not r:
        return rsp(s, m, err("err_find_goods_room_not_exist"))
    if len(r["members"]) >= 2:
        return rsp(s, m, err("err_find_goods_room_is_full"))
    r["members"].append(_member(2, me(s)))
    g["room"] = rid
    rsp(s, m, room_info=_room_info(r))


@reg("req_find_goods_match")
def match(s, m):
    """Matchmaking offline: casa na hora com o bot e empurra notify_find_goods_match_result."""
    g = S(s)
    if _myroom(g):
        return rsp(s, m, err("err_find_goods_has_in_room"))
    r = _new_room(s, g, with_bot=True)
    rsp(s, m)
    push(s, "notify_find_goods_match_result", code=0, room_info=_room_info(r))


@reg("req_find_goods_match_cancel")
def match_cancel(s, m):
    g = S(s)
    r = _myroom(g)
    if r and not r["scene"] and _mem(r, BOT_UID):
        g["rooms"].pop(r["id"], None)
        g["room"] = None
    rsp(s, m)


@reg("req_find_goods_room_enter")
def room_enter(s, m):
    rsp(s, m)


@reg("req_find_goods_room_ready")
def room_ready(s, m):
    g = S(s)
    r = _myroom(g)
    if not r:
        return rsp(s, m, err("err_find_goods_not_in_room"))
    x = _mem(r, me(s)["uid"])
    if x["ready_ts"]:
        return rsp(s, m, err("err_find_goods_has_ready"))
    x["ready_ts"] = now(s)
    rsp(s, m, ready_ts=x["ready_ts"])


@reg("req_find_goods_room_unready")
def room_unready(s, m):
    g = S(s)
    r = _myroom(g)
    if not r:
        return rsp(s, m, err("err_find_goods_not_in_room"))
    _mem(r, me(s)["uid"])["ready_ts"] = 0
    rsp(s, m)


def _start_scene(s, g, r):
    t = now(s)
    two = _two()
    rr = rng(sum(map(ord, r["id"])))
    chs = _chapters()
    ch = chs[rr.randrange(len(chs))] if chs else {}
    lvs = _levels(ch.get("chapter_id")) or [("0", {})]
    key, lv = lvs[rr.randrange(len(lvs))]
    mres = cfg("find_map").get(str(ch.get("chapter_id")), {}).get("map_resource", 1)
    ids = []
    for d, n in sorted((lv.get("new_item_number") or {"1": 5, "2": 5}).items(), key=lambda x: int(x[0])):
        pool = _map_items(mres, int(d)) or list(range(101, 140))
        ids += rr.sample(pool, min(int(n), len(pool)))
    b = t + two.get("two_loading_time", 5)
    r["scene"] = {"targets": {i: 0 for i in ids}, "gear": 1, "map": mres, "level": int(key), "begin": b,
                  "stop": b + 180, "key": "k%08x" % rr.getrandbits(32), "round": 1}


@reg("req_find_goods_room_scene_start")
def room_scene_start(s, m):
    g = S(s)
    r = _myroom(g)
    if not r:
        return rsp(s, m, err("err_find_goods_not_in_room"))
    if r["owner"] != me(s)["uid"]:
        return rsp(s, m, err("err_find_goods_no_room_start_auth"))
    if r["scene"]:
        return rsp(s, m, err("err_find_goods_room_has_started"))
    if len(r["members"]) < 2:
        return rsp(s, m, err("err_find_goods_room_not_full"))
    if any(not x["ready_ts"] for x in r["members"] if x["uid"] != r["owner"]):
        return rsp(s, m, err("err_find_goods_room_member_not_ready"))
    _start_scene(s, g, r)
    rsp(s, m, room_scene=_room_scene(r))
    push(s, "notify_find_goods_room_start", room_scene=_room_scene(r))


@reg("req_find_goods_room_scene_enter_confirm")
def room_enter_confirm(s, m):
    g = S(s)
    r = _myroom(g)
    if not r or not r["scene"]:
        return rsp(s, m, err("err_find_goods_no_room_scene"))
    rsp(s, m)
    push(s, "notify_find_goods_room_scene_time_begin")


@reg("req_find_goods_room_scene_mark")
def room_scene_mark(s, m):
    g = S(s)
    r = _myroom(g)
    o = obj(m)
    two = _two()
    if not r or not r["scene"]:
        return rsp(s, m, err("err_find_goods_no_room_scene"))
    sc = r["scene"]
    iid = o.get("item_id")
    x = _mem(r, me(s)["uid"])
    if now(s) > sc["stop"] + 2:
        return rsp(s, m, err("err_find_goods_room_scene_stop"))
    if iid not in sc["targets"]:
        return rsp(s, m, err("err_find_goods_not_in_target_group"))
    if sc["targets"][iid]:
        return rsp(s, m, err("err_find_goods_room_item_marked"))
    sc["targets"][iid] = me(s)["uid"]
    add = two.get("two_item_score", 100) * sc["gear"]
    x["score"] += add
    x["mark_count"] += 1
    g["daily_score"] += add
    if all(sc["targets"].values()):
        g["records"].append({"scene_begin_ts": sc["begin"], "score": sum(y["score"] for y in r["members"]), "team_id": r["id"]})
    rsp(s, m, result={"room_id": r["id"], "item_id": iid, "uid": x["uid"], "add_score": add, "rate_gear": sc["gear"],
                      "gear_trigger_ms": 0, "error_punish_ts": 0, "mark": True, "mark_count": x["mark_count"], "score": x["score"]},
        server_time=now(s))


@reg("req_find_goods_dissolve_room")
def dissolve_room(s, m):
    g = S(s)
    r = _myroom(g)
    if not r:
        return rsp(s, m, err("err_find_goods_not_in_room"))
    if r["owner"] != me(s)["uid"]:
        return rsp(s, m, err("err_find_goods_not_room_master"))
    g["rooms"].pop(r["id"], None)
    g["room"] = None
    rsp(s, m)


@reg("req_find_goods_out_room")
def out_room(s, m):
    g = S(s)
    r = _myroom(g)
    if not r:
        return rsp(s, m, err("err_find_goods_not_in_room"))
    if r["owner"] == me(s)["uid"] and len(r["members"]) > 1 and not _mem(r, BOT_UID):
        return rsp(s, m, err("err_find_goods_room_master_can_not_out"))
    g["rooms"].pop(r["id"], None)
    g["room"] = None
    rsp(s, m)


@reg("req_find_goods_remove_room_member")
def remove_member(s, m):
    g = S(s)
    r = _myroom(g)
    u = obj(m).get("member_uid")
    if not r:
        return rsp(s, m, err("err_find_goods_not_in_room"))
    if r["owner"] != me(s)["uid"]:
        return rsp(s, m, err("err_find_goods_no_room_remove_auth"))
    r["members"] = [x for x in r["members"] if x["uid"] != u or x["uid"] == r["owner"]]
    rsp(s, m)


@reg("req_find_goods_quick_chat")
def quick_chat(s, m):
    g = S(s)
    r = _myroom(g)
    if not r:
        return rsp(s, m, err("err_find_goods_not_in_room"))
    r["chat"] = obj(m).get("chat_id", 0)
    rsp(s, m)


@reg("req_find_goods_share_room_invite")
def share_invite(s, m):
    g = S(s)
    if not _myroom(g):
        return rsp(s, m, err("err_find_goods_not_in_room"))
    t = now(s)
    if t - g.get("last_invite", 0) < _two().get("two_invite_cd", 5):
        return rsp(s, m, err("err_find_goods_room_invite_cooldown"))
    g["last_invite"] = t
    rsp(s, m)


@reg("req_find_goods_challenge_records")
def challenge_records(s, m):
    g = S(s)
    rec = g["records"][-1] if g["records"] else {"scene_begin_ts": 0, "score": 0, "team_id": ""}
    rsp(s, m, records=[dict(rec)] if g["records"] else [])


# ---------------------------------------------------------------- cheats do modulo (lab)
@reg("req_cheat_find_goods_add_progress")
def cheat_progress(s, m):
    g = S(s)
    g["progress"] += max(0, obj(m).get("exp", 0))
    push(s, "notify_find_goods_progress_num", progress_num=g["progress"])
    rsp(s, m)


@reg("req_cheat_find_goods_add_daily_score")
def cheat_score(s, m):
    g = S(s)
    g["daily_score"] += max(0, obj(m).get("score", 0))
    rsp(s, m)


@reg("req_cheat_find_goods_challenge_record")
def cheat_record(s, m):
    g = S(s)
    o = obj(m)
    g["records"].append({"scene_begin_ts": o.get("begin_ts", now(s)), "score": o.get("score", 0),
                         "team_id": "C%d_%d" % (o.get("u1", 0), o.get("u2", 0))})
    rsp(s, m)


@reg("req_cheat_find_goods_scene_time")
def cheat_scene_time(s, m):
    g = S(s)
    if g["scene"]:
        g["scene"]["stop_ts"] = max(g["scene"]["stop_ts"], now(s)) + 60
    rsp(s, m)


@reg("req_cheat_pass_chapter_level")
def cheat_pass(s, m):
    g = S(s)
    sc = g["scene"]
    if sc:
        for k in sc["targets"]:
            sc["targets"][k] = True
    rsp(s, m)


@reg("req_cheat_find_goods_room_force_close")
def cheat_room_close(s, m):
    g = S(s)
    r = _myroom(g)
    if r:
        g["rooms"].pop(r["id"], None)
        g["room"] = None
    rsp(s, m)


def _cover_all():
    """garante cobertura de todo req_*find_goods* do schema (nao modelados acima: esqueleto code 0)."""
    try:
        for n in schema().c2s_by_name:
            if "find_goods" in n and n not in HANDLERS:
                HANDLERS[n] = handler(lambda s, m: rsp(s, m))
    except Exception:
        pass


_cover_all()
