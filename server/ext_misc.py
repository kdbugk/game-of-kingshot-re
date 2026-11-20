#!/usr/bin/env python3
"""ext_misc.py - handlers reais dos 3 proximos modulos do ranking de cobertura (fuzzcov/RELATORIO.md),
excluindo cfg/cheat/social/warmaps:  (1) garden_GardenCtrl (homeland, 31 msgs)  (2) linkagemonopoly_LinkageMonopolyCtrl
(29 msgs)  (3) truck_escort_TruckEscortCtrl (19 msgs).  Contrato: HANDLERS = {"req_x": fun}; fun(session, m)
usa session.reply/push/account/now(); nunca lanca (decorator `handler` -> code 2 em excecao).
Estado em account.ext_state['hl'|'lm'|'tk'] (memoria). Anti-replay via server_rules.ReplayRegistry (kinds novos
registrados em runtime). Codigos de erro = errcodes.json real."""
from extkit import (cfg, pairs, items, err, now, st, me, grant, spend_or_sandbox, once, rsp, push, handler, obj, rng, schema)

HANDLERS = {}


def reg(name):
    def d(fn):
        HANDLERS[name] = handler(fn)
        return fn
    return d


def pt(o):
    o = o or {}
    return (int(o.get("x", 0)), int(o.get("y", 0)))


def P(t):
    return {"x": t[0], "y": t[1]}


# ======================================================================= (1) HOMELAND / GARDEN
COIN_ITEM = 118      # moeda do jardim (garden_config.assists_num_award / prosperity reward usam 118)


def _hl_init():
    return {"b": {}, "wh": {}, "boxes": [], "coin": 0, "tree_t": 0, "skins": {}, "cur_skin": {}, "store": {},
            "like_count": 0, "like_time": 0, "liked": [], "assist_count": 0, "assist_t": 0, "assisted": 0, "belike": [],
            "assist_rec": [], "prosp_done": [], "fell": [], "all_fell": False, "wood": 0, "npc": {}, "site": False,
            "site_coin": 0, "cabin_val": 0, "quest_next": {}, "enter_t": 0, "last_npc": 0}


def H(s):
    return st(s, "hl", _hl_init)


def _hl_prosperity(h):
    return sum(v["level"] for v in h["b"].values())


def _hl_binfo(h):
    out = []
    for p, v in sorted(h["b"].items()):
        o = {"bid": v["bid"], "level": v["level"], "point": P(p), "toward": v["toward"]}
        out.append(o)
    return out


def _hl_info(s, h):
    t = now(s)
    return {"warehouse_info": {"building_infos": [{"bid": b, "level": l, "count": c} for (b, l), c in sorted(h["wh"].items()) if c > 0],
                               "item_infos": [], "skin_infos": [{"id": k, "level": v["level"], "start_time": v.get("start", 0), "end_time": v.get("end", 0)}
                                                                 for k, v in sorted(h["skins"].items())]},
            "map_info": {"building_infos": _hl_binfo(h), "open_space_infos": [], "skin_infos": [{"scene_id": a, "skin_id": b} for a, b in sorted(h["cur_skin"].items())],
                         "life_tree_info": {"cur_value": 1, "last_recovery_time": h["tree_t"] or t}, "fell_tree_infos": h["fell"], "is_fell_all_tree": h["all_fell"]},
            "store_info": {"limit_update_time": t + 604800, "limit_buy_item_infos": [{"id": k, "count": v, "limit_update_time": t + 604800} for k, v in sorted(h["store"].items())]},
            "assist_info": {"last_update_time": h["assist_t"], "assist_count": h["assist_count"], "assisted_count": h["assisted"], "last_assisted_time": 0},
            "unlock": True,
            "like_info": {"total_belike_count": len(h["belike"]), "daily_like_time": h["like_time"], "daily_like_count": h["like_count"], "is_self_like": False},
            "max_prosperity_value": _hl_prosperity(h),
            "prosperity_task_info": {"reward_tasks": [{"k": int(k), "v": int(k) in h["prosp_done"]} for k in sorted(cfg("garden_prosperity_task"), key=int)]}}


@reg("req_homeland_enter_homeland")
def hl_enter(s, m):
    h = H(s)
    h["enter_t"] = now(s)
    rsp(s, m, building_infos=_hl_binfo(h), open_space_infos=[], fell_tree_infos=h["fell"], is_fell_all_tree=h["all_fell"],
        last_record_time=h["tree_t"])


@reg("req_homeland_exit_homeland")
def hl_exit(s, m):
    rsp(s, m)


@reg("req_homeland_place_building")
def hl_place(s, m):
    h = H(s)
    o = obj(m)
    p = pt(o.get("point"))
    if p in h["b"]:
        return rsp(s, m, err("err_homeland_can_not_put_building"))
    key = (o.get("bid", 0), o.get("level", 1))
    if h["wh"].get(key, 0) > 0:
        h["wh"][key] -= 1
    h["b"][p] = {"bid": o.get("bid", 0), "level": o.get("level", 1), "toward": o.get("toward", 0)}
    rsp(s, m)


@reg("req_homeland_move_building")
def hl_move(s, m):
    h = H(s)
    infos = obj(m).get("point_infos") or []
    moves = []
    for i in infos:
        a, b = pt(i.get("src_point")), pt(i.get("dst_point"))
        if a not in h["b"]:
            return rsp(s, m, err("err_homeland_no_exist_building"))
        moves.append((a, b, i.get("dst_toward", 0)))
    taken = {a for a, _, _ in moves}
    for a, b, _ in moves:
        if b in h["b"] and b not in taken:
            return rsp(s, m, err("err_homeland_forbid_place_building"))
    tmp = [(b, h["b"].pop(a), tw) for a, b, tw in moves]
    for b, v, tw in tmp:
        v["toward"] = tw
        h["b"][b] = v
    rsp(s, m)


@reg("req_homeland_upgrade_building")
def hl_upgrade(s, m):
    h = H(s)
    o = obj(m)
    p = pt(o.get("point"))
    v = h["b"].get(p)
    if not v:
        return rsp(s, m, err("err_homeland_no_exist_building"))
    v["level"] = o.get("level", v["level"] + 1) or v["level"] + 1
    rsp(s, m)


@reg("req_homeland_recovery_building")
def hl_recovery(s, m):
    h = H(s)
    out = []
    for p in (pt(x) for x in obj(m).get("points") or []):
        v = h["b"].pop(p, None)
        if not v:
            continue
        h["wh"][(v["bid"], v["level"])] = h["wh"].get((v["bid"], v["level"]), 0) + 1
        coin = 10 * v["level"]
        h["coin"] += coin
        out.append({"point": P(p), "coin_count": coin})
    rsp(s, m, building_infos=out)


@reg("req_homeland_disassemble_building")
def hl_disassemble(s, m):
    h = H(s)
    o = obj(m)
    key = (o.get("bid", 0), o.get("level", 1))
    n = o.get("count", 1) or 1
    if o.get("type", 0) == 1 and pt(o.get("point")) in h["b"]:
        h["b"].pop(pt(o.get("point")))
    elif h["wh"].get(key, 0) >= n:
        h["wh"][key] -= n
    else:
        return rsp(s, m, err("err_homeland_building_count_not_enough"))
    coin = 5 * key[1] * n
    h["coin"] += coin
    rsp(s, m, building_infos=[{"point": o.get("point") or P((0, 0)), "coin_count": coin}])


@reg("req_homeland_repair_building")
def hl_repair(s, m):
    h = H(s)
    if pt(obj(m).get("point")) not in h["b"]:
        return rsp(s, m, err("err_homeland_no_exist_building"))
    rsp(s, m)


@reg("req_homeland_open_box")
def hl_open_box(s, m):
    h = H(s)
    p = pt(obj(m).get("point"))
    if list(p) in h["boxes"]:
        return rsp(s, m, err("err_homeland_box_is_open"))
    h["boxes"].append(list(p))
    grant(s, [(COIN_ITEM, 100)])
    rsp(s, m)


@reg("req_homeland_take_life_tree_coin")
def hl_tree_coin(s, m):
    h = H(s)
    t = now(s)
    last = h["tree_t"] or (t - 3600)
    speed = (cfg("garden_config").get("1") or {}).get("garden_coin_speed", 40)
    coin = min(int((t - last) / 3600 * speed) + 1, speed * 12)
    h["tree_t"] = t
    h["coin"] += coin
    grant(s, [(COIN_ITEM, coin)])
    rsp(s, m, add_coin=coin)


@reg("req_homeland_take_logging_site")
def hl_take_site(s, m):
    h = H(s)
    if h["site"]:
        return rsp(s, m, err("err_homeland_have_logging_site"))
    h["site"] = True
    rsp(s, m)


@reg("req_homeland_take_logging_site_coin")
def hl_site_coin(s, m):
    h = H(s)
    c = h["site_coin"]
    if c <= 0:
        return rsp(s, m, err("err_homeland_logging_site_no_coin_can_take"))
    h["site_coin"] = 0
    grant(s, [(COIN_ITEM, c)])
    rsp(s, m, coin_count=c, npc_infos=[{"id": k, "begin_time": v} for k, v in sorted(h["npc"].items())])


@reg("req_homeland_logging_site_npc_opt")
def hl_site_npc(s, m):
    h = H(s)
    o = obj(m)
    nid = o.get("npc_id", 0)
    if o.get("opt_type", 0) == 1:
        h["npc"][nid] = now(s)
        h["site_coin"] += 20
    else:
        h["npc"].pop(nid, None)
    h["wood"] += 10
    rsp(s, m, cur_value=h["wood"], npc_info={"id": nid, "begin_time": h["npc"].get(nid, 0)})


@reg("req_homeland_take_logging_cabin_tree")
def hl_cabin_tree(s, m):
    h = H(s)
    c = h["cabin_val"] or 5
    h["cabin_val"] = 0
    h["coin"] += c
    grant(s, [(COIN_ITEM, c)])
    rsp(s, m, cur_value=0, coin_count=c)


@reg("req_homeland_save_npc_wood")
def hl_save_wood(s, m):
    h = H(s)
    o = obj(m)
    if o.get("value", 0) < 0:
        return rsp(s, m, err("err_homeland_save_npc_wood_value_error"))
    h["cabin_val"] += o.get("value", 0)
    h["last_npc"] = now(s)
    rsp(s, m, last_npc_commit_time=h["last_npc"])


@reg("req_homeland_commit_npc_wood")
def hl_commit_wood(s, m):
    h = H(s)
    if not h["cabin_val"]:
        return rsp(s, m, err("err_homeland_npc_no_enough_wood"))
    h["wood"] += h["cabin_val"]
    rsp(s, m, total_value=h["wood"])


@reg("req_homeland_save_offline_npc_wood")
def hl_save_offline(s, m):
    h = H(s)
    h["cabin_val"] += sum(x.get("value", 0) for x in obj(m).get("npc_fell_wood_infos") or [])
    rsp(s, m, building_infos=_hl_binfo(h), open_space_infos=[], fell_tree_infos=h["fell"], is_fell_all_tree=h["all_fell"])


# ---- loja / skins
def _shop_row(item_id):
    c = cfg("garden_shop")
    return next((v for v in c.values() if v.get("id") == item_id), None)


@reg("req_homeland_buy_store_item")
def hl_buy(s, m):
    h = H(s)
    it = obj(m).get("item") or {}
    row = _shop_row(it.get("id"))
    if row is None:
        return rsp(s, m, err("err_homeland_item_can_not_buy"))
    n = max(1, it.get("count", 1))
    if row.get("is_limit") and h["store"].get(it["id"], 0) + n > max(1, row.get("frequency", 1)):
        return rsp(s, m, err("err_homeland_buy_item_over_limit"))
    price = row.get("selling_price", 0) * n
    if price and not spend_or_sandbox(s, [(COIN_ITEM, price)]):
        return rsp(s, m, err("err_homeland_buy_item_condition_not_enough"))
    h["store"][it["id"]] = h["store"].get(it["id"], 0) + n
    h["wh"][(it["id"], 1)] = h["wh"].get((it["id"], 1), 0) + n
    rsp(s, m, limit_update_time=now(s) + 604800)


@reg("req_homeland_sell_store_item")
def hl_sell(s, m):
    h = H(s)
    b = obj(m).get("building_info") or {}
    key = (b.get("bid", 0), b.get("level", 1))
    n = max(1, b.get("count", 1))
    if h["wh"].get(key, 0) < n:
        return rsp(s, m, err("err_homeland_building_count_not_enough"))
    row = _shop_row(key[0])
    if row is not None and not row.get("recycling_price", 0):
        pass
    h["wh"][key] -= n
    grant(s, [(COIN_ITEM, (row or {}).get("recycling_price", 0) * n)])
    rsp(s, m)


@reg("req_homeland_exchange_universal_piece")
def hl_exchange_piece(s, m):
    h = H(s)
    o = obj(m)
    n = max(1, o.get("count", 1))
    key = (o.get("bid", 0), 1)
    h["wh"][key] = h["wh"].get(key, 0) + n
    rsp(s, m)


@reg("req_homeland_skin_item_exchange")
def hl_skin_item(s, m):
    h = H(s)
    o = obj(m)
    if not o.get("item_id"):
        return rsp(s, m, err("err_homeland_item_can_not_exchange"))
    h["skins"].setdefault(o["item_id"], {"level": 1, "start": 0, "end": 0})
    rsp(s, m)


@reg("req_homeland_set_skin")
def hl_set_skin(s, m):
    h = H(s)
    o = obj(m)
    if o.get("skin_id") not in h["skins"] and o.get("skin_id"):
        return rsp(s, m, err("err_homeland_no_scene_skin"))
    if h["cur_skin"].get(o.get("scene_id")) == o.get("skin_id"):
        return rsp(s, m, err("err_homeland_same_skin"))
    h["cur_skin"][o.get("scene_id")] = o.get("skin_id")
    rsp(s, m)


@reg("req_homeland_skin_upgrade")
def hl_skin_up(s, m):
    h = H(s)
    o = obj(m)
    sk = h["skins"].setdefault(o.get("skin_id", 0), {"level": 1, "start": 0, "end": 0})
    if sk["end"] > now(s):
        return rsp(s, m, err("err_homeland_scene_skin_is_uprade"))
    t = now(s)
    sk["start"] = t
    sk["end"] = t if o.get("immediate") else t + 3600
    if sk["end"] <= t:
        sk["level"] += 1
    rsp(s, m, start_time=sk["start"], end_time=sk["end"])


@reg("req_homeland_skin_upgrade_speed_up")
def hl_skin_speed(s, m):
    h = H(s)
    o = obj(m)
    sk = h["skins"].get(o.get("skin_id", 0))
    if not sk or sk["end"] <= now(s):
        return rsp(s, m, err("err_homeland_scene_skin_not_in_uprade"))
    sk["end"] = now(s)
    sk["level"] += 1
    rsp(s, m, give_change=[], end_time=sk["end"])


# ---- prosperidade / quests / social
@reg("req_homeland_prosperity_task_reward")
def hl_prosp(s, m):
    h = H(s)
    tid = obj(m).get("task_id", 0)
    row = cfg("garden_prosperity_task").get(str(tid))
    if not row:
        return rsp(s, m, err("err_homeland_can_not_take_prosperity_task_reward"))
    if _hl_prosperity(h) < row.get("req", 0):
        return rsp(s, m, err("err_homeland_prosperity_value_not_enough"))
    e = once(s, "homeland_prosperity", "%s:%s" % (me(s)["uid"], tid), "err_homeland_already_take_prosperity_task_reward")
    if e:
        return rsp(s, m, e)
    h["prosp_done"].append(tid)
    grant(s, pairs(row.get("reward")))
    rsp(s, m)


@reg("req_get_homestead_quest_award")
def hl_quest_award(s, m):
    h = H(s)
    q = obj(m).get("questid", 0)
    e = once(s, "homestead_quest", q, "err_homeland_already_take_guide_box_reward")
    if e:
        return rsp(s, m, e)
    grant(s, [(COIN_ITEM, 50)])
    rsp(s, m, next_quest_list=[q + 1] if q else [])


@reg("req_homeland_like_homeland")
def hl_like(s, m):
    h = H(s)
    o = obj(m)
    t = now(s)
    if o.get("like"):
        if h["like_count"] >= (cfg("garden_config").get("1") or {}).get("like_day_num_limit", 100):
            return rsp(s, m, err("err_homeland_over_daily_like_count"))
        if o.get("uid") in h["liked"]:
            return rsp(s, m, err("err_homeland_is_like"))
        h["liked"].append(o.get("uid"))
        h["like_count"] += 1
    else:
        if o.get("uid") not in h["liked"]:
            return rsp(s, m, err("err_homeland_not_like"))
        h["liked"].remove(o.get("uid"))
    h["like_time"] = t
    rsp(s, m, daily_like_time=t, daily_like_count=h["like_count"])


@reg("req_homeland_visit_other_homeland")
def hl_visit(s, m):
    h = H(s)
    o = obj(m)
    if o.get("uid") == me(s)["uid"]:
        return rsp(s, m, homeland_info=_hl_info(s, h), is_like=False)
    r = rng(o.get("uid", 0))
    other = _hl_init()
    for i in range(r.randint(3, 8)):
        other["b"][(r.randint(0, 20), r.randint(0, 20))] = {"bid": r.choice([1001, 1002, 1003]), "level": r.randint(1, 5), "toward": 0}
    rsp(s, m, homeland_info=_hl_info(s, other), is_like=o.get("uid") in h["liked"])


@reg("req_homeland_assist")
def hl_assist(s, m):
    h = H(s)
    cf = cfg("garden_config").get("1") or {}
    t = now(s)
    if h["assist_count"] >= cf.get("assists_num", 3):
        return rsp(s, m, err("err_homeland_assist_count_over_limit"))
    if t - h["assist_t"] < 5:
        return rsp(s, m, err("err_homeland_assist_in_cd"))
    h["assist_count"] += 1
    h["assist_t"] = t
    pl = pairs(cf.get("assists_num_award"))
    h["assist_rec"].append({"uid": obj(m).get("uid", 0), "coin": 20, "time": t})
    grant(s, pl or [(COIN_ITEM, 200)])
    info = {"last_update_time": t, "assist_count": h["assist_count"], "assisted_count": h["assisted"], "last_assisted_time": 0}
    rsp(s, m, assist_info=info, self_assist_info=info)


@reg("req_homeland_get_assist_record")
def hl_assist_rec(s, m):
    rsp(s, m, assist_record_infos=H(s)["assist_rec"][-50:])


@reg("req_homeland_get_belike_record")
def hl_belike_rec(s, m):
    rsp(s, m, belike_record_infos=H(s)["belike"][-50:])


# ======================================================================= (2) LINKAGE MONOPOLY
ACT_LM = 2955001
DICE_ITEM, GOLD_DICE_ITEM = 625003, 625004


def _lm_init():
    return {"opened": False, "pos": 1, "points": 0, "team": None, "free_ts": 0, "free_play_ts": 0, "got_stage": [], "boss_got": [],
            "quests": [], "summary_reward": {}, "summary_cost": {}, "applies": [], "my_applies": [], "plays": 0, "seen_cut": False}


def M(s):
    return st(s, "lm", _lm_init)


def _lm_board(group=1):
    return sorted(((v["chequer_id"], v) for v in cfg("monopoly_linkage_chequer").values()
                   if v.get("group_id") == group and v.get("chequer_id") is not None), key=lambda x: x[0])


def _lm_team(s, lm):
    u = me(s)
    if not lm["team"]:
        lm["team"] = {"team_id": 100000 + u["uid"] % 100000, "leader": u["uid"],
                      "members": [{"uid": u["uid"], "kid": u["kid"], "join_ts": now(s), "is_leader": True}], "apply_count": len(lm["applies"])}
    t = lm["team"]
    return {"team_id": t["team_id"], "members": t["members"], "apply_count": len(lm["applies"])}


def _lm_roll(s, lm, n, gold_points=None, cost=None):
    board = _lm_board()
    size = len(board) or 26
    r = rng(now(s) * 31 + lm["plays"])
    pts = []
    for _ in range(n):
        pts.append(gold_points if gold_points else r.randint(1, 6))
    tot = sum(pts)
    lm["plays"] += 1
    lm["pos"] = (lm["pos"] - 1 + tot) % size + 1
    lm["points"] += tot
    row = dict(board).get(lm["pos"]) or {}
    rw = pairs(row.get("prop_chequer_reward"))[:1]
    if rw:
        grant(s, rw)
        for i, c in rw:
            lm["summary_reward"][i] = lm["summary_reward"].get(i, 0) + c
    for i, c in cost or []:
        lm["summary_cost"][i] = lm["summary_cost"].get(i, 0) + c
    return {"cheque_id": lm["pos"], "total_points": lm["points"], "chg_cheque": [], "adventure_box_cheque_id": 0}


def _lm_cost(key):
    row = cfg("monopoly_linkage_consume").get(str(ACT_LM)) or {}
    return pairs(row.get(key))


@reg("req_linkage_monopoly_open_activity")
def lm_open(s, m):
    M(s)["opened"] = True
    rsp(s, m)


@reg("req_linkage_monopoly_mark_cutscene")
def lm_cut(s, m):
    M(s)["seen_cut"] = True
    rsp(s, m)


@reg("req_linkage_monopoly_play_normal_dice")
def lm_normal(s, m):
    lm = M(s)
    n = obj(m).get("count", 1)
    if n not in (1, 5, 10) and n < 1:
        return rsp(s, m, err("err_linkage_monopoly_play_count_error"))
    cost = [(i, c * (n if n != 5 else 1)) for i, c in _lm_cost("monopoly_dice_consume_5" if n == 5 else "monopoly_dice_consume_1")] or [(DICE_ITEM, n)]
    spend_or_sandbox(s, cost)
    rsp(s, m, **_lm_roll(s, lm, 2 if n == 1 else n, cost=cost))


@reg("req_linkage_monopoly_play_gold_dice")
def lm_gold(s, m):
    lm = M(s)
    p = obj(m).get("points", 0)
    if not 1 <= p <= 6:
        return rsp(s, m, err("err_linkage_monopoly_dice_points_error"))
    cost = _lm_cost("monopoly_golden_dice_consume") or [(GOLD_DICE_ITEM, 1)]
    spend_or_sandbox(s, cost)
    rsp(s, m, **_lm_roll(s, lm, 1, gold_points=p, cost=cost))


@reg("req_linkage_monopoly_play_free")
def lm_free(s, m):
    lm = M(s)
    t = now(s)
    if t - lm["free_play_ts"] < 3600 and lm["free_play_ts"]:
        return rsp(s, m, err("err_linkage_monopoly_play_count_error"))
    lm["free_play_ts"] = t
    o = _lm_roll(s, lm, 1)
    o["free_play_time"] = t
    rsp(s, m, **o)


@reg("req_cheat_linkage_monopoly_play_dice_points")
def lm_cheat_dice(s, m):
    lm = M(s)
    plays = []
    last = {}
    for p in obj(m).get("cheat_points") or []:
        last = _lm_roll(s, lm, 1, gold_points=max(1, min(6, p)))
        plays.append({"count": 1, "points": p, "cheque_id": last["cheque_id"], "reward": [], "event_index": 0,
                      "start_trigger_cheque": [], "adventure_box_lst": [], "atk_boss_count": 0, "teammate_cannon": False, "teammate_dice": False})
    rsp(s, m, cheque_id=lm["pos"], total_points=lm["points"], play_info=plays, chg_cheque=[], adventure_box_cheque_id=0)


@reg("req_linkage_monopoly_get_free_gift")
def lm_gift(s, m):
    lm = M(s)
    e = once(s, "linkage_free_gift", me(s)["uid"], "err_linkage_monopoly_free_gift_today", daily=True)
    if e:
        return rsp(s, m, e)
    lm["free_ts"] = now(s)
    grant(s, [(DICE_ITEM, 3)])
    rsp(s, m, last_get_free_gift_ts=lm["free_ts"])


def _lm_claim_rows(s, lm, table, field, done_key):
    rows = cfg(table)
    got = []
    for k in sorted(rows, key=int):
        r = rows[k]
        if r.get("group_id", 1) == 1 and r.get("points_sum", 1 << 30) <= lm["points"] and int(k) not in lm[done_key]:
            lm[done_key].append(int(k))
            got += pairs(r.get("reward"))
    return got


@reg("req_linkage_monopoly_get_reward")
def lm_get_reward(s, m):
    lm = M(s)
    stage = obj(m).get("stage", 0)
    rows = cfg("monopoly_linkage_extra_reward")
    row = rows.get(str(stage))
    if not row:
        return rsp(s, m, err("err_linkage_monopoly_get_reward_stage_error"))
    if row.get("points_sum", 0) > lm["points"]:
        return rsp(s, m, err("err_linkage_monopoly_points_not_enough"))
    e = once(s, "linkage_stage", "%s:%s" % (me(s)["uid"], stage), "err_linkage_monopoly_already_get_reward")
    if e:
        return rsp(s, m, e)
    lm["got_stage"].append(stage)
    rw = grant(s, pairs(row.get("reward")))
    rsp(s, m, rewards=rw, received_mark=[{"k": k, "v": True} for k in sorted(lm["got_stage"])])


@reg("req_linkage_monopoly_get_boss_reward")
def lm_boss(s, m):
    lm = M(s)
    got = _lm_claim_rows(s, lm, "monopoly_linkage_boss_reward", "reward", "boss_got")
    if not got:
        return rsp(s, m, err("err_linkage_monopoly_boss_reward_not_available"))
    rsp(s, m, rewards=grant(s, got), boss_extra_reward_count=len(lm["boss_got"]))


@reg("req_linkage_monopoly_get_quest_reward")
def lm_quest(s, m):
    lm = M(s)
    q = obj(m).get("quest_id", 0)
    e = once(s, "linkage_quest", "%s:%s" % (me(s)["uid"], q), "err_linkage_monopoly_already_get_reward", daily=True)
    if e:
        return rsp(s, m, e)
    lm["quests"].append(q)
    grant(s, [(DICE_ITEM, 1)])
    rsp(s, m)


@reg("req_linkage_monopoly_rewards_summary")
def lm_summary(s, m):
    lm = M(s)
    rsp(s, m, reward=items(sorted(lm["summary_reward"].items())), cost=items(sorted(lm["summary_cost"].items())), ret1=[])


@reg("req_linkage_monopoly_record_reward_id")
def lm_record(s, m):
    rsp(s, m)


@reg("req_linkage_monopoly_watch_winning_info")
def lm_watch(s, m):
    rsp(s, m)


@reg("req_linkage_monopoly_watch_winning_info_rsp")
def lm_watch2(s, m):
    rsp(s, m)


@reg("req_linkage_monopoly_claim_teammate_gift")
def lm_tm_gift(s, m):
    lm = M(s)
    if not lm["team"] or len(lm["team"]["members"]) < 2:
        return rsp(s, m, err("err_linkage_monopoly_no_teammate_reward"))
    e = once(s, "linkage_tm_gift", me(s)["uid"], "err_linkage_monopoly_no_teammate_reward", daily=True)
    if e:
        return rsp(s, m, e)
    rsp(s, m, rewards=grant(s, [(DICE_ITEM, 2)]), atk_boss_count=1)


# ---- equipes (solo/sintetico; sem outros jogadores reais)
def _fake_team(i):
    return {"team_id": 200000 + i, "members": [{"uid": 800000 + i, "kid": 1, "join_ts": 1, "is_leader": True}]}


@reg("req_linkage_monopoly_get_team_detail")
def lm_team_detail(s, m):
    lm = M(s)
    rsp(s, m, team_info=_lm_team(s, lm), boss_damages=[{"k": me(s)["uid"], "v": lm["points"] * 100}], assist_records=[])


@reg("req_linkage_monopoly_get_other_team_info")
def lm_other_team(s, m):
    tid = obj(m).get("team_id", 0)
    t = _fake_team(tid % 1000)
    t["team_id"] = tid
    rsp(s, m, team_info=dict(t, apply_count=0))


@reg("req_linkage_monopoly_get_recommend_teams")
def lm_recommend(s, m):
    rsp(s, m, teams=[_fake_team(i) for i in range(1, 4)])


@reg("req_linkage_monopoly_get_my_applies")
def lm_my_applies(s, m):
    lm = M(s)
    rsp(s, m, teams=[_fake_team(i % 1000) for i in lm["my_applies"]])


@reg("req_linkage_monopoly_apply_team")
def lm_apply(s, m):
    lm = M(s)
    tid = obj(m).get("team_id", 0)
    if len(lm["my_applies"]) >= 10:
        return rsp(s, m, err("err_linkage_monopoly_apply_limit"))
    if tid in lm["my_applies"]:
        return rsp(s, m, err("err_linkage_monopoly_has_applied"))
    lm["my_applies"].append(tid)
    rsp(s, m)


@reg("req_linkage_monopoly_cancel_apply")
def lm_cancel(s, m):
    lm = M(s)
    tid = obj(m).get("team_id", 0)
    if tid not in lm["my_applies"]:
        return rsp(s, m, err("err_linkage_monopoly_apply_not_exist"))
    lm["my_applies"].remove(tid)
    rsp(s, m)


@reg("req_linkage_monopoly_get_apply_list")
def lm_apply_list(s, m):
    rsp(s, m, applies=[{"uid": a, "apply_ts": now(s)} for a in M(s)["applies"]])


@reg("req_linkage_monopoly_accept_apply")
def lm_accept_apply(s, m):
    lm = M(s)
    u = obj(m).get("target_uid")
    if u not in lm["applies"]:
        return rsp(s, m, err("err_linkage_monopoly_apply_not_exist"))
    t = _lm_team(s, lm)
    if len(lm["team"]["members"]) >= 2:
        return rsp(s, m, err("err_linkage_monopoly_team_full"))
    lm["applies"].remove(u)
    lm["team"]["members"].append({"uid": u, "kid": me(s)["kid"], "join_ts": now(s), "is_leader": False})
    rsp(s, m, team_info=_lm_team(s, lm))


@reg("req_linkage_monopoly_accept_invite")
def lm_accept_invite(s, m):
    lm = M(s)
    tid = obj(m).get("team_id", 0)
    if lm["team"] and len(lm["team"]["members"]) > 1:
        return rsp(s, m, err("err_linkage_monopoly_already_in_team"))
    lm["team"] = None
    t = _lm_team(s, lm)
    lm["team"]["team_id"] = tid or lm["team"]["team_id"]
    lm["team"]["members"].insert(0, {"uid": 800000 + tid % 1000, "kid": 1, "join_ts": now(s), "is_leader": True})
    lm["team"]["members"][1]["is_leader"] = False
    rsp(s, m, team_info=_lm_team(s, lm))


@reg("req_linkage_monopoly_reject_apply")
def lm_reject(s, m):
    lm = M(s)
    u = obj(m).get("target_uid")
    if u not in lm["applies"]:
        return rsp(s, m, err("err_linkage_monopoly_apply_not_exist"))
    lm["applies"].remove(u)
    rsp(s, m)


@reg("req_linkage_monopoly_reject_all_apply")
def lm_reject_all(s, m):
    M(s)["applies"] = []
    rsp(s, m)


@reg("req_linkage_monopoly_kick_member")
def lm_kick(s, m):
    lm = M(s)
    u = obj(m).get("target_uid")
    if not lm["team"]:
        return rsp(s, m, err("err_linkage_monopoly_not_in_team"))
    if u == me(s)["uid"]:
        return rsp(s, m, err("err_linkage_monopoly_not_leader"))
    lm["team"]["members"] = [x for x in lm["team"]["members"] if x["uid"] != u or x["is_leader"] and x["uid"] == me(s)["uid"]]
    rsp(s, m)


@reg("req_linkage_monopoly_quit_team")
def lm_quit(s, m):
    lm = M(s)
    t = lm["team"]
    if not t or len(t["members"]) < 2:
        return rsp(s, m, err("err_linkage_monopoly_not_in_team"))
    if t["leader"] == me(s)["uid"]:
        return rsp(s, m, err("err_linkage_monopoly_leader_cannot_quit"))
    lm["team"] = None
    rsp(s, m)


@reg("req_linkage_monopoly_get_invite_list")
def lm_invite_list(s, m):
    rsp(s, m, friends=[], reload=False, channel_invites=[])


# ======================================================================= (3) TRUCK ESCORT
def _tk_init():
    return {"trucks": {}, "assist_unit": None, "plunder_count": 0, "last_plunder": 0, "last_list": 0, "last_enemy": 0,
            "records": [], "seeded": False, "reports": {}, "filter": [False, False]}


def T(s):
    t = st(s, "tk", _tk_init)
    if not t["seeded"]:
        t["seeded"] = True
        n = now(s)
        for slot in (1, 2, 3):
            t["trucks"][slot] = {"slot_id": slot, "id": slot, "quality": slot + 1, "begin": n - 7200, "total": 3600, "route": 1,
                                 "diamond": 0, "random_count": 0, "done": False}
    return t


def _truck_items(q):
    ids = [i for i in (cfg("truck_escort_group").get("1") or {}).get("reward_c", {}).values()] or [500220, 500240]
    return [(i, q * (k + 1)) for k, i in enumerate(ids[:3])]


def _truck_struct(tr):
    b = items(_truck_items(tr["quality"]))
    return {"slot_id": tr["slot_id"], "id": tr["id"], "quality": tr["quality"], "basis_reward_items": b,
            "random_reward_items": items([(101, 1000 * tr["quality"])]),
            "march_info": {"route_id": tr["route"], "total_time": tr["total"], "march_id": 7000 + tr["slot_id"], "begin_time": tr["begin"], "kid": 1,
                           "start_point": P((10, 10)), "old_total_time": tr["total"]},
            "is_finish": tr["done"], "diamond_count": tr["diamond"], "assist_uid": 0, "plundered_basis_items": [], "plundered_random_items": [],
            "predator_infos": [], "random_count": tr["random_count"], "be_plundered": 0, "aid": 0, "free_random_count": 1,
            "extra_reward_items": [], "take_back_reward_items_array": [], "expert_items_array": [], "expert_quality_drop_id": 0}


def _cover_list(s, n, base, t):
    r = rng(base)
    out = []
    for i in range(n):
        u = 70000 + r.randint(0, 9999)
        out.append({"kid": 1, "uid": u, "id": i + 1, "quality": r.randint(1, 5), "abbr": "NPC", "name": "Caravana%d" % (u % 1000),
                    "endtime": t + r.randint(600, 3600), "starttime": t - r.randint(0, 600), "route_id": r.randint(1, 5),
                    "startpoint": P((r.randint(1, 100), r.randint(1, 100))), "be_plundered": r.randint(0, 1), "owner_kid": 1, "aid": 0})
    return out


@reg("req_truck_escort_new_plunder_list")
def tk_new_plunder(s, m):
    t = T(s)
    n = now(s)
    t["last_list"] = t["last_list"] or n
    rsp(s, m, trucks=_cover_list(s, 8, t["last_list"], n), last_refresh_list=t["last_list"])


@reg("req_truck_escort_refresh_plunder_list")
def tk_refresh_plunder(s, m):
    t = T(s)
    n = now(s)
    if n - t["last_list"] < 3 and t["last_list"]:
        return rsp(s, m, err("err_truck_escort_requested_too_frequently"))
    t["last_list"] = n
    rsp(s, m, trucks=_cover_list(s, 8, n, n), last_refresh_list=n)


@reg("req_truck_escort_new_enemy_list")
def tk_new_enemy(s, m):
    t = T(s)
    n = now(s)
    t["last_enemy"] = t["last_enemy"] or n
    rsp(s, m, trucks=_cover_list(s, 5, t["last_enemy"] + 1, n), last_refresh_enemy_list=t["last_enemy"])


@reg("req_truck_escort_refresh_enemy_list")
def tk_refresh_enemy(s, m):
    t = T(s)
    n = now(s)
    if n - t["last_enemy"] < 3 and t["last_enemy"]:
        return rsp(s, m, err("err_truck_escort_requested_too_frequently"))
    t["last_enemy"] = n
    rsp(s, m, trucks=_cover_list(s, 5, n + 1, n), last_refresh_enemy_list=n)


@reg("req_truck_escort_fliter_kingdom_self")
def tk_filter(s, m):
    o = obj(m)
    T(s)["filter"] = [bool(o.get("fliter")), bool(o.get("enemy_fliter"))]
    rsp(s, m)


@reg("req_truck_escort_get_other_truck_info")
def tk_other_info(s, m):
    o = obj(m)
    if o.get("uid") == me(s)["uid"]:
        return rsp(s, m, err("err_truck_escort_can_not_fight_self"))
    q = 1 + (o.get("truck_id", 1) % 5)
    tr = {"slot_id": 1, "id": o.get("truck_id", 1), "quality": q, "begin": now(s) - 600, "total": 3600, "route": 1, "diamond": 0, "random_count": 0, "done": False}
    rsp(s, m, truck_info=_truck_struct(tr))


@reg("req_truck_escort_get_truck_assist_formation")
def tk_assist_formation(s, m):
    rsp(s, m, formation={"hero_map": [], "soldier_map": [], "power": 0}, nick="")


@reg("req_truck_escort_get_assist_info")
def tk_assist_info(s, m):
    rsp(s, m, list=[])


@reg("req_truck_escort_get_assist_unit")
def tk_assist_unit(s, m):
    t = T(s)
    u = t["assist_unit"]
    if not u:
        return rsp(s, m, err("err_truck_escort_truck_no_assist"))
    rsp(s, m, unit=u)


@reg("req_truck_escort_issue_assisting_unit")
def tk_issue(s, m):
    t = T(s)
    if t["assist_unit"]:
        return rsp(s, m, err("err_truck_escort_already_send_truck"))
    t["assist_unit"] = {"uid": me(s)["uid"], "hero_map": [], "power": 1000 * len(obj(m).get("hero_id") or []), "lock_uid": 0,
                        "finish_ts": now(s) + 6 * 3600, "count": 0, "soldier_map": [], "quality": 1, "expert_info": []}
    rsp(s, m)


@reg("req_truck_escort_modify_assisting_unit")
def tk_modify(s, m):
    t = T(s)
    if not t["assist_unit"]:
        return rsp(s, m, err("err_truck_escort_truck_no_assist"))
    t["assist_unit"]["power"] = 1000 * len(obj(m).get("hero_id") or [])
    rsp(s, m)


@reg("req_truck_escort_withdraw_assisting_unit")
def tk_withdraw(s, m):
    t = T(s)
    if not t["assist_unit"]:
        return rsp(s, m, err("err_truck_escort_truck_no_assist"))
    t["assist_unit"] = None
    rsp(s, m)


@reg("req_truck_escort_take_truck_reward")
def tk_take(s, m):
    t = T(s)
    o = obj(m)
    tr = t["trucks"].get(o.get("truck_id"))
    if not tr:
        return rsp(s, m, err("err_truck_escort_no_exist_truck"))
    if tr["done"]:
        return rsp(s, m, err("err_truck_escort_already_send_truck"))
    if now(s) < tr["begin"] + tr["total"]:
        return rsp(s, m, err("err_truck_escort_truck_not_finish"))
    e = once(s, "truck_take", "%s:%s:%s" % (me(s)["uid"], tr["slot_id"], tr["begin"]), "err_truck_escort_already_send_truck")
    if e:
        return rsp(s, m, e)
    tr["done"] = True
    basis = grant(s, _truck_items(tr["quality"]))
    rand = grant(s, [(101, 1000 * tr["quality"])])
    pass
    ts = _truck_struct(tr)
    rsp(s, m, basis_reward_items=basis, random_reward_items=rand, truck_info=ts, formation_info={"hero_map": [], "soldier_map": [], "power": 0},
        extra_reward_items=[], take_back_reward_items=[], expert_total_take_truck_reward_count=sum(1 for x in t["trucks"].values() if x["done"]), expert_refresh_quality_count=0)


@reg("req_truck_escort_refresh_truck_reward")
def tk_refresh_reward(s, m):
    t = T(s)
    o = obj(m)
    tr = t["trucks"].get(o.get("truck_id"))
    if not tr:
        return rsp(s, m, err("err_truck_escort_no_exist_truck"))
    if tr["done"]:
        return rsp(s, m, err("err_truck_escort_already_send_truck"))
    cost = pairs(((cfg("truck_escort_diamond_cost").get(str(min(5, tr["diamond"] + 1)))) or {}).get("cost"))
    if o.get("use_diamond") and cost:
        spend_or_sandbox(s, cost)
        tr["diamond"] += 1
    tr["random_count"] += 1
    r = rng(tr["random_count"] * 131 + tr["slot_id"])
    tr["quality"] = max(tr["quality"], r.randint(1, 5)) if o.get("use_diamond") else r.randint(1, 5)
    rsp(s, m, truck_info=_truck_struct(tr))


@reg("req_truck_escort_get_truck_record")
def tk_records(s, m):
    rsp(s, m, record_infos=[])


@reg("req_truck_escort_plunder_records")
def tk_plunder_records(s, m):
    rsp(s, m, records=T(s)["records"][-50:])


@reg("req_truck_escort_plunder_battle_report")
def tk_report(s, m):
    rid = obj(m).get("record_id", 0)
    rep = T(s)["reports"].get(rid)
    if rep is None:
        return rsp(s, m, err("err_truck_escort_report_not_exist"))
    rsp(s, m, report=rep)


@reg("req_truck_escort_plunder_fight")
def tk_fight(s, m):
    t = T(s)
    o = obj(m)
    n = now(s)
    if o.get("target_uid") == me(s)["uid"]:
        return rsp(s, m, err("err_truck_escort_can_not_fight_self"))
    if t["plunder_count"] >= 5:
        return rsp(s, m, err("err_truck_escort_not_enough_count"))
    if n - t["last_plunder"] < 2 and t["last_plunder"]:
        return rsp(s, m, err("err_truck_escort_fight_too_soon"))
    heroes = o.get("map_heros") or []
    win = len(heroes) > 0
    t["plunder_count"] += 1
    t["last_plunder"] = n
    rid = 5000 + len(t["reports"]) + 1
    t["reports"][rid] = b"report-%d" % rid
    pl = {"plundered_basis_items": [], "plundered_random_items": [], "expert_items": {"basis_items": [], "random_items": [], "expert_effect_map": []}}
    if win:
        pl["plundered_basis_items"] = grant(s, [(i, c // 5 or 1) for i, c in _truck_items(3)])
        pl["plundered_random_items"] = grant(s, [(101, 600)])
    t["records"].append({"id": rid, "cover": {"time": n, "info": {"quality": 3, "kid": 1, "abbr": "NPC", "name": "Caravana", "truck_id": o.get("target_march_id", 1), "uid": o.get("target_uid", 0)},
                                                "items": dict(pl), "take_back_reward_items": {}}})
    rsp(s, m, win=win, items=pl, plunder_count=t["plunder_count"], count_refresh_stage=1, last_plunder_time=n, target_report_id=rid,
        take_back_reward_items={"basis_items": [], "random_items": [], "expert_effect_map": []})


def _cover_all():
    """qualquer req do modulo nao modelado: esqueleto code 0."""
    try:
        for n, p in schema().c2s_by_name.items():
            if n.startswith(("req_homeland_", "req_linkage_monopoly_", "req_truck_escort_")) and n not in HANDLERS:
                HANDLERS[n] = handler(lambda s, m: rsp(s, m))
    except Exception:
        pass


_cover_all()
