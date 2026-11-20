# -*- coding: utf-8 -*-
"""ext_worldmap.py — handlers reais p/ MAPA-MUNDI + CAPITAL (king war). Contrato: HANDLERS={"req_x": fun(session,m)}.
Usa session.reply/push/account/now(). Nunca lança. Estado por sessão em session._wm (dict).
Premissas (ver RELATORIO_WARMAPS.md): world_mapobj.type = tag-1 (1 city,2 res,3 monster,4 camp,5 minor fort,6 boss,
7 middle,8 major,16 capital); mapa 1200x1200, capital em (597,597) (world_map_fixed_obj #1)."""
import random, zlib

MAP_W = MAP_H = 1200
CAPITAL_XY = (597, 597)
OBJ_CITY, OBJ_RES, OBJ_MONSTER, OBJ_CAMP, OBJ_MINOR, OBJ_BOSS, OBJ_MIDDLE, OBJ_MAJOR, OBJ_CAPITAL = 1, 2, 3, 4, 5, 6, 7, 8, 16
FIGHT_S = 18000  # capital_war_config.war_fight_time
CAPITAL_CYCLE = 7 * 86400


# ------------------------------------------------------------------ helpers (duplicados no ext_supremacywar de propósito)
def _now(s):
    try:
        return int(s.now())
    except Exception:
        import time
        return int(time.time())


def _acct_base(s):
    try:
        a = getattr(s, "account", None)
        if callable(a):
            a = a()
        if a is None:
            a = getattr(s, "acct", None)
        return dict(getattr(a, "base", None) or {})
    except Exception:
        return {}


_FALLBACK = {}


def _st(s):
    try:
        return s.__dict__.setdefault("_wm", {})
    except Exception:
        return _FALLBACK.setdefault(id(s), {})


def _me(s):
    b = _acct_base(s)
    return {"uid": int(b.get("uid", 1) or 1), "nick": str(b.get("nickName", "player")), "kid": int(b.get("kid", 1) or 1),
            "image": int(b.get("image", 1001) or 1001)}


def _pt(x, y):
    return {"x": int(x), "y": int(y)}


def _city_xy(s):
    st = _st(s)
    if "city" not in st:
        me = _me(s)
        r = random.Random(me["uid"] * 7919)
        st["city"] = (CAPITAL_XY[0] + r.randint(-180, 180), CAPITAL_XY[1] + r.randint(-180, 180))
    return st["city"]


def _clamp(v, lo=0, hi=MAP_W - 1):
    return max(lo, min(hi, int(v)))


def _rsp_spec(s, m):
    try:
        return s.S.c2s_by_name[m["name"]]["response"]
    except Exception:
        return "?"


def _reply(s, m, obj):
    """Responde só se o protocolo tem response."""
    try:
        if _rsp_spec(s, m) is None:
            return
        s.reply(m, obj)
    except Exception:
        pass


def _push(s, name, obj):
    try:
        s.push(name, obj)
    except Exception:
        pass


def _obj(m):
    o = m.get("obj") if isinstance(m, dict) else None
    return o if isinstance(o, dict) else {}


def _safe(fn):
    def w(s, m):
        try:
            fn(s, m)
        except Exception:
            try:
                _reply(s, m, {"code": 1})
            except Exception:
                pass
    w.__name__ = fn.__name__
    return w


def _ok(s, m, **kw):
    _reply(s, m, dict({"code": 0}, **kw))


# ------------------------------------------------------------------ geração sintética do mapa
def _cell_obj(x, y, kid, me_city, me, now):
    """Objeto determinístico por célula (seed = kid,x,y): o mesmo chunk é sempre igual."""
    if (x, y) == tuple(me_city):
        return {"point": _pt(x, y), "type": OBJ_CITY, "map_city": {"uid": me["uid"], "lv": 1, "nickName": me["nick"], "kid": me["kid"],
                "aid": 0, "abbr": "", "shield_endtime": now + 3600, "office": 0}}
    if (x, y) == CAPITAL_XY:
        return {"point": _pt(x, y), "type": OBJ_CAPITAL, "map_capital": {"id": 1, "state": 0, "endtime": 0, "def_kid": kid, "occupied_kid": kid}}
    h = zlib.crc32(f"{kid}:{x}:{y}".encode()) & 0xffffffff
    if x % 4 or y % 4 or h % 9:
        return None
    k = h % 100
    if k < 50:
        return {"point": _pt(x, y), "type": OBJ_RES, "map_resource": {"id": 1250101 + (h >> 8) % 8, "kid": kid, "create_time": now - 600}}
    if k < 85:
        return {"point": _pt(x, y), "type": OBJ_MONSTER, "map_monster": {"id": 7100001 + (h >> 8) % 30, "win": False, "time": now}}
    if k < 95:
        return {"point": _pt(x, y), "type": OBJ_CITY, "map_city": {"uid": 900000 + h % 99999, "lv": 1 + (h >> 8) % 30,
                "nickName": "Gov%d" % (h % 9999), "kid": kid, "aid": 0, "abbr": "", "shield_endtime": 0, "office": 0}}
    return {"point": _pt(x, y), "type": OBJ_MINOR, "map_minor_fort": {"id": h % 70, "state": 0, "time": now, "first": True}}


def build_chunk(s, p0, p1, kid, max_obj=400):
    me = _me(s)
    now = _now(s)
    city = _city_xy(s)
    out = []
    x0, x1 = sorted((_clamp(p0.get("x", 0)), _clamp(p1.get("x", 0))))
    y0, y1 = sorted((_clamp(p0.get("y", 0)), _clamp(p1.get("y", 0))))
    x1 = min(x1, x0 + 120)
    y1 = min(y1, y0 + 120)
    for x in range(x0, x1 + 1):
        for y in range(y0, y1 + 1):
            o = _cell_obj(x, y, kid, city, me, now)
            if o:
                out.append(o)
                if len(out) >= max_obj:
                    return out
    return out


# ------------------------------------------------------------------ handlers de mapa / jogador
@_safe
def h_map_info(s, m):
    o = _obj(m)
    me = _me(s)
    args = o.get("args") if isinstance(o.get("args"), list) else []
    args = [a for a in args if isinstance(a, dict)]
    _ok(s, m)
    sess = int(o.get("session", 0) or 0)
    for a in args or [{"startpoint": _pt(0, 0), "endpoint": _pt(60, 60), "kid": me["kid"]}]:
        kid = int(a.get("kid") or me["kid"])
        objs = build_chunk(s, a.get("startpoint") or _pt(0, 0), a.get("endpoint") or _pt(60, 60), kid)
        _push(s, "notify_world_mapobjs", {"session": sess, "datalist": objs, "end_flag": True, "kid": kid, "lod": int(o.get("lod", 0) or 0)})
        _push(s, "notify_world_marchs", {"session": sess, "datalist": _st(s).get("marchs_list", []), "end_flag": True, "kid": kid})


@_safe
def h_mapobj(s, m):
    o = _obj(m)
    p = o.get("point") or _pt(*_city_xy(s))
    kid = int(o.get("kid") or _me(s)["kid"])
    px, py = int(p.get("x", 0) or 0), int(p.get("y", 0) or 0)
    ob = _cell_obj(px, py, kid, _city_xy(s), _me(s), _now(s)) or {"point": _pt(px, py), "type": 0}
    _ok(s, m, mapobj=ob)


@_safe
def h_map_search(s, m):
    o = _obj(m)
    cx, cy = _city_xy(s)
    r = random.Random(_now(s) // 60 + int(o.get("mapobj_type", 0) or 0))
    _ok(s, m, point=_pt(_clamp(cx + r.randint(-40, 40)), _clamp(cy + r.randint(-40, 40))), is_create=True)


@_safe
def h_map_fog(s, m):
    _ok(s, m, fogid=1)


@_safe
def h_kingdom_info(s, m):
    k = _me(s)["kid"]
    _ok(s, m, count=1, merge_map=[{"k": k, "v": k}])


@_safe
def h_resource_info(s, m):
    now = _now(s)
    st = _st(s).setdefault("res", {})
    p = _obj(m).get("point") or {}
    beg = st.setdefault((p.get("x"), p.get("y")), now - 300)
    _ok(s, m, res_count=50000, collect_begin_time=beg, collect_speed=88, collect_speed_add=0,
        collect_finish_time=now + 3600, collect_buff_info=[], res_load=1000)


@_safe
def h_alliance_resource_info(s, m):
    now = _now(s)
    _ok(s, m, collect_begin_time=now - 300, collect_speed=88, collect_speed_add=0, collect_finish_time=now + 3600, collect_buff_info=[], res_load=1000)


@_safe
def h_territory_buff(s, m):
    _ok(s, m, buff_map=[])


@_safe
def h_del_watch(s, m):
    _ok(s, m)


def _set_city(s, x, y, push_full=False):
    x, y = _clamp(x), _clamp(y)
    _st(s)["city"] = (x, y)
    _push(s, "notify_player_city_update", {"point": _pt(x, y), "be_atk": False, "burn_down": False})
    if push_full:
        _push(s, "notify_world_player_init", {"city_point": _pt(x, y), "march_info": [], "mass_master_marchs": [], "kingdom_count": 1,
              "is_respawned": False, "war_ban_endtime": 0, "jump_kid": 0, "last_jump_time": 0, "jump_free_count": 3})
    return x, y


@_safe
def h_move_city(s, m):
    p = _obj(m).get("point") or {}
    x, y = _set_city(s, p.get("x", 600), p.get("y", 600))
    _ok(s, m, point=_pt(x, y))


@_safe
def h_alliance_move_city(s, m):
    p = _obj(m).get("point") or {}
    x, y = _set_city(s, p.get("x", 600), p.get("y", 600), push_full=True)
    _ok(s, m, point=_pt(x, y))


@_safe
def h_random_move_city(s, m):
    r = random.Random(_now(s))
    x, y = _set_city(s, r.randint(250, 950), r.randint(250, 950))
    _ok(s, m, point=_pt(x, y))


@_safe
def h_move_point(s, m):
    cx, cy = _city_xy(s)
    r = random.Random(cx * 1201 + cy)
    _ok(s, m, point=_pt(_clamp(cx + r.randint(-25, 25)), _clamp(cy + r.randint(-25, 25))))


@_safe
def h_gohome(s, m):
    x, y = _city_xy(s)
    _set_city(s, x, y, push_full=True)
    _ok(s, m)


@_safe
def h_gohome_to_point(s, m):
    p = _obj(m).get("point") or {}
    _set_city(s, p.get("x", 600), p.get("y", 600), push_full=True)
    _ok(s, m)


@_safe
def h_wormhole_random(s, m):
    r = random.Random(_now(s))
    _set_city(s, r.randint(250, 950), r.randint(250, 950), push_full=True)
    _ok(s, m, jump_time=_now(s))


@_safe
def h_wormhole_to_point(s, m):
    p = _obj(m).get("point") or {}
    _set_city(s, p.get("x", 600), p.get("y", 600), push_full=True)
    _ok(s, m)


@_safe
def h_control_list(s, m):
    _ok(s, m, list=[])


@_safe
def h_fort_pro_progress(s, m):
    _ok(s, m, aid=0, time=_now(s), infos=[])


@_safe
def h_noresp(s, m):
    _reply(s, m, {})   # rsp_watch_*/rsp_*: response é struct vazia (sem campo code)


# ------------------------------------------------------------------ CAPITAL (guerra do rei) — estado sintético + estático
def _cap(s):
    st = _st(s)
    if "cap" not in st:
        me = _me(s)
        st["cap"] = {"president": me["uid"], "manifesto": "", "man_ts": 0, "kname": "Kingdom %d" % me["kid"], "kflag": 1,
                     "name_ts": 0, "mode": 0, "mode_ts": 0, "tasks": {}, "task_seq": 0, "apply": {}, "offices": {}, "skills": {},
                     "reward_taken": False}
    return st["cap"]


def capital_phase(now):
    """Ciclo semanal: guerra (FIGHT_S) no fim do ciclo, paz/eleição no resto. Retorna (state 0=paz|1=guerra, end_ts)."""
    base = (now // CAPITAL_CYCLE) * CAPITAL_CYCLE
    t = now - base
    war_start = CAPITAL_CYCLE - 2 * FIGHT_S
    if war_start <= t < war_start + FIGHT_S:
        return 1, base + war_start + FIGHT_S
    return 0, base + (war_start if t < war_start else CAPITAL_CYCLE + war_start)


def _president_data(s):
    c = _cap(s)
    me = _me(s)
    return {"office_map": [], "dominance": 0, "skill_info_map": [], "gift_data": {"uid_set": [], "gift_map": []}, "uid": c["president"],
            "abbr": "", "nickName": me["nick"], "image": me["image"], "aid": 0, "manifesto": c["manifesto"], "term": 1,
            "kingdom_name": c["kname"], "kingdom_flag": c["kflag"], "modify_manifesto_ts": c["man_ts"], "modify_name_ts": c["name_ts"],
            "kid": me["kid"], "aname": "", "modify_name_count": 0, "office_mode": c["mode"], "office_mode_ts": c["mode_ts"], "is_cross_mode": False}


def push_capital_init(s):
    now = _now(s)
    state, end = capital_phase(now)
    c = _cap(s)
    _push(s, "notify_capital_war_init", {"state": state, "endtime": end, "president_data": _president_data(s), "is_winner": True,
          "elect_endtime": end, "show_state": 0, "show_endtime": 0, "is_first": False, "buff_map": [], "president": c["president"],
          "is_cross_mode": False, "office_mode": c["mode"]})
    _push(s, "notify_capital_war_office_init", {"red_dot": [], "apply_info": [{"id": o, "ts": t["ts"], "status": 1} for o, t in c["apply"].items()],
          "auto_agree_map": []})


@_safe
def h_cap_search_alliance(s, m):
    _ok(s, m, aids=[])
    push_capital_init(s)


@_safe
def h_cap_president_info(s, m):
    me = _me(s)
    c = _cap(s)
    _ok(s, m, uid=c["president"], abbr="", nickName=me["nick"], image=me["image"], manifesto=c["manifesto"], is_cross_mode=False,
        kid=me["kid"], aname="")


@_safe
def h_cap_set_manifesto(s, m):
    c = _cap(s)
    t = str(_obj(m).get("manifesto", ""))[:512]
    c["manifesto"] = t
    c["man_ts"] = _now(s)
    _ok(s, m, modify_manifesto_ts=c["man_ts"], manifesto=t, manifesto_ban_ts=0)
    push_capital_init(s)


@_safe
def h_cap_set_kname(s, m):
    c = _cap(s)
    n = str(_obj(m).get("name", "")).strip()
    if not n or len(n) > 24:
        return _reply(s, m, {"code": 2})   # param_illegal (comportamento prod)
    c["kname"] = n
    c["name_ts"] = _now(s)
    _ok(s, m)
    push_capital_init(s)


@_safe
def h_cap_check_name(s, m):
    n = str(_obj(m).get("name", "")).strip()
    _reply(s, m, {"code": 0 if 0 < len(n) <= 24 else 2})


@_safe
def h_cap_set_flag(s, m):
    _cap(s)["kflag"] = int(_obj(m).get("flag", 1) or 1)
    _ok(s, m)
    push_capital_init(s)


@_safe
def h_cap_set_mode(s, m):
    c = _cap(s)
    c["mode"] = int(_obj(m).get("mode", 0) or 0)
    c["mode_ts"] = _now(s)
    _ok(s, m, office_mode_ts=c["mode_ts"])


@_safe
def h_cap_apply_office(s, m):
    o = _obj(m)
    c = _cap(s)
    off = int(o.get("office", 0) or 0)
    if o.get("cancel"):
        c["apply"].pop(off, None)
    else:
        c["apply"][off] = {"ts": _now(s)}
    _ok(s, m, info={"id": off, "ts": _now(s), "status": 0 if o.get("cancel") else 1}, lv_limit=0)
    push_capital_init(s)


@_safe
def h_cap_bid_office(s, m):
    _ok(s, m, lv_limit=0)


@_safe
def h_cap_appoint(s, m):
    o = _obj(m)
    now = _now(s)
    _cap(s)["offices"][int(o.get("office", 0) or 0)] = {"uid": int(o.get("uid", 0) or 0), "ts": now}
    _ok(s, m, time=now)


@_safe
def h_cap_dismissal(s, m):
    _cap(s)["offices"].pop(int(_obj(m).get("office", 0) or 0), None)
    _ok(s, m, time=_now(s))


@_safe
def h_cap_appoint_list(s, m):
    c = _cap(s)
    e = c["offices"].get(int(_obj(m).get("office", 0) or 0))
    now = _now(s)
    _ok(s, m, list=[{"uid": e["uid"], "ts": e["ts"], "abbr": "", "name": "Gov%d" % e["uid"], "kid": _me(s)["kid"], "end_ts": now + 86400}] if e else [])


@_safe
def h_cap_app_list(s, m):
    _ok(s, m, list=[], auto_agree=False, only_native=False, lv_limit=0)


@_safe
def h_cap_slot_app_list(s, m):
    _ok(s, m, list={"order_uid": 0, "list": []}, auto_agree=False, only_native=False, lv_limit=0)


@_safe
def h_cap_list_only(s, m):
    _ok(s, m, list=[])


@_safe
def h_cap_change_buff(s, m):
    _ok(s, m, ts=_now(s))


@_safe
def h_cap_goals_by_uid(s, m):
    _ok(s, m, uid_map=[{"uid": int(x.get("k", 0) or 0), "goal": 0} for x in (_obj(m).get("uid_set") or []) if isinstance(x, dict)])


@_safe
def h_cap_merge_history(s, m):
    _ok(s, m, merge_history=[])


@_safe
def h_cap_president_history(s, m):
    me = _me(s)
    _ok(s, m, records=[{"abbr": "", "nickName": me["nick"], "time": _now(s) - 7 * 86400, "image": me["image"], "uid": me["uid"],
                        "kid": me["kid"], "is_cross_mode": False}])
    push_capital_init(s)


@_safe
def h_cap_get_sched(s, m):
    c = _cap(s)
    _ok(s, m, list=[{"task_id": k, "start_ts": v["start_ts"], "task_type": v["task_type"], "skill_data": v.get("skill_data") or {}}
                    for k, v in sorted(c["tasks"].items())])


@_safe
def h_cap_add_sched(s, m):
    o = _obj(m)
    c = _cap(s)
    c["task_seq"] += 1
    tid = c["task_seq"]
    c["tasks"][tid] = {"start_ts": int(o.get("start_ts", 0) or 0), "task_type": int(o.get("task_type", 0) or 0), "skill_data": o.get("skill_data") or {}}
    _ok(s, m, task_id=tid)


@_safe
def h_cap_mod_sched(s, m):
    o = _obj(m)
    t = _cap(s)["tasks"].get(int(o.get("task_id", 0) or 0))
    if t is None:
        return _reply(s, m, {"code": 2})
    t.update(start_ts=int(o.get("start_ts", t["start_ts"]) or 0), task_type=int(o.get("task_type", t["task_type"]) or 0),
             skill_data=o.get("skill_data") or {})
    _ok(s, m)


@_safe
def h_cap_use_skill(s, m):
    sid = int(_obj(m).get("id", 0) or 0)
    now = _now(s)
    n = _cap(s)["skills"].setdefault(sid, {"n": 0, "t": 0})
    n["n"] += 1
    n["t"] = now
    _ok(s, m, use_count=n["n"], use_time=now, redeem=[])


@_safe
def h_cap_gift(s, m):
    _ok(s, m, fails=[], success_ids=[int(u) for u in (_obj(m).get("uids") or [])])


@_safe
def h_cap_record(s, m):
    _ok(s, m, record=[])


@_safe
def h_cap_goal_rank(s, m):
    me = _me(s)
    _ok(s, m, list=[{"uid": me["uid"], "points": 0}], my_info={"rank": 1, "points": 0, "detail": []})


@_safe
def h_cap_receive_reward(s, m):
    c = _cap(s)
    if c["reward_taken"]:
        return _reply(s, m, {"code": 4004})   # repetição (código genérico de "já recebido/intervalo")
    c["reward_taken"] = True
    _ok(s, m)


@_safe
def h_code0(s, m):
    _ok(s, m)


@_safe
def h_cap_review(s, m):
    _cap(s)["apply"].pop(int(_obj(m).get("office", 0) or 0), None)
    _ok(s, m)
    push_capital_init(s)


HANDLERS = {
    "req_world_map_info": h_map_info, "req_world_mapobj": h_mapobj, "req_world_map_search": h_map_search, "req_world_map_fog": h_map_fog,
    "req_world_kingdom_info": h_kingdom_info, "req_world_resource_info": h_resource_info,
    "req_world_alliance_resource_info": h_alliance_resource_info, "req_world_territory_buff": h_territory_buff, "req_world_del_watch": h_del_watch,
    "req_world_move_city": h_move_city, "req_world_random_move_city": h_random_move_city,
    "req_world_alliance_move_city_point": h_move_point, "req_world_alliance_territory_move_city_point": h_move_point,
    "req_world_alliance_move_city": h_alliance_move_city, "req_world_alliance_territory_move_city": h_alliance_move_city,
    "req_world_fort_move_city": h_move_city, "req_world_gohome": h_gohome, "req_world_gohome_to_point": h_gohome_to_point,
    "req_world_wormhole_jumping_random": h_wormhole_random, "req_world_wormhole_jumping_to_point": h_wormhole_to_point,
    "req_world_control_list": h_control_list, "req_world_fort_pro_progress": h_fort_pro_progress,
    "rsp_watch_world_fort_defenses": h_noresp, "rsp_watch_capital_war_info": h_noresp, "rsp_watch_capital_war_order_list": h_noresp,
    "rsp_watch_capital_war_president_data": h_noresp,
    "req_capital_search_alliance_by_key": h_cap_search_alliance, "req_capital_war_president_info": h_cap_president_info,
    "req_capital_war_set_manifesto": h_cap_set_manifesto, "req_capital_war_set_kingdom_name": h_cap_set_kname,
    "req_capital_war_check_name": h_cap_check_name, "req_capital_war_set_kingdom_flag": h_cap_set_flag,
    "req_capital_war_set_office_mode": h_cap_set_mode, "req_capital_war_apply_office": h_cap_apply_office,
    "req_capital_war_bid_office": h_cap_bid_office, "req_capital_war_appoint": h_cap_appoint, "req_capital_war_dismissal": h_cap_dismissal,
    "req_capital_war_appoint_list": h_cap_appoint_list, "req_capital_war_get_application_list": h_cap_app_list,
    "req_capital_war_get_slot_application_list": h_cap_slot_app_list, "req_capital_war_agree_all_application": h_cap_list_only,
    "req_capital_war_auto_agree_application": h_cap_list_only, "req_capital_war_change_office_buff": h_cap_change_buff,
    "req_capital_war_get_goals_by_uid_set": h_cap_goals_by_uid, "req_capital_war_get_merge_history": h_cap_merge_history,
    "req_capital_war_get_president_history": h_cap_president_history, "req_capital_war_get_schedule_task": h_cap_get_sched,
    "req_capital_war_add_schedule_task": h_cap_add_sched, "req_capital_war_modify_schedule_task": h_cap_mod_sched,
    "req_capital_war_use_skill": h_cap_use_skill, "req_capital_war_gift": h_cap_gift, "req_capital_war_gift_record": h_cap_record,
    "req_capital_war_skill_record": h_cap_record, "req_capital_war_hall_of_president": h_cap_record, "req_capital_war_goal_rank": h_cap_goal_rank,
    "req_capital_war_receive_president_reward": h_cap_receive_reward, "req_capital_war_review_application": h_cap_review,
    "req_capital_war_add_candidate_batch": h_code0, "req_capital_war_ban_office_apply": h_code0, "req_capital_war_elect": h_code0,
    "req_capital_war_modify_candidate": h_code0, "req_capital_war_modify_order": h_code0, "req_capital_war_quit_office_self": h_code0,
    "req_alliance_war_mark_leader": h_code0,
}
