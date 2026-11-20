# -*- coding: utf-8 -*-
"""ext_supremacywar.py — handlers reais p/ SUPREMACY WAR (Flamedragon Tyrant): mapa de batalha, marchas, habilidades de aliança,
governo (presidente/cargos), banquete (feast) e espectador. Contrato: HANDLERS={"req_x": fun(session,m)}; nunca lança.
Fase derivada de TIMESTAMPS (ciclo de 14 dias ancorado na época), igual ao cliente (SupremacyWarActivityCtrl):
Nothing=0, Predicted=1, SignUp=2, Dispatched=3, Publicity=4, Fighting=5, Restored=6 (reports/econ_war.md §1.1).
SANDBOX: entrar na guerra é permitido em qualquer fase (STRICT_PHASE=False) — a prod provavelmente recusa fora de Fighting."""
import json, os, random, zlib

STRICT_PHASE = False
H = 3600
# (estado, duração s) em ordem; o restante do ciclo é Nothing(0). econ_war.md §1.1: inscrição 48h, despacho 48h,
# véspera/publicidade 59h, campo aberto 7h, restauração 198000s (supremacy_ui_97 recovery_duration_time).
PHASES = [(1, 12 * H), (2, 48 * H), (3, 48 * H), (4, 59 * H), (5, 7 * H), (6, 198000)]
CYCLE = 14 * 86400
PHASE_NAMES = {0: "Nothing", 1: "Predicted", 2: "SignUp", 3: "Dispatched", 4: "Publicity", 5: "Fighting", 6: "Restored"}
MAP_SIZE = 400            # supremacy_war_area #1: 0..399
PALACE_XY = (195, 195)    # supremacy_war_fixed_obj #1 (type 501, 10x10)
BATTLE_PREPARE_S = 300
ENTER_WAR_CD = 600
CFG_DIR = os.environ.get("KS_CFG_DIR", "C:/Users/prs/work/lua-logic/cfg")
_SKILL_FALLBACK = {1: 3600, 2: 3600, 3: 3600, 4: 3600, 5: 3600}  # cooling_time (cfg: skill 1 = 3600s)
_cfg_cache = {}


def war_phase(now):
    """-> (state, state_begin, state_end, cycle_begin). Puro, sem I/O."""
    cb = (now // CYCLE) * CYCLE
    t = now - cb
    acc = CYCLE - sum(d for _, d in PHASES)       # Nothing no início do ciclo
    if t < acc:
        return 0, cb, cb + acc, cb
    for stt, d in PHASES:
        if t < acc + d:
            return stt, cb + acc, cb + acc + d, cb
        acc += d
    return 0, cb + acc, cb + CYCLE, cb


# ------------------------------------------------------------------ helpers
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
        return s.__dict__.setdefault("_sw", {})
    except Exception:
        return _FALLBACK.setdefault(id(s), {})


def _me(s):
    b = _acct_base(s)
    return {"uid": int(b.get("uid", 1) or 1), "nick": str(b.get("nickName", "player")), "kid": int(b.get("kid", 1) or 1),
            "image": int(b.get("image", 1001) or 1001)}


def _pt(x, y):
    return {"x": int(x), "y": int(y)}


def _clamp(v, hi=MAP_SIZE - 1):
    return max(0, min(hi, int(v)))


def _rsp_spec(s, m):
    try:
        return s.S.c2s_by_name[m["name"]]["response"]
    except Exception:
        return "?"


def _reply(s, m, obj):
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


def _i(o, k, d=0):
    try:
        return int(o.get(k, d) or d)
    except Exception:
        return d


def _skill_cooldowns():
    if "cd" not in _cfg_cache:
        cd = dict(_SKILL_FALLBACK)
        try:
            d = json.load(open(os.path.join(CFG_DIR, "supremacy_war_skill.json"), encoding="utf8"))
            c2 = {}
            for v in d.values():
                if "skill_id" in v:
                    c2[int(v["skill_id"])] = int(v.get("cooling_time", 0) or 0)
            if c2:
                cd = c2
        except Exception:
            pass
        _cfg_cache["cd"] = cd
    return _cfg_cache["cd"]


def _otype(s, name, default):
    """world_mapobj.type = tag-1 do campo (premissa); lê do schema da sessão se possível."""
    try:
        for f in s.S.types["world_mapobj"]:
            if f["name"] == name:
                return f["tag"] - 1
    except Exception:
        pass
    return default


def _war(s):
    st = _st(s)
    if "war" not in st:
        me = _me(s)
        st["war"] = {"in_war": False, "exit_ts": 0, "enter_ts": 0, "marchs": {}, "mseq": 1000, "city": None, "offices": {}, "manifesto": "",
                     "man_ts": 0, "skills": {}, "ops": [], "crystal": 1200, "president": me["uid"], "feast": {}, "reward_taken": False,
                     "gifts": [], "term_end": 0}
    return st["war"]


def _city(s):
    w = _war(s)
    if w["city"] is None:
        r = random.Random(_me(s)["uid"] * 31 + 7)
        w["city"] = (r.randint(20, 170), r.randint(20, 170))
    return w["city"]


# ------------------------------------------------------------------ pushes de estado
def push_war_info(s):
    now = _now(s)
    stt, b, e, cb = war_phase(now)
    _push(s, "notify_supremacy_war_info", {
        "act_info": {"id": 1, "start_ts": cb, "end_ts": cb + CYCLE, "serial_no": cb // CYCLE, "state": stt, "state_begin_ts": b, "state_end_ts": e,
                     "point_reward_map": []},
        "group_info": {"self_group": 1, "group_info": [], "big_group_id": 1},
        "alliance_info": {"is_sign": stt >= 2, "is_can": stt == 2, "rank": 1, "fights": [], "ask_for_battle": [], "forbid_for_battle": [], "permit_uid_map": []},
        "player_info": {"join_aid": 0}, "pre_unlock_buff": [], "rank_rewards": []})


def push_gov_init(s):
    w = _war(s)
    me = _me(s)
    now = _now(s)
    _push(s, "notify_supremacy_war_init", {
        "gov_data": {"office_map": [], "gift_data": {"uid_set": [], "gift_map": []}, "uid": w["president"], "abbr": "", "nickName": me["nick"],
                     "image": me["image"], "aid": 0, "manifesto": w["manifesto"], "term_end_ts": w["term_end"] or now + 7 * 86400,
                     "modify_manifesto_ts": w["man_ts"], "kid": me["kid"], "kid_set": [], "dominance": 0, "manifesto_ban_ts": 0},
        "id": 1, "group_arr": [], "dominance_info": {"start_time": now - 86400, "end_time": now + 6 * 86400, "daily_dominance_nums": 0,
                                                       "last_reset_dominance_time": now}})


def push_player_init(s, in_war=None):
    now = _now(s)
    w = _war(s)
    stt, b, e, _ = war_phase(now)
    fight_end = e if stt == 5 else now + 7 * H
    _push(s, "notify_supremacy_war_player_init", {"state": stt, "starttime": b if stt == 5 else now, "endtime": fight_end,
          "chat_room_id": 5000001, "exit_time": w["exit_ts"], "chat_alliance_room_id": 5000002})


# ------------------------------------------------------------------ mapa de batalha sintético
def _cell(s, x, y, now):
    cx, cy = _city(s)
    me = _me(s)
    if (x, y) == (cx, cy):
        return {"point": _pt(x, y), "type": _otype(s, "map_city", 1), "map_city": {"uid": me["uid"], "lv": 30, "nickName": me["nick"], "kid": me["kid"],
                "aid": 0, "abbr": "", "side": 1, "supremacy_war_lock_endtime": 0}}
    if (x, y) == PALACE_XY:
        return {"point": _pt(x, y), "type": _otype(s, "map_supremacy_palace", 41), "map_supremacy_palace": {"is_monster": True, "state": 0, "state_time": now,
                "begin_time": now, "uid": 0, "id": 1, "aid": 0, "abbr": "", "kid": 0, "name": ""}}
    h = zlib.crc32(f"sw:{x}:{y}".encode()) & 0xffffffff
    if x % 5 or y % 5 or h % 4:
        return None
    k = h % 100
    if k < 30:
        return {"point": _pt(x, y), "type": _otype(s, "map_supremacy_resource1", 49), "map_supremacy_resource1": {"id": 1 + h % 8, "kid": 0, "create_time": now - 300}}
    if k < 45:
        return {"point": _pt(x, y), "type": _otype(s, "map_supremacy_resource2", 50), "map_supremacy_resource2": {"id": 1 + h % 8, "kid": 0, "create_time": now - 300}}
    if k < 80:
        return {"point": _pt(x, y), "type": _otype(s, "map_supremacy_monster", 51), "map_supremacy_monster": {"id": 7100001 + h % 20, "win": False, "time": now}}
    return {"point": _pt(x, y), "type": _otype(s, "map_supremacy_guard", 40), "map_supremacy_guard": {"aid": 0, "state": 0, "state_end_time": 0, "id": 1 + h % 8,
            "uid": 0, "name": "Guard%d" % (h % 8), "kid": 0, "abbr": "", "flag": 1, "flag_bg": 1}}


def _chunk(s, p0, p1, cap=300):
    now = _now(s)
    x0, x1 = sorted((_clamp(p0.get("x", 0)), _clamp(p1.get("x", 0))))
    y0, y1 = sorted((_clamp(p0.get("y", 0)), _clamp(p1.get("y", 0))))
    out = []
    for x in range(x0, min(x1, x0 + 120) + 1):
        for y in range(y0, min(y1, y0 + 120) + 1):
            o = _cell(s, x, y, now)
            if o:
                out.append(o)
                if len(out) >= cap:
                    return out
    return out


def _march_list(s):
    return [dict(v) for v in _war(s)["marchs"].values()]


@_safe
def h_map_info(s, m):
    o = _obj(m)
    _ok(s, m)
    objs = _chunk(s, o.get("startpoint") or _pt(0, 0), o.get("endpoint") or _pt(MAP_SIZE - 1, MAP_SIZE - 1))
    _push(s, "notify_supremacy_war_mapobjs", {"session": _i(o, "session"), "datalist": objs, "end_flag": True, "lod": _i(o, "lod")})
    _push(s, "notify_supremacy_war_marchs", {"session": _i(o, "session"), "datalist": _march_list(s), "end_flag": True})


@_safe
def h_enter(s, m):
    cheat = False
    now = _now(s)
    w = _war(s)
    stt, b, e, _ = war_phase(now)
    if STRICT_PHASE and not cheat and stt != 5:
        return _reply(s, m, {"code": 4})   # fora da janela de batalha (código assumido)
    if not cheat and w["exit_ts"] and now - w["exit_ts"] < ENTER_WAR_CD and STRICT_PHASE:
        return _reply(s, m, {"code": 4004})  # enter_war_cd=600s
    w["in_war"] = True
    w["enter_ts"] = now
    cx, cy = _city(s)
    over = e if stt == 5 else now + 7 * H
    _ok(s, m, city_point=_pt(cx, cy), march_info=_march_list(s), mass_master_marchs=[], chat_room_id=5000001, chat_alliance_room_id=5000002,
        begin_time=b if stt == 5 else now, over_time=over, burn_down_flag=False,
        crystal={"count": w["crystal"], "inc_rate": 1.0, "last_chg_ts": now},
        skills=[{"skill_id": k, "use_time": v} for k, v in sorted(w["skills"].items())], skill_stop_move_time=0)
    push_war_info(s)
    push_player_init(s)


@_safe
def h_cheat_enter(s, m):
    _enter_impl(s, m, True)


def _enter_impl(s, m, cheat):
    now = _now(s)
    w = _war(s)
    stt, b, e, _ = war_phase(now)
    w["in_war"] = True
    w["enter_ts"] = now
    cx, cy = _city(s)
    _ok(s, m, city_point=_pt(cx, cy), march_info=_march_list(s), mass_master_marchs=[], chat_room_id=5000001, chat_alliance_room_id=5000002,
        begin_time=now, over_time=now + 7 * H, burn_down_flag=False, crystal={"count": w["crystal"], "inc_rate": 1.0, "last_chg_ts": now},
        skills=[], skill_stop_move_time=0)
    push_player_init(s)


@_safe
def h_exit(s, m):
    w = _war(s)
    w["in_war"] = False
    w["exit_ts"] = _now(s)
    _ok(s, m, time=w["exit_ts"])


@_safe
def h_del_watch(s, m):
    _ok(s, m)


@_safe
def h_code0(s, m):
    _ok(s, m)


@_safe
def h_noresp(s, m):
    _reply(s, m, {})   # response é struct vazia (sem campo code)


@_safe
def h_control_list(s, m):
    _ok(s, m, list=[])


@_safe
def h_map_search(s, m):
    cx, cy = _city_xy_war(s)
    r = random.Random(_now(s) // 60)
    _ok(s, m, point=_pt(_clamp(cx + r.randint(-30, 30)), _clamp(cy + r.randint(-30, 30))))


def _city_xy_war(s):
    return _city(s)


@_safe
def h_resource_info(s, m):
    now = _now(s)
    _ok(s, m, res_count=600, collect_begin_time=now - 120, collect_speed=1, collect_speed_add=[], collect_finish_time=now + 1800, collect_buff_info=[])


# ---- marchas
def _mk_march(s, o, now):
    w = _war(s)
    w["mseq"] += 1
    me = _me(s)
    ep = o.get("endpoint") or _pt(*PALACE_XY)
    cx, cy = _city(s)
    dist = abs(int(ep.get("x", 0)) - cx) + abs(int(ep.get("y", 0)) - cy)
    dur = max(10, dist * 2)           # 2 s/tile (sandbox)
    mk = {"id": w["mseq"], "owner": me["uid"], "startpoint": _pt(cx, cy), "endpoint": _pt(ep.get("x", 0), ep.get("y", 0)), "starttime": now,
          "endtime": now + dur, "state": 1, "type": _i(o, "type", 1), "kid": me["kid"]}
    w["marchs"][mk["id"]] = mk
    return mk


@_safe
def h_march(s, m):
    mk = _mk_march(s, _obj(m), _now(s))
    _ok(s, m, march_info=dict(mk))
    _push(s, "notify_supremacy_war_march_add", {"march": mk})


@_safe
def h_march_recall(s, m):
    w = _war(s)
    mid = _i(_obj(m), "id")
    mk = w["marchs"].pop(mid, None)
    if mk is None:
        return _reply(s, m, {"code": 2})
    _ok(s, m)
    _push(s, "notify_supremacy_war_march_del", {"march": mk})


@_safe
def h_march_off_work(s, m):
    w = _war(s)
    mk = w["marchs"].pop(_i(_obj(m), "id"), None)
    if mk is None:
        return _reply(s, m, {"code": 2})
    _ok(s, m)
    _push(s, "notify_supremacy_war_march_del", {"march": mk})


@_safe
def h_march_speedup(s, m):
    w = _war(s)
    o = _obj(m)
    mk = w["marchs"].get(_i(o, "id"))
    now = _now(s)
    if mk is None:
        return _reply(s, m, {"code": 2})
    left = max(0, mk["endtime"] - now)
    mk["endtime"] = now + left // 2
    _ok(s, m, endtime=mk["endtime"])
    _push(s, "notify_supremacy_war_march_update", {"march": mk})


@_safe
def h_march_detail(s, m):
    mk = _war(s)["marchs"].get(_i(_obj(m), "id"))
    me = _me(s)
    d = {"owner": me["uid"], "id": _i(_obj(m), "id"), "state": (mk or {}).get("state", 0), "endtime": (mk or {}).get("endtime", 0),
         "starttime": (mk or {}).get("starttime", 0), "nickName": me["nick"], "abbr": "", "aid": 0, "power": _i(_acct_base(s), "power")}
    _ok(s, m, detail=d)


@_safe
def h_mass_detail(s, m):
    _ok(s, m, detail_list=[], max=60)


@_safe
def h_move_city(s, m):
    p = _obj(m).get("point") or {}
    x, y = _clamp(p.get("x", 100)), _clamp(p.get("y", 100))
    _war(s)["city"] = (x, y)
    _ok(s, m, point=_pt(x, y))
    _push(s, "notify_supremacy_war_city_update", {"point": _pt(x, y), "be_atk": False, "burn_down": False})


@_safe
def h_embassy_simple(s, m):
    _ok(s, m, cap=10, exist=0, helped=False)


@_safe
def h_embassy_list(s, m):
    _ok(s, m, march_detail_list=[], cap=10)


# ---- habilidades de aliança (cooldown da cfg supremacy_war_skill.cooling_time)
@_safe
def h_use_skill(s, m):
    sid = _i(_obj(m), "skill_id")
    cds = _skill_cooldowns()
    if sid not in cds:
        return _reply(s, m, {"code": 2})
    w = _war(s)
    now = _now(s)
    last = w["skills"].get(sid, 0)
    if last and now - last < cds[sid]:
        return _reply(s, m, {"code": 4004})   # em cooldown (mesmo código do interval_not_enough do mock)
    w["skills"][sid] = now
    w["ops"].append({"user_name": _me(s)["nick"], "skill_id": sid, "op_ts": now})
    _ok(s, m)


@_safe
def h_skill_records(s, m):
    _ok(s, m, records=list(_war(s)["ops"][-50:]))


# ---- governo
@_safe
def h_gov_overview(s, m):
    w = _war(s)
    now = _now(s)
    _ok(s, m, uid=w["president"], dominance=0, manifesto=w["manifesto"], term_end_ts=w["term_end"] or now + 7 * 86400)
    push_war_info(s)


@_safe
def h_gov_dominance(s, m):
    _ok(s, m, dominance=0)
    push_gov_init(s)


@_safe
def h_gov_all_president(s, m):
    _ok(s, m, group_arr=[{"id": 1, "kids": [_me(s)["kid"]], "uid": _war(s)["president"], "term_end_ts": _now(s) + 7 * 86400}])


@_safe
def h_gov_dominion(s, m):
    _ok(s, m, kids=[_me(s)["kid"]], num=1)


@_safe
def h_gov_points(s, m):
    _ok(s, m, points_map=[{"k": int(u), "v": 0} for u in (_obj(m).get("uids") or [])])


@_safe
def h_gov_top100(s, m):
    _ok(s, m, list=[_me(s)["uid"]])


@_safe
def h_gov_100_info(s, m):
    _ok(s, m, list=[])


@_safe
def h_gov_search(s, m):
    _ok(s, m, aids=[])
    push_player_init(s)


@_safe
def h_appoint(s, m):
    o = _obj(m)
    _war(s)["offices"][_i(o, "office")] = {"uid": _i(o, "uid"), "ts": _now(s)}
    _ok(s, m)
    push_gov_init(s)


@_safe
def h_dismiss(s, m):
    _war(s)["offices"].pop(_i(_obj(m), "office"), None)
    _ok(s, m)


@_safe
def h_set_manifesto(s, m):
    w = _war(s)
    w["manifesto"] = str(_obj(m).get("manifesto", ""))[:512]
    w["man_ts"] = _now(s)
    _ok(s, m, modify_manifesto_ts=w["man_ts"])


@_safe
def h_get_president_reward(s, m):
    w = _war(s)
    if w["reward_taken"]:
        return _reply(s, m, {"code": 4004})
    w["reward_taken"] = True
    _ok(s, m)
    push_gov_init(s)


@_safe
def h_send_gift(s, m):
    o = _obj(m)
    _war(s)["gifts"].append({"id": _i(o, "id"), "uids": list(o.get("uids") or []), "ts": _now(s)})
    _ok(s, m, fails=[])
    push_gov_init(s)


@_safe
def h_gift_record(s, m):
    _ok(s, m, record=[])


# ---- banquete
@_safe
def h_feast_list(s, m):
    _ok(s, m, feasts=[{"kid": f["kid"], "uid": f["uid"], "id": f["id"], "time": f["time"], "group": 1} for f in _war(s)["feast"].values()])


@_safe
def h_feast_open(s, m):
    me = _me(s)
    fid = _i(_obj(m), "id", 1)
    _war(s)["feast"][fid] = {"kid": me["kid"], "uid": me["uid"], "id": fid, "time": _now(s)}
    _ok(s, m)


@_safe
def h_feast_reserve(s, m):
    o = _obj(m)
    me = _me(s)
    fid = _i(o, "id", 1)
    _war(s)["feast"][fid] = {"kid": me["kid"], "uid": me["uid"], "id": fid, "time": _i(o, "time", _now(s) + 3600)}
    _ok(s, m)


@_safe
def h_feast_tables(s, m):
    me = _me(s)
    _ok(s, m, tables=[{"uid": me["uid"], "table_id": 1, "meal_id": 1}], point=_pt(PALACE_XY[0] + 12, PALACE_XY[1] + 12))


@_safe
def h_feast_records(s, m):
    _ok(s, m, records=[], rewards=[])


@_safe
def h_feast_satiated(s, m):
    _ok(s, m, over_time=_now(s) + 1800, satiated=[])


@_safe
def h_search_table(s, m):
    _ok(s, m, point=_pt(PALACE_XY[0] + 12, PALACE_XY[1] + 12))


# ---- espectador
@_safe
def h_spec_enter(s, m):
    now = _now(s)
    stt, b, e, _ = war_phase(now)
    _ok(s, m, begin_time=b if stt == 5 else now, over_time=e if stt == 5 else now + 7 * H)


@_safe
def h_spec_map_info(s, m):
    o = _obj(m)
    _ok(s, m)
    _push(s, "notify_supremacy_war_mapobjs", {"session": _i(o, "session"), "datalist": _chunk(s, o.get("startpoint") or _pt(0, 0),
          o.get("endpoint") or _pt(MAP_SIZE - 1, MAP_SIZE - 1)), "end_flag": True, "lod": _i(o, "lod")})


@_safe
def h_spec_guard(s, m):
    _ok(s, m, guard_infos=[{"id": i, "aid": 0} for i in range(1, 5)])


@_safe
def h_spec_control(s, m):
    _ok(s, m, list=[])
    push_player_init(s)


@_safe
def h_mass_cancel(s, m):
    _ok(s, m)
    push_player_init(s)


@_safe
def h_occupy_captain(s, m):
    _ok(s, m)
    push_player_init(s)


@_safe
def h_fort_watch(s, m):
    _ok(s, m)


HANDLERS = {
    "req_supremacy_war_enter": h_enter, "req_supremacy_war_cheat_enter": h_cheat_enter, "req_supremacy_war_exit": h_exit,
    "req_supremacy_war_map_info": h_map_info, "req_supremacy_war_map_search": h_map_search, "req_supremacy_war_del_watch": h_del_watch,
    "req_supremacy_war_control_list": h_control_list, "req_supremacy_war_resource_info": h_resource_info,
    "req_supremacy_war_march": h_march, "req_supremacy_war_march_recall": h_march_recall, "req_supremacy_war_march_off_work": h_march_off_work,
    "req_supremacy_war_march_speedup": h_march_speedup, "req_supremacy_war_march_detail": h_march_detail,
    "req_supremacy_war_mass_master_detail": h_mass_detail, "req_supremacy_war_move_city": h_move_city,
    "req_supremacy_war_embassy_help_simple_info": h_embassy_simple, "req_supremacy_war_embassy_help_march_detail_list": h_embassy_list,
    "req_supremacy_war_embassy_repatriation": h_code0, "req_supremacy_war_captain_repatriation": h_code0,
    "req_supremacy_war_mass_prepare_cancel": h_code0, "req_supremacy_war_alliance_mass_prepare_cancel": h_mass_cancel,
    "req_supremacy_war_mass_slave_repatriate": h_code0, "req_supremacy_war_mass_slave_alliance_repatriate": h_code0,
    "req_supremacy_war_occupy_obj_change_captain": h_occupy_captain, "req_supremacy_war_occupy_obj_repatriate": h_code0,
    "req_supremacy_war_fort_defense_rsp": h_fort_watch, "req_supremacy_war_fort_defense_watch": h_fort_watch,
    "req_supremacy_war_fort_rank_rsp": h_fort_watch, "req_supremacy_war_fort_rank_watch": h_fort_watch,
    "req_supremacy_war_use_alliance_skill": h_use_skill, "req_supremacy_war_get_alliance_skill_op_record": h_skill_records,
    "req_supremacy_war_gov_group_overview": h_gov_overview, "req_supremacy_war_gov_group_dominance": h_gov_dominance,
    "req_supremacy_war_gov_get_all_president": h_gov_all_president, "req_supremacy_war_gov_get_dominion": h_gov_dominion,
    "req_supremacy_war_gov_get_player_points": h_gov_points, "req_supremacy_war_gov_get_top_100_uids": h_gov_top100,
    "req_supremacy_war_gov_get_100_player_uid": h_gov_100_info, "req_supremacy_war_gov_search_alliance_by_key": h_gov_search,
    "req_supremacy_war_appoint": h_appoint, "req_supremacy_war_dismiss": h_dismiss, "req_supremacy_war_set_manifesto": h_set_manifesto,
    "req_supremacy_war_get_president_reward": h_get_president_reward, "req_supremacy_war_send_gift": h_send_gift,
    "req_supremacy_war_gift_record": h_gift_record,
    "req_supremacy_war_feast_list": h_feast_list, "req_supremacy_war_feast_open": h_feast_open, "req_supremacy_war_feast_reserve": h_feast_reserve,
    "req_supremacy_war_feast_tables": h_feast_tables, "req_supremacy_war_feast_player_records": h_feast_records,
    "req_supremacy_war_feast_table_satiated_info": h_feast_satiated, "rsp_watch_supremacy_war_feast_tables": h_code0,
    "req_world_search_supremacy_table": h_search_table, "rsp_supremacy_war_gov_data": h_noresp,
    "req_spectator_supremacy_war_enter": h_spec_enter, "req_spectator_supremacy_war_exit": h_code0,
    "req_spectator_supremacy_war_map_info": h_spec_map_info, "req_spectator_supremacy_war_get_guard_info": h_spec_guard,
    "req_spectator_supremacy_war_control_list": h_spec_control,
}
