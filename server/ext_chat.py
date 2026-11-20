"""ext_chat.py — handlers dos req_chat_* (51 mensagens do schema) do servidor de jogo offline.

O chat real roda em um RTM externo (token/endpoint vêm no notify_chat_init: token estável "mock-rtm-local",
rtmcode 0); as mensagens NÃO passam por s2c (não há notify_chat_msg no schema) — o servidor só responde
code/mid e guarda um histórico local em account.social["chat"] (ring buffer 200/sala) usado por
translate/withdraw/at. Grupos de chat (group_*) têm estado real + pushes notify_chat_group_*.
Contrato: HANDLERS = {"req_x": fun(session, m)}; nunca lança.
"""
import copy
import _ext_common as C
from _ext_common import ok, fail, safe, i, acct, now, my_uid, raw1, social, cfg

HANDLERS = {}
TOKEN = "mock-rtm-local"           # igual ao notify_chat_init do seed
MAX_LEN = 500


def H(name):
    def deco(fn):
        HANDLERS[name] = safe(fn)
        return fn
    return deco


def _push(s, name, obj):
    try: s.push(name, obj)
    except Exception: pass


def _chat(a): return social(a)["chat"]


def _ring(a, room):
    r = _chat(a).setdefault(str(room), [])
    return r


def _mid(s, a):
    return f"{int(now(s)) * 1000}{C.next_id(a):06d}"


def _state(a): return social(a)["misc"]


def _alliance(a):
    o = raw1(a, "notify_alliance_init")
    if social(a)["left"] or not o: return None
    return o.get("alliance")


def _rank(s, a):
    for x in (raw1(a, "notify_alliance_member_init") or {}).get("members", []):
        if x["uid"] == my_uid(s): return x["rank"]
    return 0


def _stranger_limit(a):
    ci = raw1(a, "notify_chat_init") or {}
    return _state(a).get("stranger_lv", ci.get("stranger_lv_limit", 0))


def _check_msg(s, m):
    """valida msg; devolve texto ou None (já respondeu erro)."""
    msg = m["obj"].get("msg")
    if not isinstance(msg, str) or not msg.strip():
        fail(s, m, "err_chat_msg_empty"); return None
    if len(msg) > MAX_LEN:
        fail(s, m, "err_chat_msgtype_arg_err"); return None
    return msg


def _record(s, a, room, msg, attrs):
    mid = _mid(s, a)
    r = _ring(a, room)
    r.append({"mid": mid, "uid": my_uid(s), "msg": msg, "attrs": attrs or "", "ts": now(s)})
    del r[:-200]
    return mid


def _send(room_of, need=None):
    def h(s, m):
        a = acct(s)
        if need:
            e = need(s, a, m)
            if e: return fail(s, m, e)
        msg = _check_msg(s, m)
        if msg is None: return
        room = room_of(s, a, m)
        if room is None: return fail(s, m, "err_chat_enter_room_not_exist")
        mid = _record(s, a, room, msg, m["obj"].get("attrs"))
        ok(s, m, rtmcode=0, mid=mid, msg=msg)
    return h


def _need_alliance(s, a, m):
    return None if _alliance(a) else C.err("err_alliance_player_not_in_same_alliance")


def _need_r4(s, a, m):
    if not _alliance(a): return C.err("err_alliance_player_not_in_same_alliance")
    return None if _rank(s, a) >= 4 else C.err("err_chat_send_r4_permission_err")


def _alliance_room(s, a, m): return (_alliance(a) or {}).get("aid")
def _kingdom_room(s, a, m): return C.my_base(s).get("kid", 0)


HANDLERS["req_chat_send_alliance"] = safe(_send(_alliance_room, _need_alliance))
HANDLERS["req_chat_send_alliance_r4"] = safe(_send(_alliance_room, _need_r4))


@H("req_chat_send_kingdom")
def _send_kingdom(s, m):
    a = acct(s); msg = _check_msg(s, m)
    if msg is None: return
    lim = int(cfg("systemconfig").get("chat", {}).get("kingdom_stove_limit", 0) or 0)
    if C.my_base(s).get("stove_lv", 99) < lim: return fail(s, m, "err_chat_stove_not_enough")
    t = now(s); st = _state(a)
    if t - st.get("last_kingdom", 0) < 1: return fail(s, m, "err_chat_broadcast_cd")
    st["last_kingdom"] = t
    mid = _record(s, a, C.my_base(s).get("kid", 0), msg, m["obj"].get("attrs"))
    ok(s, m, rtmcode=0, mid=mid, broadcast_ts=t, msg=msg)


HANDLERS["req_chat_cross_capital_send_kingdom"] = safe(_send(_kingdom_room))


@H("req_chat_send_room")
def _send_room(s, m):
    a = acct(s); msg = _check_msg(s, m)
    if msg is None: return
    rid = i(m["obj"].get("rid"))
    if rid not in _state(a).get("rooms", [rid]) and rid not in (0,): pass
    mid = _record(s, a, rid, msg, m["obj"].get("attrs"))
    ok(s, m, rtmcode=0, mid=mid, msg=msg)


@H("req_chat_send_to_self")
def _send_self(s, m):
    a = acct(s); msg = _check_msg(s, m)
    if msg is None: return
    ok(s, m, rtmcode=0, mid=_record(s, a, my_uid(s), msg, m["obj"].get("attrs")))


def _blocked(a, uid): return str(uid) in social(a)["block"]


@H("req_chat_send_p2p")
def _send_p2p(s, m):
    a = acct(s); msg = _check_msg(s, m)
    if msg is None: return
    to = i(m["obj"].get("to"))
    if to == my_uid(s) or to <= 0: return fail(s, m, 2)
    if _blocked(a, to): return fail(s, m, "err_chat_block_other")
    lim = _stranger_limit(a)
    members = {x["uid"] for x in (raw1(a, "notify_alliance_member_init") or {}).get("members", [])}
    peer_lv = C.player_base_of(s, to).get("stove_lv", 0)
    if to not in members and C.my_base(s).get("stove_lv", 99) < lim:
        return fail(s, m, "err_chat_less_than_lv_limit", lv_limit=lim)
    mid = _record(s, a, f"p2p:{to}", msg, m["obj"].get("attrs"))
    st = _state(a); rc = st.setdefault("recent", {}); rc[str(to)] = True
    ok(s, m, rtmcode=0, mid=mid, lv_limit=0, msg=msg)


@H("req_chat_send_to_uids")
def _send_uids(s, m):
    a = acct(s); msg = _check_msg(s, m)
    if msg is None: return
    tos = [i(x) for x in (m["obj"].get("tos") or [])]
    if not tos: return fail(s, m, 2)
    bl = [u for u in tos if _blocked(a, u)]
    mid = _record(s, a, "multi", msg, m["obj"].get("attrs"))
    ok(s, m, rtmcode=0, mid=mid, beblocklist=bl, lv_limit=[], msg=msg)


@H("req_chat_share_to_chat")
def _share(s, m):
    a = acct(s); o = m["obj"]
    if not any(o.get(k) for k in o): return fail(s, m, "err_chat_msgtype_illegal")
    mid = _mid(s, a)
    ok(s, m, share_common_return_info={"rtmcode": 0, "mid": mid, "msg": "", "lv_limit": 0, "beblocklist": [],
                                       "broadcast_ts": now(s), "attrs": "", "succ_list": []})


@H("req_chat_get_token")
def _get_token(s, m):
    ok(s, m, rtmcode=0, token=TOKEN)


@H("req_chat_login_room")
def _login_room(s, m):
    a = acct(s); st = _state(a)
    st["rooms"] = [i(x) for x in (m["obj"].get("room_ids") or [])]
    ok(s, m)


@H("req_chat_set_reddot_ts")
def _reddot(s, m):
    a = acct(s); t = now(s); _state(a)["reddot_ts"] = t; ok(s, m, ts=t)


# ---------------------------------------------------------------- bloqueio / privacidade
@H("req_chat_block")
def _block(s, m):
    a = acct(s); to = i(m["obj"].get("to")); bl = social(a)["block"]
    if to == my_uid(s) or to <= 0: return fail(s, m, "err_chat_block_other")
    if str(to) in bl: return fail(s, m, "err_chat_already_block")
    if len(bl) >= 100: return fail(s, m, "err_chat_block_list_is_full")
    t = now(s); bl[str(to)] = t; ok(s, m, time=t)


@H("req_chat_unblock")
def _unblock(s, m):
    a = acct(s); to = str(i(m["obj"].get("to"))); bl = social(a)["block"]
    if to not in bl: return fail(s, m, "err_chat_not_block")
    del bl[to]; ok(s, m)


@H("req_chat_temporary_block")
def _tblock(s, m):
    a = acct(s); to = i(m["obj"].get("to")); d = max(0, i(m["obj"].get("duration")))
    t = now(s); _state(a).setdefault("tblock", {})[str(to)] = t + d
    ok(s, m, start_ts=t, end_ts=t + d)


@H("req_chat_ban_stranger")
def _ban_stranger(s, m):
    _state(acct(s))["ban_stranger"] = i(m["obj"].get("opt")); ok(s, m)


@H("req_chat_set_stranger_lv_limit")
def _set_lv(s, m):
    lv = i(m["obj"].get("lv"))
    if lv < 0 or lv > 100: return fail(s, m, 2)
    _state(acct(s))["stranger_lv"] = lv; ok(s, m)


@H("req_chat_check_p2p_limit")
def _chk_p2p(s, m):
    a = acct(s); uid = i(m["obj"].get("uid"))
    ok(s, m, lv_limit=C.player_base_of(s, uid).get("stove_lv", 0) and _stranger_limit(a))


@H("req_chat_set_show_self_skin")
def _skin(s, m):
    a = acct(s); v = bool(m["obj"].get("is_show_self_skin")); st = _state(a)
    if st.get("show_self_skin") == v: return fail(s, m, "err_chat_already_same_self_skin_setting")
    st["show_self_skin"] = v; ok(s, m)


@H("req_chat_set_recent_contact")
def _recent(s, m):
    st = _state(acct(s)); u = m["obj"].get("uid_set") or []
    st["recent"] = {str(i(x.get("k") if isinstance(x, dict) else x)): True for x in u}; ok(s, m)


@H("req_chat_set_p2p_history_del_ts")
def _p2p_del(s, m):
    _state(acct(s)).setdefault("p2p_del", {})[str(i(m["obj"].get("target")))] = i(m["obj"].get("del_ts")); ok(s, m)


# ---------------------------------------------------------------- marcas de leitura / @
def _pairs(lst): return [(i(x.get("k")), i(x.get("v"))) for x in (lst or []) if isinstance(x, dict)]


@H("req_chat_add_unread_mark")
def _add_unread(s, m):
    st = _state(acct(s)); o = m["obj"]
    st.setdefault("p2p_unread", {}).update({str(k): v for k, v in _pairs(o.get("p2p_mark_map"))})
    st.setdefault("room_unread", {}).update({str(k): v for k, v in _pairs(o.get("room_mark_map"))})
    ok(s, m)


@H("req_chat_remove_unread_mark")
def _rm_unread(s, m):
    st = _state(acct(s)); o = m["obj"]
    for k in o.get("rm_p2p_list") or []: st.setdefault("p2p_unread", {}).pop(str(i(k)), None)
    for k in o.get("rm_room_list") or []: st.setdefault("room_unread", {}).pop(str(i(k)), None)
    ok(s, m)


@H("req_chat_set_read_mark")
def _read_mark(s, m):
    o = m["obj"]; _state(acct(s)).setdefault("read", {})[str(i(o.get("room_id")))] = {"ms": i(o.get("ms")), "mid": str(o.get("mid", ""))}
    ok(s, m)


@H("req_chat_at")
def _at(s, m):
    a = acct(s); o = m["obj"]; arr = o.get("uid_arr") or []
    if not arr: return fail(s, m, "err_chat_at_uid_arr_empty")
    if len(arr) > 20: return fail(s, m, "err_chat_at_uid_arr_limit")
    if i(o.get("type")) not in (1, 2): return fail(s, m, "err_chat_at_param_illegal")
    _state(a).setdefault("at", {}).setdefault(str(i(o.get("room_id"))), []).append(
        {"ms": i(o.get("ms")), "mid": str(o.get("mid", "")), "at_type": i(o.get("at_type")), "uids": [i(x) for x in arr]})
    ok(s, m)


@H("req_chat_clean_at")
def _clean_at(s, m):
    o = m["obj"]
    if i(o.get("type")) not in (1, 2): return fail(s, m, "err_chat_clean_at_param_illegal")
    _state(acct(s)).setdefault("at", {}).pop(str(i(o.get("room_id"))), None); ok(s, m)


# ---------------------------------------------------------------- consulta / tradução / retirar
@H("req_chat_players_info_by_key")
def _players_key(s, m):
    a = acct(s); key = str(m["obj"].get("key", "")).strip().lower()
    if not key: return ok(s, m, result=[])
    uids = [my_uid(s)] + [x["uid"] for x in (raw1(a, "notify_alliance_member_init") or {}).get("members", [])]
    out, seen = [], set()
    for u in uids:
        if u in seen: continue
        seen.add(u); pb = C.player_base_of(s, u)
        if key in pb.get("nickName", "").lower() or key == str(u): out.append(pb)
    ok(s, m, result=out[:20])


@H("req_chat_translate")
def _translate(s, m):
    o = m["obj"]; src = str(o.get("source_text", ""))
    if not src: return fail(s, m, "err_chat_translate_target_error")
    ok(s, m, target_text=f"[{o.get('target', 'en')}] {src}", mark=i(o.get("mark")), mid=str(o.get("mid", "")),
       origin=1, source="en")


@H("req_chat_translate_feedback")
def _tfeed(s, m): ok(s, m)


@H("req_chat_withdraw")
def _withdraw(s, m):
    a = acct(s); mid = str(m["obj"].get("mid", ""))
    for room, lst in _chat(a).items():
        for x in lst:
            if x["mid"] == mid:
                if x["uid"] != my_uid(s): return fail(s, m, "err_chat_at_not_permission")
                if now(s) - x["ts"] > 120: return fail(s, m, "err_chat_timeout")
                lst.remove(x); return ok(s, m, rtmcode=0, ex="")
    fail(s, m, "err_chat_msg_empty")


# ---------------------------------------------------------------- grupos de chat
def _groups(a): return social(a)["groups"]


def _gview(g):
    return {"group_id": g["group_id"], "owner_uid": g["owner_uid"], "name": g["name"], "uid_arr": list(g["uid_arr"]),
            "create_ts": g["create_ts"], "invite_review": g["invite_review"]}


def _grp(s, m, owner=False, member=True):
    a = acct(s); g = _groups(a).get(str(i(m["obj"].get("group_id"))))
    if g is None:
        fail(s, m, "err_chat_group_not_exist"); return None
    if member and my_uid(s) not in g["uid_arr"]:
        fail(s, m, "err_chat_group_not_member"); return None
    if owner and g["owner_uid"] != my_uid(s):
        fail(s, m, "err_chat_group_not_owner"); return None
    return g


LIMIT_MEMBERS = 100
LIMIT_GROUPS = 20


@H("req_chat_group_create")
def _g_create(s, m):
    a = acct(s); arr = [i(x) for x in (m["obj"].get("uid_arr") or []) if i(x) != my_uid(s)]
    if not arr: return fail(s, m, 2)
    if len([g for g in _groups(a).values() if g["owner_uid"] == my_uid(s)]) >= LIMIT_GROUPS:
        return fail(s, m, "err_chat_group_create_limit")
    gid = 70000000 + C.next_id(a)
    g = {"group_id": gid, "owner_uid": my_uid(s), "name": f"Group {gid % 10000}", "uid_arr": [my_uid(s)] + arr[:LIMIT_MEMBERS - 1],
         "create_ts": now(s), "invite_review": False, "notice": None, "history": []}
    _groups(a)[str(gid)] = g
    _push(s, "notify_chat_group_join", {"group_id": gid, "uid_arr": g["uid_arr"], "group_overview": _gview(g)})
    ok(s, m, group_id=gid, fail_uid_arr=[], group_overview=_gview(g), fail_send_msg_info=[])


@H("req_chat_group_detail")
def _g_detail(s, m):
    g = _grp(s, m)
    if g: ok(s, m, info=_gview(g))


@H("req_chat_group_add_member")
def _g_add(s, m):
    g = _grp(s, m)
    if not g: return
    arr = [i(x) for x in (m["obj"].get("uid_arr") or [])]
    succ, exist, bad = [], [], []
    for u in arr:
        if u in g["uid_arr"]: exist.append(u)
        elif len(g["uid_arr"]) >= LIMIT_MEMBERS: bad.append(u)
        elif g["invite_review"] and g["owner_uid"] != my_uid(s): succ.append(u)     # vai para revisão do dono
        else: g["uid_arr"].append(u); succ.append(u)
    if succ and not (g["invite_review"] and g["owner_uid"] != my_uid(s)):
        _push(s, "notify_chat_group_join", {"group_id": g["group_id"], "uid_arr": succ, "group_overview": _gview(g)})
    ok(s, m, fail_uid_arr=bad, fail_send_msg_info=[], invite_succ_uid_arr=succ, invite_fail_uid_arr=bad, invite_exist_uid_arr=exist)


@H("req_chat_group_agree_member")
def _g_agree(s, m):
    g = _grp(s, m, owner=True)
    if not g: return
    u = i(m["obj"].get("uid"))
    if u not in g["uid_arr"]: g["uid_arr"].append(u)
    ok(s, m, data={"uid": u, "code": 0, "rtmcode": 0, "mid": "", "msg": "", "lv_limit": 0, "attrs": ""})


@H("req_chat_group_disagree_member")
def _g_disagree(s, m):
    g = _grp(s, m, owner=True)
    if g: ok(s, m, send_msg_info=[])


@H("req_chat_group_del_member")
def _g_del(s, m):
    g = _grp(s, m, owner=True)
    if not g: return
    arr = [i(x) for x in (m["obj"].get("uid_arr") or []) if i(x) != my_uid(s) and i(x) in g["uid_arr"]]
    for u in arr: g["uid_arr"].remove(u)
    if arr: _push(s, "notify_chat_group_leave", {"group_id": g["group_id"], "uid_arr": arr})
    ok(s, m, disbanded=False)


@H("req_chat_group_quit")
def _g_quit(s, m):
    g = _grp(s, m)
    if not g: return
    a = acct(s); me = my_uid(s); disbanded = False
    g["uid_arr"].remove(me)
    if not g["uid_arr"]:
        disbanded = True; del _groups(a)[str(g["group_id"])]
        _push(s, "notify_chat_group_disbanded", {"group_id": g["group_id"]})
    else:
        if g["owner_uid"] == me:
            g["owner_uid"] = g["uid_arr"][0]
            _push(s, "notify_chat_group_owner", {"group_id": g["group_id"], "owner_uid": g["owner_uid"], "is_change": True})
        _push(s, "notify_chat_group_leave", {"group_id": g["group_id"], "uid_arr": [me]})
    ok(s, m, disbanded=disbanded)


@H("req_chat_group_modify_name")
def _g_name(s, m):
    g = _grp(s, m)
    if not g: return
    n = str(m["obj"].get("name", "")).strip()
    if not (1 <= len(n) <= 30): return fail(s, m, 2)
    g["name"] = n
    _push(s, "notify_chat_group_modify_name", {"group_id": g["group_id"], "name": n}); ok(s, m)


@H("req_chat_group_change_group_owner")
def _g_owner(s, m):
    g = _grp(s, m, owner=True)
    if not g: return
    u = i(m["obj"].get("uid"))
    if u not in g["uid_arr"]: return fail(s, m, "err_chat_group_not_member")
    g["owner_uid"] = u
    _push(s, "notify_chat_group_owner", {"group_id": g["group_id"], "owner_uid": u, "is_change": True}); ok(s, m)


@H("req_chat_group_change_invite_review")
def _g_review(s, m):
    g = _grp(s, m, owner=True)
    if g: g["invite_review"] = bool(m["obj"].get("invite_review")); ok(s, m)


@H("req_chat_group_change_group_notice")
def _g_notice(s, m):
    g = _grp(s, m)
    if not g: return
    n = m["obj"].get("notice")
    if not isinstance(n, str) or len(n) > 200: return fail(s, m, "err_chat_group_notice_length_error")
    rec = {"uid": my_uid(s), "notice": n, "ts": now(s), "uuid": f"g{C.next_id(acct(s))}"}
    g["notice"] = rec; g["history"].insert(0, rec)
    _push(s, "notify_chat_group_update", {"group_id": g["group_id"], "data": rec}); ok(s, m)


@H("req_chat_group_get_group_notice")
def _g_get_notice(s, m):
    g = _grp(s, m)
    if g: ok(s, m, data=g["notice"] or {"uid": 0, "notice": "", "ts": 0, "uuid": ""})


@H("req_chat_group_get_group_notice_history")
def _g_hist(s, m):
    g = _grp(s, m)
    if g: ok(s, m, data=copy.deepcopy(g["history"]))


@H("req_chat_group_del_history_notice")
def _g_del_hist(s, m):
    g = _grp(s, m)
    if not g: return
    u = m["obj"].get("uuid"); n0 = len(g["history"])
    g["history"][:] = [x for x in g["history"] if x["uuid"] != u]
    if len(g["history"]) == n0: return fail(s, m, "err_chat_group_history_notice_not_exist")
    ok(s, m)


# ---- votos de grupo
def _gv(g): return g.setdefault("votes", [])


def _vpub(v): return {k: copy.deepcopy(x) for k, x in v.items() if not k.startswith("_")}


@H("req_chat_group_vote_add")
def _gv_add(s, m):
    g = _grp(s, m)
    if not g: return
    o = m["obj"]; opts = [str(x) for x in (o.get("options") or [])]
    title = str(o.get("title", ""))
    if not title: return fail(s, m, "err_chat_group_vote_title_limit")
    if len(title) > 100: return fail(s, m, "err_chat_group_vote_title_length_limit")
    if not (2 <= len(opts) <= 10): return fail(s, m, "err_chat_group_vote_options_num_illegal")
    if len(_gv(g)) >= 20: return fail(s, m, "err_chat_group_vote_count_limit")
    t = now(s); dur = i(o.get("time"))
    et = dur if dur > t else t + 86400
    _gv(g).append({"id": C.next_id(acct(s)), "uid": my_uid(s), "is_multi": bool(o.get("is_multi")), "st": t, "et": et, "title": title,
                   "options": opts, "selects": [], "total": 0, "s_uname": C.my_base(s).get("nickName", ""), "e_uname": "",
                   "s_abbr": (C.my_base(s).get("alliance") or {}).get("abbr", ""), "e_abbr": "", "_voters": {}})
    ok(s, m)


def _gfind(g, vid): return next((v for v in _gv(g) if v["id"] == vid), None)


@H("req_chat_group_vote_records")
def _gv_records(s, m):
    g = _grp(s, m)
    if g: ok(s, m, group_id=g["group_id"], records=[_vpub(v) for v in _gv(g)])


@H("req_chat_group_vote_record_detail")
def _gv_detail(s, m):
    g = _grp(s, m)
    if not g: return
    v = _gfind(g, i(m["obj"].get("id")))
    if v is None: return fail(s, m, "err_chat_group_vote_not_exist")
    pls = []
    if m["obj"].get("need_info"):
        for u in v["_voters"]:
            pb = C.player_base_of(s, int(u)); pls.append({k: pb[k] for k in ("uid", "nickName", "power", "stove_lv") if k in pb})
    ok(s, m, players=pls, vote=_vpub(v))


@H("req_chat_group_vote_select")
def _gv_select(s, m):
    g = _grp(s, m)
    if not g: return
    v = _gfind(g, i(m["obj"].get("id")))
    if v is None: return fail(s, m, "err_chat_group_vote_not_exist")
    sel = [i(x) for x in (m["obj"].get("list") or [])]
    if v["et"] < now(s) or str(my_uid(s)) in v["_voters"]: return fail(s, m, "err_chat_group_vote_ins_error")
    if not sel or any(not 0 <= x < len(v["options"]) for x in sel) or (not v["is_multi"] and len(sel) > 1):
        return fail(s, m, "err_chat_group_vote_options_illegal")
    v["_voters"][str(my_uid(s))] = sel
    cnt = {}
    for lst in v["_voters"].values():
        for x in lst: cnt[x] = cnt.get(x, 0) + 1
    v["selects"] = [{"k": k, "v": c} for k, c in sorted(cnt.items())]; v["total"] = len(v["_voters"])
    _push(s, "notify_chat_group_vote_update", {"group_id": g["group_id"], "vote": _vpub(v)}); ok(s, m)


@H("req_chat_group_vote_finish")
def _gv_finish(s, m):
    g = _grp(s, m)
    if not g: return
    v = _gfind(g, i(m["obj"].get("id")))
    if v is None: return fail(s, m, "err_chat_group_vote_not_exist")
    if v["uid"] != my_uid(s) and g["owner_uid"] != my_uid(s): return fail(s, m, "err_chat_group_permission_denied")
    v["et"] = now(s); v["e_uname"] = C.my_base(s).get("nickName", ""); ok(s, m)


@H("req_chat_group_vote_delete_record")
def _gv_del(s, m):
    g = _grp(s, m)
    if not g: return
    n0 = len(_gv(g)); _gv(g)[:] = [v for v in _gv(g) if v["id"] != i(m["obj"].get("id"))]
    if len(_gv(g)) == n0: return fail(s, m, "err_chat_group_vote_not_exist")
    ok(s, m)


@H("req_chat_group_vote_top")
def _gv_top(s, m):
    g = _grp(s, m)
    if not g: return
    v = _gfind(g, i(m["obj"].get("id")))
    if v is None: return fail(s, m, "err_chat_group_vote_not_exist")
    v["_top"] = bool(m["obj"].get("top")); ok(s, m)


# ---------------------------------------------------------------- stubs p/ qualquer req_chat_* futuro do schema
def _stub(s, m): ok(s, m)


for _n in C.req_names("req_chat_"):
    if _n not in HANDLERS:
        HANDLERS[_n] = safe(_stub)
STUBS = sorted(n for n in HANDLERS if HANDLERS[n].__name__ == "_stub")
