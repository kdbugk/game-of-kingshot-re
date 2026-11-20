"""ext_alliance.py — handlers dos req_alliance_* (205 mensagens do schema) do servidor de jogo offline.

Contrato: HANDLERS = {"req_x": fun(session, m)}; fun responde via session.reply / session.push, retorna None
e NUNCA lança (decorator `safe` -> code 2).

Estado REAL: aliança/jogador/membros/ciência/baú/ajuda/prédios vêm do seed (account.raw: notify_alliance_init,
notify_alliance_member_init, notify_alliance_science_init, notify_alliance_chest_init, ...), são MUTADOS in-place
(persistem e o snapshot/re-push reflete). Custos: server_rules.check_cost + account.spend; recompensas: account.grant.
Estado SINTÉTICO: demais alíases/jogadores (nomes deterministas), logs, rankings; guerras (arsenal/duel/showdown/
supremacy/triangle) = stubs code:0 (ver RELATORIO_SOCIAL.md).
"""
import copy, os, random
import _ext_common as C
from _ext_common import ok, fail, safe, i, acct, now, my_uid, raw1, social, cfg

DIAMOND_ID = 101          # ASSUMIDO: moeda premium (ver relatório)
FREE = os.environ.get("KS_SOCIAL_FREE", "0") == "1"   # 1 = doações/custos não debitam (sandbox)
RANK_PERM = 4             # R4+ gerencia aliança
HANDLERS = {}


def H(name):
    def deco(fn):
        HANDLERS[name] = safe(fn)
        return fn
    return deco


# ---------------------------------------------------------------- estado base
def _al(a):
    if social(a)["left"]: return None
    o = raw1(a, "notify_alliance_init")
    return (o or {}).get("alliance") or None


def _pl(a):
    o = raw1(a, "notify_alliance_init")
    return (o or {}).get("player") or {}


def _members(a):
    return (raw1(a, "notify_alliance_member_init") or {}).setdefault("members", [])


def _my_rank(s, a):
    uid = my_uid(s)
    for x in _members(a):
        if x["uid"] == uid: return x["rank"]
    return _pl(a).get("rank", 0)


def _need_ally(s, m):
    """(a, al) ou None (já respondeu err_alliance_player_not_in_same_alliance)."""
    a = acct(s); al = _al(a)
    if al is None:
        fail(s, m, "err_alliance_player_not_in_same_alliance"); return None
    return a, al


def _need_perm(s, m, a, minrank=RANK_PERM):
    if _my_rank(s, a) < minrank:
        fail(s, m, "err_alliance_have_not_permission"); return False
    return True


def _cover(al):
    keys = ("aid", "name", "abbr", "flag", "flag_bg", "lv", "exp", "public", "count", "condition", "language", "leader",
            "leader_name", "power", "power_rank", "apply_num", "member_max", "active_time")
    return {k: copy.deepcopy(al[k]) for k in keys if k in al}


def _synth_alliance(aid):
    r = random.Random(aid)
    return {"aid": aid, "name": f"Clan{aid % 100000}", "abbr": "".join(r.choice("ABCDEFGHJKLMNPRSTUVWXYZ") for _ in range(3)),
            "flag": [1 + aid % 10], "flag_bg": [1 + aid % 6], "lv": 1 + aid % 12, "exp": 0, "public": True,
            "count": 5 + aid % 40, "language": 1, "leader": 30000000 + aid % 1000000, "member_max": 50,
            "power": 10000000 + (aid * 104729) % 900000000, "power_rank": 1 + aid % 200, "apply_num": 0,
            "condition": {"level": 1, "power": 0}, "leader_name": C.synth_name(aid), "active_time": 0}


def _alliance_by_aid(a, aid):
    al = _al(a)
    if al and al["aid"] == aid: return copy.deepcopy(al)
    return _synth_alliance(aid)


def _push(s, name, obj):
    try: s.push(name, obj)
    except Exception: pass


def _touch(a):
    try: a._touch()
    except Exception: pass


def _spend(a, items):
    """aplica custo {id:count}; True se pagou (FREE=1 não debita)."""
    if FREE: return True
    return a.spend(items)


def _cost_err(a, items):
    if FREE: return None
    bal = {}
    for k in items: bal[k] = a.balance(k)
    return C.R.check_cost(bal, items) if C.R else (None if a.can_afford(items) else 51)


# ---------------------------------------------------------------- info / básico
@H("req_alliance_init_data")
def _init(s, m):
    a = acct(s); al = _al(a)
    if al is None:
        return ok(s, m, player={"aid": 0, "rank": 0})
    ok(s, m, player=copy.deepcopy(_pl(a)), alliance=copy.deepcopy(al))


@H("req_alliance_detail_info")
def _detail(s, m):
    a = acct(s); aid = i(m["obj"].get("aid"))
    ok(s, m, alliance=_alliance_by_aid(a, aid))


@H("req_alliance_cover_info")
def _cover_info(s, m):
    a = acct(s)
    ok(s, m, infos=[_cover(_alliance_by_aid(a, i(x))) for x in (m["obj"].get("aids") or [])[:50]])


@H("req_alliance_members")
def _members_h(s, m):
    a = acct(s); al = _al(a); aid = i(m["obj"].get("aid"))
    if al and (aid == al["aid"] or aid == 0):
        return ok(s, m, members=copy.deepcopy(_members(a)))
    r = random.Random(aid)
    ok(s, m, members=[{"uid": 30000000 + r.randrange(10**6), "rank": 1 + k % 5} for k in range(5)] if aid else [])


@H("req_alliance_setting")
def _setting(s, m):
    a = acct(s); st = social(a)["misc"]
    ok(s, m, setting={"abbr_count": st.get("abbr_count", 0), "name_count": st.get("name_count", 0)})


@H("req_alliance_power")
def _power(s, m):
    al = _al(acct(s)); ok(s, m, power=(al or {}).get("power", 0))


@H("req_alliance_online_info")
def _online(s, m):
    a = acct(s); al = _al(a)
    n = len(_members(a)) if al else 0
    ok(s, m, online=min(n, max(1, n // 3)) if n else 0, count=n)


@H("req_alliance_check_name")
def _check_name(s, m):
    n = str(m["obj"].get("name", ""))
    if not (2 <= len(n) <= 20): return fail(s, m, 2)
    ok(s, m)


@H("req_alliance_check_abbr")
def _check_abbr(s, m):
    n = str(m["obj"].get("abbr", ""))
    if len(n) != 3: return fail(s, m, 2)
    ok(s, m)


@H("req_alliance_check_whitelist_by_uid")
def _chk_wl(s, m):
    ok(s, m, exist=i(m["obj"].get("uid")) in social(acct(s))["whitelist"])


@H("req_alliance_whitelist_get")
def _wl_get(s, m):
    ok(s, m, list=list(social(acct(s))["whitelist"]))


@H("req_alliance_whitelist_add")
def _wl_add(s, m):
    wl = social(acct(s))["whitelist"]
    for u in m["obj"].get("uids") or []:
        if i(u) not in wl:
            if len(wl) >= 50: return fail(s, m, "err_alliance_whitelist_full")
            wl.append(i(u))
    ok(s, m)


@H("req_alliance_whitelist_del")
def _wl_del(s, m):
    wl = social(acct(s))["whitelist"]
    for u in m["obj"].get("uids") or []:
        if i(u) in wl: wl.remove(i(u))
    ok(s, m)


# ---------------------------------------------------------------- busca / recomendação
def _pool(a, key=None, language=None):
    base = 94000000
    out = []
    al = _al(a)
    if al: out.append(copy.deepcopy(al))
    for k in range(1, 13): out.append(_synth_alliance(base + k * 37))
    if key: out = [x for x in out if key.lower() in x["name"].lower() or key.lower() in x["abbr"].lower()]
    return out


@H("req_alliance_search_init")
def _search_init(s, m):
    ls = [_cover(x) for x in _pool(acct(s))][:10]
    ok(s, m, alliances=ls, aids=[x["aid"] for x in ls])


@H("req_alliance_search_by_key")
def _search_key(s, m):
    ls = [_cover(x) for x in _pool(acct(s), str(m["obj"].get("key", "")))][:20]
    ok(s, m, alliances=ls, aids=[x["aid"] for x in ls])


@H("req_alliance_recommend_alliance")
def _recommend(s, m):
    ok(s, m, alliance=_cover(_synth_alliance(94000037)))


@H("req_alliance_recommend_players")
def _rec_players(s, m):
    uids = [34190000 + k * 13 for k in range(6)]
    ok(s, m, uids=uids, players=[C.player_base_of(s, u) for u in uids])


@H("req_alliance_member_info_by_key")
def _mem_key(s, m):
    a = acct(s); key = str(m["obj"].get("key", "")).lower()
    uids = [x["uid"] for x in _members(a) if key in C.synth_name(x["uid"]).lower() or key in str(x["uid"])]
    ok(s, m, uids=uids)


# ---------------------------------------------------------------- criar / entrar / sair
def _join_seed(s, a, rank=1):
    st = social(a); st["left"] = False
    uid = my_uid(s); ms = _members(a)
    if not any(x["uid"] == uid for x in ms): ms.append({"uid": uid, "rank": rank})
    pl = _pl(a); pl["aid"] = (raw1(a, "notify_alliance_init") or {}).get("alliance", {}).get("aid", 0)
    pl["rank"] = rank; pl["join_time"] = now(s)
    al = raw1(a, "notify_alliance_init")["alliance"]; al["count"] = len(ms)


def _join_common(s, m):
    a = acct(s)
    if not _al(a) is None: return fail(s, m, "err_alliance_player_already_join")
    base = raw1(a, "notify_alliance_init")
    if not base: return fail(s, m, "err_alliance_player_not_in_same_alliance")
    al = base["alliance"]; req = al.get("condition") or {}
    b = C.my_base(s)
    if b.get("power", 0) < req.get("power", 0) or b.get("stove_lv", 99) < req.get("level", 0):
        return fail(s, m, "err_alliance_player_level_not_enough")
    if len(_members(a)) >= al.get("member_max", 100): return fail(s, m, "err_alliance_is_full")
    return a


@H("req_alliance_join")
def _join(s, m):
    a = _join_common(s, m)
    if a is None or a is False or isinstance(a, type(None)): return
    al = raw1(a, "notify_alliance_init")["alliance"]
    if i(m["obj"].get("aid")) not in (al["aid"], 0) and not al.get("public"):
        return fail(s, m, "err_alliance_player_not_in_same_alliance")
    if not al.get("public"):        # fechada: vira pedido
        social(a)["applys"].append(al["aid"]); return ok(s, m, ban_time=0)
    _join_seed(s, a)
    ok(s, m, alliance=copy.deepcopy(al), player=copy.deepcopy(_pl(a)), ban_time=0)


@H("req_alliance_fast_join")
def _fast_join(s, m):
    a = _join_common(s, m)
    if a is None: return
    _join_seed(s, a)
    ok(s, m, alliance=copy.deepcopy(_al(a)), player=copy.deepcopy(_pl(a)), ban_time=0)


@H("req_alliance_apply_join")
def _apply_join(s, m):
    a = acct(s)
    if _al(a): return fail(s, m, "err_alliance_player_already_join")
    aid = i(m["obj"].get("aid")); ap = social(a)["applys"]
    if aid in ap: return fail(s, m, "err_alliance_already_invite")
    ap.append(aid)
    pl = _pl(a); pl["applys"] = list(ap)
    ok(s, m, alliance=_cover(_alliance_by_aid(a, aid)), player=copy.deepcopy(pl), ban_time=0)


@H("req_alliance_cancel_apply")
def _cancel_apply(s, m):
    a = acct(s); ap = social(a)["applys"]; aid = i(m["obj"].get("aid"))
    if aid in ap: ap.remove(aid)
    ok(s, m, applys=list(ap))


@H("req_alliance_applys")
def _applys(s, m):
    a = acct(s); al = _al(a)
    ls = social(a)["misc"].get("pending", []) if al else []
    ok(s, m, applys=copy.deepcopy(ls))


@H("req_alliance_deal_apply")
def _deal_apply(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    uid = i(m["obj"].get("uid")); pend = social(a)["misc"].setdefault("pending", [])
    ent = next((x for x in pend if x["uid"] == uid), None)
    if ent is None: return fail(s, m, "err_alliance_toplayer_already_join")
    pend.remove(ent)
    if m["obj"].get("agree"):
        if len(_members(a)) >= al.get("member_max", 100): return fail(s, m, "err_alliance_is_full")
        _members(a).append({"uid": uid, "rank": 1}); al["count"] = len(_members(a))
    al["apply_num"] = len(pend)
    ok(s, m, applys=copy.deepcopy(pend), members=copy.deepcopy(_members(a)))


@H("req_alliance_invite_member")
def _invite(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    uid = i(m["obj"].get("uid")); inv = social(a)["misc"].setdefault("invited", [])
    if uid in inv: return fail(s, m, "err_alliance_already_invite")
    if any(x["uid"] == uid for x in _members(a)): return fail(s, m, "err_alliance_toplayer_already_join")
    inv.append(uid); ok(s, m)


@H("req_alliance_deal_invite")
def _deal_invite(s, m):
    a = acct(s)
    if _al(a): return fail(s, m, "err_alliance_player_already_join")
    inv = (_pl(a).get("invites") or [])
    if not m["obj"].get("agree"): return ok(s, m)
    base = raw1(a, "notify_alliance_init")
    if not base: return fail(s, m, 2)
    _join_seed(s, a)
    ok(s, m, alliance=copy.deepcopy(_al(a)), player=copy.deepcopy(_pl(a)))


@H("req_alliance_quit")
def _quit(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if al.get("leader") == my_uid(s) and len(_members(a)) > 1:
        return fail(s, m, "err_alliance_have_not_permission")
    ms = _members(a); uid = my_uid(s)
    ms[:] = [x for x in ms if x["uid"] != uid]
    al["count"] = len(ms)
    social(a)["left"] = True
    ok(s, m, player={"aid": 0, "rank": 0})


@H("req_alliance_dismiss")
def _dismiss(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if al.get("leader") != my_uid(s): return fail(s, m, "err_alliance_have_not_permission")
    social(a)["left"] = True
    ok(s, m, player={"aid": 0, "rank": 0})


@H("req_alliance_create")
def _create(s, m):
    a = acct(s); o = m["obj"]
    if _al(a): return fail(s, m, "err_alliance_player_already_join")
    name = str(o.get("name", ""))
    if not (2 <= len(name) <= 20): return fail(s, m, 2)
    cost = {DIAMOND_ID: int(cfg("systemconfig").get("alliance", {}).get("create_cost", 400))}
    e = _cost_err(a, cost)
    if e: return fail(s, m, e)
    _spend(a, cost)
    base = raw1(a, "notify_alliance_init")
    if base is None: return fail(s, m, 2)
    al = base["alliance"]
    al.update({"name": name, "abbr": al.get("abbr", "NEW")[:3], "flag": [i(o.get("flag"), 1)], "flag_bg": [i(o.get("flag_bg"), 1)],
               "manifesto": str(o.get("manifesto", "")), "language": i(o.get("language"), 1), "public": bool(o.get("public", True)),
               "lv": 1, "exp": 0, "leader": my_uid(s), "leader_name": C.my_base(s).get("nickName", ""), "count": 1})
    ms = _members(a); ms[:] = [{"uid": my_uid(s), "rank": 5}]
    social(a)["left"] = False
    pl = _pl(a); pl.update({"rank": 5, "join_time": now(s)})
    ok(s, m, player=copy.deepcopy(pl), alliance=copy.deepcopy(al))


# ---------------------------------------------------------------- gestão de membros
@H("req_alliance_change_rank")
def _change_rank(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    uid, rk = i(m["obj"].get("uid")), i(m["obj"].get("rank"))
    if not 1 <= rk <= 4: return fail(s, m, 2)           # rank 5 só via change_leader
    for x in _members(a):
        if x["uid"] == uid:
            if x["rank"] >= _my_rank(s, a) and uid != my_uid(s): return fail(s, m, "err_alliance_have_not_permission")
            x["rank"] = rk; return ok(s, m, members=copy.deepcopy(_members(a)))
    fail(s, m, "err_alliance_player_not_in_same_alliance")


@H("req_alliance_del_member")
def _del_member(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    uid = i(m["obj"].get("uid")); ms = _members(a)
    tgt = next((x for x in ms if x["uid"] == uid), None)
    if tgt is None: return fail(s, m, "err_alliance_player_not_in_same_alliance")
    if tgt["rank"] >= _my_rank(s, a): return fail(s, m, "err_alliance_have_not_permission")
    ms.remove(tgt); al["count"] = len(ms)
    ok(s, m, members=copy.deepcopy(ms))


@H("req_alliance_change_leader")
def _change_leader(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if al.get("leader") != my_uid(s): return fail(s, m, "err_alliance_have_not_permission")
    uid = i(m["obj"].get("uid")); ms = _members(a)
    tgt = next((x for x in ms if x["uid"] == uid), None)
    if tgt is None: return fail(s, m, "err_alliance_player_not_in_same_alliance")
    for x in ms:
        if x["uid"] == my_uid(s): x["rank"] = 4
    tgt["rank"] = 5; al["leader"] = uid; al["leader_name"] = C.synth_name(uid)
    pl = _pl(a); pl["rank"] = 4
    ok(s, m, player=copy.deepcopy(pl), members=copy.deepcopy(ms))


@H("req_alliance_replace_leader")
def _replace_leader(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if _my_rank(s, a) < 4 or al.get("leader") == my_uid(s): return fail(s, m, "err_alliance_have_not_permission")
    cost = {DIAMOND_ID: int(cfg("systemconfig").get("alliance", {}).get("replace_leader_cost", 200))}
    e = _cost_err(a, cost)
    if e: return fail(s, m, e)
    _spend(a, cost)
    ms = _members(a)
    for x in ms:
        if x["uid"] == al["leader"]: x["rank"] = 4
        if x["uid"] == my_uid(s): x["rank"] = 5
    al["leader"] = my_uid(s); al["leader_name"] = C.my_base(s).get("nickName", "")
    pl = _pl(a); pl["rank"] = 5
    ok(s, m, player=copy.deepcopy(pl), members=copy.deepcopy(ms))


# ---------------------------------------------------------------- configurações (modify_*)
def _modify(field_map, name_count=None):
    def h(s, m):
        r = _need_ally(s, m)
        if not r: return
        a, al = r
        if not _need_perm(s, m, a): return
        o = m["obj"]
        for k_req, k_al in field_map.items():
            if k_req in o:
                v = o[k_req]
                al[k_al] = [i(x) for x in v] if isinstance(v, list) else v
        resp = {}
        if name_count:
            st = social(a)["misc"]; st[name_count] = st.get(name_count, 0) + 1
            resp["setting"] = {"abbr_count": st.get("abbr_count", 0), "name_count": st.get("name_count", 0)}
        ok(s, m, **resp)
    return h


HANDLERS["req_alliance_modify_name"] = safe(_modify({"name": "name"}, "name_count"))
HANDLERS["req_alliance_modify_abbr"] = safe(_modify({"abbr": "abbr"}, "abbr_count"))
HANDLERS["req_alliance_modify_flag"] = safe(_modify({"flag": "flag", "flag_bg": "flag_bg"}))
HANDLERS["req_alliance_modify_language"] = safe(_modify({"language": "language"}))
HANDLERS["req_alliance_modify_manifesto"] = safe(_modify({"manifesto": "manifesto"}))
HANDLERS["req_alliance_modify_recruit_type"] = safe(_modify({"public": "public"}))


@H("req_alliance_modify_recruit_cond")
def _recruit_cond(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    al["condition"] = {"level": i(m["obj"].get("level")), "power": i(m["obj"].get("power"))}
    ok(s, m)


@H("req_alliance_modify_rank_name")
def _rank_names(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if _my_rank(s, a) < 5: return fail(s, m, "err_alliance_have_not_permission")
    rn = m["obj"].get("rank_names")
    if isinstance(rn, list): al["rank_names"] = [{"rank": i(x.get("rank")), "name": str(x.get("name", ""))} for x in rn]
    ok(s, m)


# ---------------------------------------------------------------- avisos (notice) / histórico / reserva
def _notices(a):
    return social(a)["notices"]


@H("req_alliance_modify_notice")
def _modify_notice(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    o = m["obj"]; t = now(s)
    al.update({"notice": str(o.get("notice", "")), "notice_uid": my_uid(s), "notice_time": t,
               "notice_open_like": bool(o.get("open_like")), "notice_top": bool(o.get("top")), "notice_star": bool(o.get("star"))})
    _notices(a).insert(0, {"notice": al["notice"], "uid": my_uid(s), "ts": t, "uuid": f"n{C.next_id(a)}", "star": bool(o.get("star")),
                           "open_like": bool(o.get("open_like")), "like_data": {"like": 0, "unlike": 0}})
    ok(s, m)


@H("req_alliance_get_notice_history")
def _notice_hist(s, m):
    a = acct(s); o = m["obj"]; ls = _notices(a)
    if not ls and _al(a) and _al(a).get("notice"):
        al = _al(a)
        ls = [{"notice": al["notice"], "uid": al.get("notice_uid", 0), "ts": al.get("notice_time", 0), "uuid": "n1", "like_data": {"like": 0, "unlike": 0}}]
    idx, size = i(o.get("idx")), max(1, i(o.get("size"), 20))
    ok(s, m, list=copy.deepcopy(ls[idx:idx + size]), like_idx_arr=[], unlike_idx_arr=[], self_like_uuids=[], self_unlike_uuids=[])


@H("req_alliance_get_notice_star_history")
def _notice_star(s, m):
    a = acct(s); o = m["obj"]; ls = [x for x in _notices(a) if x.get("star")]
    idx, size = i(o.get("idx")), max(1, i(o.get("size"), 20))
    ok(s, m, list=copy.deepcopy(ls[idx:idx + size]), self_like_uuids=[], self_unlike_uuids=[])


@H("req_alliance_del_notice_history")
def _notice_del(s, m):
    ls = _notices(acct(s)); k = i(m["obj"].get("idx"), -1)
    if 0 <= k < len(ls): ls.pop(k)
    ok(s, m)


def _find_notice(a, uuid):
    return next((x for x in _notices(a) if x.get("uuid") == uuid), None)


def _hist_flag(flag):
    def h(s, m):
        r = _need_ally(s, m)
        if not r: return
        a, al = r
        if not _need_perm(s, m, a): return
        n = _find_notice(a, str(m["obj"].get("uuid", "")))
        if n is None: return fail(s, m, "err_chat_group_history_notice_not_exist" if False else 2)
        n[flag[0]] = bool(m["obj"].get(flag[1])); ok(s, m)
    return h


HANDLERS["req_alliance_star_history_notice"] = safe(_hist_flag(("star", "star")))
HANDLERS["req_alliance_top_history_notice"] = safe(_hist_flag(("top", "top")))
HANDLERS["req_alliance_history_notice_open_like"] = safe(_hist_flag(("open_like", "open_like")))


@H("req_alliance_like_notice")
def _like(s, m):
    a = acct(s); o = m["obj"]; st = social(a)["misc"]
    ld = st.setdefault("like", {"like": 0, "unlike": 0})
    if i(o.get("type")) == 1: ld["like"] += 1
    else: ld["unlike"] += 1
    ok(s, m, like=ld["like"], unlike=ld["unlike"], last_time=now(s))


@H("req_alliance_cur_notice_like_data")
def _cur_like(s, m):
    ld = social(acct(s))["misc"].get("like", {"like": 0, "unlike": 0})
    ok(s, m, like_data={"like": ld["like"], "unlike": ld["unlike"], "type": 0})


@H("req_alliance_get_all_reserve_notice")
def _rn_all(s, m):
    ok(s, m, reserve_notice_list=copy.deepcopy(social(acct(s))["reserve"]))


@H("req_alliance_get_reserve_notice_count")
def _rn_count(s, m):
    ok(s, m, count=len(social(acct(s))["reserve"]))


@H("req_alliance_reserve_notice")
def _rn_add(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    lim = int(cfg("systemconfig").get("alliance", {}).get("notice_reserve_count", 10))
    rs = social(a)["reserve"]
    if len(rs) >= lim: return fail(s, m, "err_alliance_whitelist_full")
    o = m["obj"]
    n = {"uid": my_uid(s), "notice": str(o.get("notice", "")), "create_ts": now(s), "publish_ts": i(o.get("ts")),
         "uuid": f"r{C.next_id(a)}", "open_like": bool(o.get("open_like")), "top": bool(o.get("top")), "star": bool(o.get("star"))}
    rs.append(n); ok(s, m, data=copy.deepcopy(n))


@H("req_alliance_change_reserve_notice")
def _rn_chg(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    o = m["obj"]; n = next((x for x in social(a)["reserve"] if x["uuid"] == o.get("uuid")), None)
    if n is None: return fail(s, m, 2)
    n.update({"notice": str(o.get("notice", "")), "publish_ts": i(o.get("ts")), "open_like": bool(o.get("open_like")),
              "top": bool(o.get("top")), "star": bool(o.get("star"))})
    ok(s, m, data=copy.deepcopy(n))


@H("req_alliance_cancel_reserve_notice")
def _rn_cancel(s, m):
    a = acct(s); rs = social(a)["reserve"]
    rs[:] = [x for x in rs if x["uuid"] != m["obj"].get("uuid")]
    ok(s, m)


# ---------------------------------------------------------------- ciência / doação (custos reais + buff)
def _science_row(sid, lv):
    return cfg("alliance_science_detail").get(f"{sid}{lv}")


def _sci_state(a, sid):
    o = raw1(a, "notify_alliance_science_init")
    if not o: return None, None
    for x in o.get("sciences", []):
        if x["id"] == sid: return o, x
    return o, None


def _donate_common(s, m, diamond):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    sid = i(m["obj"].get("id"))
    root, sci = _sci_state(a, sid)
    if sci is None: return fail(s, m, "err_alliance_science_type_not_exist")
    row = _science_row(sid, sci["lv"] + 1)
    if row is None: return fail(s, m, "err_alliance_science_donate_full")
    need = row.get("need_donation_value", 0)
    if sci["donate"] >= need: return fail(s, m, "err_alliance_science_donate_full")
    dc = row.get("donate_cost") or {}
    base_item, base_cnt = i(dc.get("1")), i(dc.get("2"))
    if base_cnt <= 0: return fail(s, m, "err_alliance_science_can_not_research")
    sconf = cfg("systemconfig").get("alliance_science_conf", {})
    if diamond:
        cost = {DIAMOND_ID: int(sconf.get("diamond_cost", 10))}
    else:
        cost = {base_item: base_cnt}
    e = _cost_err(a, cost)
    if e: return fail(s, m, e)
    pl = _pl(a); dn = pl.setdefault("donate", {})
    if diamond:
        dn["diamond_count"] = dn.get("diamond_count", 0) + 1
    else:
        dn["resource_count"] = dn.get("resource_count", 0) + base_cnt
    _spend(a, cost)
    # multiplicador (crit) conforme res_conf.rates
    rates = sconf.get("res_conf", {}).get("rates", {"1": 100}); mult_tab = sconf.get("res_conf", {}).get("multiple", {"1": 1})
    rng = random.Random((my_uid(s) << 20) ^ C.next_id(a))
    tot = sum(rates.values()); x = rng.uniform(0, tot); acc = 0; mult = 1
    for k, w in rates.items():
        acc += w
        if x <= acc: mult = int(mult_tab.get(k, 1)); break
    gain = (base_cnt if not diamond else base_cnt * 2) * mult
    sci["donate"] = min(need, sci["donate"] + gain)
    root["donate_day"] = root.get("donate_day", 0) + gain
    # recompensa pessoal (systemconfig.alliance_science_conf.donate_reward: id,qtd pares)
    dr = sconf.get("donate_reward", {}); items = {}
    ks = sorted(dr, key=int)
    for j in range(0, len(ks) - 1, 2):
        items[int(dr[ks[j]])] = int(dr[ks[j + 1]]) * mult
    a.grant(items)
    # buff: a ciência sobe de nível ao completar a meta de doação (a pesquisa propriamente dita é req_..._research)
    _push(s, "notify_alliance_science_exp_update", {"science": {"id": sid, "lv": sci["lv"], "donate": sci["donate"]}})
    try:
        if hasattr(s, "push_res_add"): s.push_res_add(list(items.items()))
    except Exception: pass
    ok(s, m, multiple=mult, rank_data={"rank": 1, "value": root["donate_day"]})


@H("req_alliance_science_donate")
def _sci_donate(s, m): _donate_common(s, m, False)


@H("req_alliance_science_diamond_donate")
def _sci_dia(s, m): _donate_common(s, m, True)


@H("req_alliance_science_research")
def _sci_research(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    sid = i(m["obj"].get("id"))
    root, sci = _sci_state(a, sid)
    if sci is None: return fail(s, m, "err_alliance_science_type_not_exist")
    row = _science_row(sid, sci["lv"] + 1)
    if row is None: return fail(s, m, "err_alliance_science_can_not_research")
    if sci["donate"] < row.get("need_donation_value", 0): return fail(s, m, "err_alliance_science_exp_not_enough")
    pre = row.get("prepose_technology") or {}
    if pre:
        _, ps = _sci_state(a, i(pre.get("1")))
        if ps is None or ps["lv"] < i(pre.get("2")): return fail(s, m, "err_alliance_science_not_meet_condition")
    cr = row.get("cost_alliance_resource") or {}
    cost = {i(cr[k]): i(cr[str(int(k) + 1)]) for k in cr if int(k) % 2 == 1 and str(int(k) + 1) in cr}
    res = {x["id"]: x["count"] for x in (al.get("resource") or [])}
    if C.R and C.R.check_cost(res, cost): return fail(s, m, "err_alliance_science_not_enough")
    for x in al.get("resource", []):
        x["count"] -= cost.get(x["id"], 0)
    sci["lv"] += 1; sci["donate"] = 0       # conclusão imediata (sem fila de pesquisa; ver relatório)
    _push(s, "notify_alliance_science_exp_update", {"science": copy.deepcopy(sci)})
    ok(s, m)


@H("req_alliance_science_recommend")
def _sci_rec(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    root, sci = _sci_state(a, i(m["obj"].get("id")))
    if sci is None: return fail(s, m, "err_alliance_science_type_not_exist")
    root["recommend"] = sci["id"]; ok(s, m)


@H("req_alliance_science_cancel_recommend")
def _sci_unrec(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    root = raw1(a, "notify_alliance_science_init") or {}
    root["recommend"] = 0; ok(s, m)


# ---------------------------------------------------------------- desenvolvimento / ajuda / recursos / bomba
@H("req_alliance_dev_get_main")
def _dev_main(s, m):
    d = raw1(acct(s), "notify_alliance_dev_init") or {}
    ok(s, m, total_point=d.get("point", 0), last_week_reward=[])


@H("req_alliance_dev_get_week")
def _dev_week(s, m):
    a = acct(s); d = raw1(a, "notify_alliance_dev_init") or {}
    ok(s, m, reward=[], week_point=d.get("point", 0), member_map=[{"k": my_uid(s), "v": d.get("point", 0)}], rank=1)


@H("req_alliance_dev_get_rank")
def _dev_rank(s, m):
    a = acct(s); d = raw1(a, "notify_alliance_dev_init") or {}
    ok(s, m, list=[{"key": my_uid(s), "value": [d.get("point", 0)]}])


@H("req_alliance_dev_get_daily")
def _dev_daily(s, m):
    a = acct(s); d = raw1(a, "notify_alliance_dev_init")
    if not _al(a): return fail(s, m, "err_alliance_player_not_in_same_alliance")
    e = s.replay_err("alliance_dev_daily", my_uid(s)) if hasattr(s, "replay_err") else (
        C.err("err_alliance_dev_already_get_daily_reward") if social(a)["misc"].get("dev_daily") == s.now() // 86400 else None)
    if e: return fail(s, m, e)
    social(a)["misc"]["dev_daily"] = s.now() // 86400
    if d is not None: d["daily_manual"] = True
    reward = [{"id": 101, "count": 50}, {"id": 110, "count": 1000}]       # sintético (alliance_dev_config só dá ids de mail)
    a.grant([(x["id"], x["count"]) for x in reward])
    ok(s, m, reward=reward)


@H("req_alliance_help_all")
def _help_all(s, m):
    a = acct(s)
    h = raw1(a, "notify_alliance_help_init") or {}
    ah = h.get("alliance_help") or {}
    pending = [x for x in ah.get("help_list", []) if my_uid(s) not in (x.get("helpers") or []) and x.get("uid") != my_uid(s)]
    if not pending: return fail(s, m, "err_alliance_already_help_all")
    glory = int(cfg("systemconfig").get("alliance", {}).get("help_reward", {}).get("2", 20))
    cap = int(cfg("systemconfig").get("alliance", {}).get("help_glory_day_max", 2000))
    gain = min(glory * len(pending), max(0, cap - ah.get("day_glory", 0)))
    for x in pending: x.setdefault("helpers", []).append(my_uid(s))
    ah["day_glory"] = ah.get("day_glory", 0) + gain; ah["help_num"] = ah.get("help_num", 0) + len(pending)
    rw = [{"id": 110, "count": gain}] if gain else []
    if rw: a.grant([(110, gain)])
    ok(s, m, count=len(pending), rewards=rw, day_glory=ah["day_glory"])


@H("req_alliance_exchange_resource")
def _exchange(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    rid, cnt = i(m["obj"].get("id")), i(m["obj"].get("count"))
    ex = cfg("alliance_resources_exchange").get(str(rid))
    res = next((x for x in al.get("resource", []) if x["id"] == rid), None)
    if res is None or cnt <= 0 or res["count"] < cnt: return fail(s, m, "err_alliance_science_not_enough")
    lim = int((al.get("resource_exchange") or {}).get("count", 100000))
    if cnt > lim: return fail(s, m, 2)
    res["count"] -= cnt
    ok(s, m)


@H("req_alliance_bomb_use")
def _bomb(s, m):
    a = acct(s); b = raw1(a, "notify_alliance_bomb_info")
    if b: b.setdefault("info", {})["use_count"] = b["info"].get("use_count", 0) + 1
    ok(s, m)


@H("req_alliance_war_mark_leader")
def _war_mark(s, m):
    a = acct(s)
    ok(s, m, replace_uid=0)


# ---------------------------------------------------------------- baú (chest)
def _chests(a):
    return (raw1(a, "notify_alliance_chest_init") or {}).get("chests", [])


def _claim(s, a, ch):
    if ch.get("receive"): return C.err("err_alliance_already_receive_chest")
    if ch.get("endtime", 1 << 40) < now(s): return 2
    ch["receive"] = True
    items = [(x["id"], x["count"]) for x in ch.get("rewards", [])]
    if items: a.grant(items)
    root = raw1(a, "notify_alliance_chest_init") or {}
    root["trophy_received_count"] = root.get("trophy_received_count", 0) + 1
    return 0


@H("req_alliance_receive_chest")
def _rc(s, m):
    a = acct(s)
    ch = next((c for c in _chests(a) if c["id"] == i(m["obj"].get("id"))), None)
    if ch is None: return fail(s, m, 2)
    c = _claim(s, a, ch)
    if c: return fail(s, m, c)
    ok(s, m, chest=copy.deepcopy(ch), trophy_received_count=(raw1(a, "notify_alliance_chest_init") or {}).get("trophy_received_count", 0))


@H("req_alliance_receive_chest_by_ids")
def _rc_ids(s, m):
    a = acct(s); ids = set(i(x) for x in (m["obj"].get("ids") or []))
    got = 0
    for ch in _chests(a):
        if ch["id"] in ids and not _claim(s, a, ch): got += 1
    if not got and ids: return fail(s, m, "err_alliance_already_receive_chest")
    ok(s, m)


@H("req_alliance_receive_chest_by_type")
def _rc_type(s, m):
    a = acct(s); t = i(m["obj"].get("type")); got = 0
    for ch in _chests(a):
        ci = cfg("alliance_chest").get(str(ch.get("cid")), {})
        if (t == 0 or ci.get("type") == t) and not _claim(s, a, ch): got += 1
    ok(s, m)


@H("req_alliance_chest_set_anonymity")
def _anon(s, m):
    _pl(acct(s))["anonymity"] = bool(m["obj"].get("anonymity")); ok(s, m)


# ---------------------------------------------------------------- rankings
@H("req_alliance_members_power_rank")
def _pow_rank(s, m):
    a = acct(s)
    ls = [{"key": x["uid"], "value": C.player_base_of(s, x["uid"]).get("power", 0)} for x in _members(a)]
    ls.sort(key=lambda r: -r["value"])
    for n, r in enumerate(ls, 1): r["rank"] = n
    ok(s, m, list=ls)


@H("req_alliance_members_kill_num_rank")
def _kill_rank(s, m):
    a = acct(s)
    ls = [{"key": x["uid"], "value": (x["uid"] * 31) % 100000} for x in _members(a)]
    ls.sort(key=lambda r: -r["value"])
    for n, r in enumerate(ls, 1): r["rank"] = n
    ok(s, m, list=ls)


@H("req_alliance_rank_data")
def _rank_data(s, m):
    a = acct(s); al = _al(a)
    ls = [{"key": x["aid"], "value": [x["power"], x["lv"]]} for x in _pool(a)]
    ls.sort(key=lambda r: -r["value"][0])
    for n, r in enumerate(ls, 1): r["rank"] = n
    ok(s, m, rank_list=ls[:20], join_info=[])


@H("req_alliance_player_rank_data")
def _player_rank(s, m):
    d = raw1(acct(s), "notify_alliance_dev_init") or {}
    ok(s, m, rank_data={"rank": 1, "value": d.get("point", 0)})


@H("req_alliance_rank_get_rewards")
def _rank_rw(s, m):
    ok(s, m, rewards=[])


# ---------------------------------------------------------------- prédios
@H("req_alliance_building_list")
def _bl(s, m):
    a = acct(s); o = raw1(a, "notify_alliance_building_simple_info") or {}
    ok(s, m, merged=False, merge_zero_ts=0, building_storage=[])


@H("req_alliance_building_list_exist")
def _ble(s, m):
    a = acct(s); o = raw1(a, "notify_alliance_building_simple_info") or {}
    ok(s, m, building_list=[{"id": b["id"], "x": b["x"], "y": b["y"], "bid": b["bid"], "blv": b.get("blv", 1), "is_finish": True,
                             "is_active": True} for b in o.get("building_list", [])])


@H("req_alliance_building_add")
def _ba(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    o = raw1(a, "notify_alliance_building_simple_info")
    if o is None: return fail(s, m, 2)
    bid = i(m["obj"].get("bid"))
    cost_row = cfg("alliance_building_cost").get(str(bid)) or {}
    o.setdefault("building_list", []).append({"id": 90000 + C.next_id(a), "x": i(m["obj"].get("x")), "y": i(m["obj"].get("y")), "bid": bid})
    ok(s, m)


@H("req_alliance_building_remove")
def _br(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    o = raw1(a, "notify_alliance_building_simple_info") or {}
    bl = o.get("building_list", []); bid = i(m["obj"].get("id"))
    n0 = len(bl); bl[:] = [b for b in bl if b["id"] != bid]
    if len(bl) == n0: return fail(s, m, "err_alliance_resource_already_delete")
    ok(s, m)


@H("req_alliance_hall_move")
def _hm(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    o = raw1(a, "notify_alliance_building_simple_info") or {}
    for b in o.get("building_list", []):
        if b["id"] == i(m["obj"].get("id")):
            b["x"], b["y"] = i(m["obj"].get("target_x")), i(m["obj"].get("target_y")); return ok(s, m)
    fail(s, m, 2)


# ---------------------------------------------------------------- votos
def _votes(a): return social(a)["votes"]


@H("req_alliance_vote_add")
def _vote_add(s, m):
    r = _need_ally(s, m)
    if not r: return
    a, al = r
    if not _need_perm(s, m, a): return
    o = m["obj"]; vc = cfg("systemconfig").get("alliance_vote", {})
    opts = [str(x) for x in (o.get("options") or [])]
    if not (vc.get("option_min", 2) <= len(opts) <= vc.get("option_limit", 10)): return fail(s, m, "err_alliance_whitelist_full" if False else 2)
    t = now(s); dur = i(o.get("time"), 0)
    st = t; et = dur if dur > t else t + max(vc.get("min_time", 7200), min(vc.get("max_time", 259200), 86400))
    _votes(a).append({"id": C.next_id(a), "uid": my_uid(s), "is_multi": bool(o.get("is_multi")), "st": st, "et": et,
                      "title": str(o.get("title", "")), "options": opts, "selects": [], "total": 0,
                      "s_uname": C.my_base(s).get("nickName", ""), "e_uname": "",
                      "join_ranks": [{"k": i(x.get("k")), "v": bool(x.get("v"))} for x in (o.get("join_ranks") or []) if isinstance(x, dict)],
                      "_voters": {}, "_top": False})
    ok(s, m)


def _vote_pub(v):
    return {k: copy.deepcopy(x) for k, x in v.items() if not k.startswith("_")}


@H("req_alliance_vote_records")
def _vote_records(s, m):
    ok(s, m, records=[_vote_pub(v) for v in _votes(acct(s))])


def _find_vote(a, vid): return next((v for v in _votes(a) if v["id"] == vid), None)


@H("req_alliance_vote_record_detail")
def _vote_detail(s, m):
    a = acct(s); v = _find_vote(a, i(m["obj"].get("id")))
    if v is None: return fail(s, m, 2)
    pls = []
    if m["obj"].get("need_info"):
        for uid in v["_voters"]:
            pb = C.player_base_of(s, int(uid))
            pls.append({"uid": int(uid), "nickName": pb["nickName"], "power": pb["power"], "stove_lv": pb["stove_lv"], "rank": 1})
    ok(s, m, players=pls, vote=_vote_pub(v))


@H("req_alliance_vote_select")
def _vote_select(s, m):
    a = acct(s); v = _find_vote(a, i(m["obj"].get("id")))
    if v is None: return fail(s, m, 2)
    if v["et"] < now(s): return fail(s, m, 2)
    sel = [i(x) for x in (m["obj"].get("list") or [])]
    if not sel or any(not 0 <= x < len(v["options"]) for x in sel) or (not v["is_multi"] and len(sel) > 1): return fail(s, m, 2)
    if str(my_uid(s)) in v["_voters"]: return fail(s, m, 2)
    v["_voters"][str(my_uid(s))] = sel
    cnt = {}
    for lst in v["_voters"].values():
        for x in lst: cnt[x] = cnt.get(x, 0) + 1
    v["selects"] = [{"k": k, "v": c} for k, c in sorted(cnt.items())]; v["total"] = len(v["_voters"])
    ok(s, m)


@H("req_alliance_vote_finish")
def _vote_finish(s, m):
    a = acct(s)
    if not _need_perm(s, m, a): return
    v = _find_vote(a, i(m["obj"].get("id")))
    if v is None: return fail(s, m, 2)
    v["et"] = now(s); v["e_uname"] = C.my_base(s).get("nickName", ""); ok(s, m)


@H("req_alliance_vote_delete_record")
def _vote_del(s, m):
    a = acct(s)
    if not _need_perm(s, m, a): return
    vs = _votes(a); n0 = len(vs); vs[:] = [v for v in vs if v["id"] != i(m["obj"].get("id"))]
    if len(vs) == n0: return fail(s, m, 2)
    ok(s, m)


@H("req_alliance_vote_top")
def _vote_top(s, m):
    a = acct(s)
    if not _need_perm(s, m, a): return
    v = _find_vote(a, i(m["obj"].get("id")))
    if v is None: return fail(s, m, 2)
    v["_top"] = bool(m["obj"].get("top")); ok(s, m)


@H("req_alliance_vote_share_to_uids")
def _vote_share(s, m):
    a = acct(s); v = _find_vote(a, i(m["obj"].get("id")))
    if v is None: return fail(s, m, 2)
    ok(s, m, uids=[i(x) for x in (m["obj"].get("uids") or [])], msg=v["title"])


# ---------------------------------------------------------------- armadilha (trap)
def _trap(a, tid):
    for o in (getattr(a, "raw", {}) or {}).get("notify_alliance_trap_update", []):
        if o.get("trap_id") == tid: return o
    return None


@H("req_alliance_trap_info")
def _trap_info(s, m):
    a = acct(s); t = _trap(a, i(m["obj"].get("trap_id"))) or {}
    ok(s, m, code=None, mass_start_time=0, mass_end_time=0, cool_end_time=0, donate=t.get("donate", 0),
       total_score=t.get("total_score", 0), reserve_time=0)


@H("req_alliance_trap_score_rank")
def _trap_rank(s, m):
    a = acct(s); t = _trap(a, i(m["obj"].get("trap_id"))) or {}
    ok(s, m, rank_list=[{"uid": my_uid(s), "score": t.get("total_score", 0)}], rank=1, score=t.get("total_score", 0))


@H("req_alliance_trap_get_mass_record")
def _trap_mass(s, m): ok(s, m, code=None, infos=[])


@H("req_alliance_trap_join_count")
def _trap_join(s, m): ok(s, m, count=0)


@H("req_alliance_trap_batch_get_personal_score_reward")
def _trap_batch(s, m): ok(s, m, rewarded_lst=[])


@H("req_alliance_trap_buff_strengthen")
def _trap_buff(s, m):
    a = acct(s); t = _trap(a, i(m["obj"].get("trap_id")))
    cnt = i(m["obj"].get("count"))
    if t is None or cnt <= 0: return fail(s, m, 2)
    cost = {101: 0}  # custo exato em alliance_trap_strengthen (não ligado) -> só contabiliza a doação
    t["donate"] = t.get("donate", 0) + cnt; ok(s, m)


# ---------------------------------------------------------------- logs (vazios plausíveis)
@H("req_alliance_activity_logs")
def _alogs(s, m): ok(s, m, data=[], log_set=[])


@H("req_alliance_activity_sub_logs")
def _alogs2(s, m): ok(s, m, data=[])


@H("req_alliance_battle_logs")
def _blogs(s, m): ok(s, m, data=[])


# ---------------------------------------------------------------- stubs (guerras/eventos): code:0 + listas vazias
def _stub(s, m):
    ok(s, m)


for _n in C.req_names("req_alliance_"):
    if _n not in HANDLERS:
        HANDLERS[_n] = safe(_stub)
    else:
        pass
STUBS = sorted(n for n in HANDLERS if HANDLERS[n].__name__ == "_stub")
