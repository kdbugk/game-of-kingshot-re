"""_ext_common.py — helpers comuns de ext_alliance.py / ext_chat.py (standalone, stdlib).

Estado social vive em `account.social` (dict JSON-safe, chaves str) — persiste junto com a conta
porque Account.to_dict() serializa __dict__. O que NÃO é modelado pela Account (aliança) é lido do
passthrough `account.raw` (notify_alliance_init etc.), que é a fonte de verdade do seed.
"""
import copy, json, os, re, time

try:
    import server_rules as R
except Exception:       # pragma: no cover
    R = None

HERE = os.path.dirname(os.path.abspath(__file__))
CFG_DIR = os.environ.get("KS_CFG_DIR", r"C:/Users/prs/work/lua-logic/cfg")
_cfg_cache = {}


def cfg(name):
    if name not in _cfg_cache:
        try:
            with open(os.path.join(CFG_DIR, name + ".json"), encoding="utf8") as f:
                _cfg_cache[name] = json.load(f)
        except (OSError, ValueError):
            _cfg_cache[name] = {}
    return _cfg_cache[name]


def err(name, default=2):
    """código de erro real (errcodes.json); fallback err_param_illegal=2."""
    try:
        return R.ERR.get(name, default) if R else default
    except Exception:
        return default


def acct(session):
    return getattr(session, "account", None) or getattr(session, "acct", None)


def now(session=None):
    try:
        return int(session.now())
    except Exception:
        return int(time.time())


def my_uid(session):
    a = acct(session)
    try:
        return int(a.base.get("uid") or a.meta.get("uid") or 0)
    except Exception:
        return 0


def my_base(session):
    a = acct(session)
    return getattr(a, "base", {}) or {}


def raw1(a, name):
    """primeiro objeto do passthrough `raw[name]` (mutável, in-place) ou None."""
    lst = (getattr(a, "raw", {}) or {}).get(name) or []
    return lst[0] if lst else None


def social(a):
    s = getattr(a, "social", None)
    if s is None:
        s = {"left": False, "applys": [], "whitelist": [], "votes": [], "next_id": 1, "notices": [],
             "reserve": [], "chat": {}, "block": {}, "groups": {}, "read": {}, "at": {}, "misc": {}}
        a.social = s
    return s


def next_id(a):
    s = social(a)
    s["next_id"] = int(s.get("next_id", 1)) + 1
    return s["next_id"]


def ok(session, m, **kw):
    kw.setdefault("code", 0)
    if kw["code"] is None: del kw["code"]       # mensagens cujo response não tem campo code
    session.reply(m, kw)


def fail(session, m, name_or_code, **kw):
    c = name_or_code if isinstance(name_or_code, int) else err(name_or_code)
    session.reply(m, {"code": c, **kw})


def safe(fn):
    """handler nunca lança: qualquer exceção vira code err_param_illegal (2)."""
    def w(session, m):
        try:
            fn(session, m)
        except Exception as e:                      # noqa
            try:
                log = getattr(session, "log", None)
                if log: log(f"[EXT] {m.get('name')} erro {e!r}")
            except Exception:
                pass
            try:
                session.reply(m, {"code": 2})
            except Exception:
                pass
    w.__name__ = getattr(fn, "__name__", "h")
    return w


def i(v, d=0):
    try:
        return int(v)
    except Exception:
        return d


def req_names(prefix):
    """nomes req_<prefix>* do schema c2s (para registrar stubs em todo o módulo)."""
    names = []
    cands = [os.environ.get("KS_PROTOCOLS", ""), HERE, r"C:/Users/prs/projects/game-of-kingshot-re/protocols"]
    for d in cands:
        p = os.path.join(d, "game_proto_c2s.sproto") if d else ""
        if p and os.path.exists(p):
            with open(p, encoding="utf8") as f:
                txt = f.read()
            names = sorted(set(re.findall(r"^(" + re.escape(prefix) + r"\w+)\s+\d+\s*\{", txt, re.M)))
            break
    return names


# ---------------------------------------------------------------- jogadores sintéticos (nomes plausíveis)
_N = ["Aldric", "Brenna", "Cael", "Dorian", "Elowen", "Fenris", "Garrick", "Hilda", "Ivar", "Jora",
      "Kael", "Lyra", "Magnus", "Nyx", "Orin", "Petra", "Quill", "Rhea", "Soren", "Thalia"]


def synth_name(uid):
    return f"{_N[uid % len(_N)]}{uid % 10000}"


def player_base_of(session, uid):
    """player_base (schema) p/ uid: o próprio usa o seed; outros são sintéticos deterministas."""
    b = my_base(session)
    if uid == my_uid(session) and b:
        keys = ("nickName", "lv", "uid", "offline_time", "power", "image", "vip", "language", "kid", "fid", "stove_lv",
                "vip_show_in_chat", "is_vip_active")
        o = {k: b[k] for k in keys if k in b}
        if b.get("alliance"):
            o["alliance"] = copy.deepcopy(b["alliance"])
        return o
    a = acct(session)
    al = raw1(a, "notify_alliance_init") or {}
    mem = {x["uid"] for x in (raw1(a, "notify_alliance_member_init") or {}).get("members", [])}
    o = {"nickName": synth_name(uid), "lv": 30 + uid % 20, "uid": uid, "offline_time": now(session) - 3600 - uid % 5000,
         "power": 1000000 + (uid * 7919) % 90000000, "image": 1001 + uid % 10, "vip": uid % 10, "language": "en",
         "kid": b.get("kid", 1), "fid": uid * 3, "stove_lv": 20 + uid % 20}
    if uid in mem and al.get("alliance"):
        o["alliance"] = {"aid": al["alliance"]["aid"], "abbr": al["alliance"].get("abbr", ""),
                         "name": al["alliance"].get("name", "")}
    return o
