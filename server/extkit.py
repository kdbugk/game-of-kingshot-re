#!/usr/bin/env python3
"""extkit.py — utilitários comuns dos ext_*.py (esqueleto schema-driven, cfg, anti-replay, estado, erros).
Sem dependência do mock_v4. Tudo tolerante: nenhuma função aqui lança para o handler."""
import json, os, random, time, functools
import sproto_lib as L
import server_rules as R

CFG_DIR = os.environ.get("CFG_DIR", "C:/Users/prs/work/lua-logic/cfg")
_S = None
_CFG = {}

def schema():
    global _S
    if _S is None: _S = L.default_schema()
    return _S

def cfg(name):
    if name not in _CFG:
        try:
            with open(os.path.join(CFG_DIR, name + ".json"), encoding="utf8") as f: _CFG[name] = json.load(f)
        except Exception: _CFG[name] = {}
    return _CFG[name]

def pairs(d):
    """{'1':id,'2':cnt,'3':id,'4':cnt} -> [(id,cnt),...] (formato alternado das cfg)."""
    if not isinstance(d, dict): return []
    v = [d[k] for k in sorted(d, key=lambda x: int(x))]
    return [(v[i], v[i + 1]) for i in range(0, len(v) - 1, 2)]

def items(pl): return [{"id": i, "count": c} for i, c in pl]

# ---- erros reais (errcodes.json)
def err(name, default=2):
    return R.ERR.get(name, R.ERR.get("err_" + name, default))

# ---- relógio / conta / estado
def now(s):
    try: return int(s.now())
    except Exception: return int(time.time())

def acct(s):
    return getattr(s, "account", None) or getattr(s, "acct", None)

def st(s, mod, init=None):
    """estado do módulo, pendurado na conta (`ext_state`); sobrevive enquanto a conta viver em memória."""
    a = acct(s)
    holder = a if a is not None else s
    d = getattr(holder, "ext_state", None)
    if d is None:
        d = {}
        try: holder.ext_state = d
        except Exception: pass
    if mod not in d: d[mod] = init() if init else {}
    return d[mod]

def me(s):
    a = acct(s); b = getattr(a, "base", None) or {}
    return {"uid": b.get("uid", getattr(a, "meta", {}).get("uid", 1) if a else 1), "kid": b.get("kid", 1),
            "nickName": b.get("nickName", "Player"), "abbr": b.get("abbr", "")}

def grant(s, pl):
    """pl = [(id,count)]. Credita e devolve lista item[] p/ o cliente."""
    a = acct(s); pl = [(int(i), int(c)) for i, c in pl if c]
    if a is not None and pl:
        try: a.grant(pl)
        except Exception: pass
    return items(pl)

def spend_or_sandbox(s, pl):
    """Sandbox generoso: debita se há saldo; se faltar, completa o saldo (lab) e debita. Sempre True."""
    a = acct(s)
    if a is None: return True
    try:
        for i, c in pl:
            miss = c - a.balance(i)
            if miss > 0: a.grant([(i, miss)])
        return a.spend(pl)
    except Exception: return True

# ---- anti-replay (reusa ReplayRegistry da sessão; registra kinds novos em server_rules em runtime)
def register_kind(kind, errname, daily=False):
    R.REPLAY_ERR.setdefault(kind, errname)
    if daily: R.DAILY_KINDS.add(kind)

def once(s, kind, key, errname=None, daily=False):
    """None se 1ª vez (já marca) ou código de erro se repetido."""
    if errname: register_kind(kind, errname, daily)
    reg = getattr(s, "replay", None)
    try:
        if reg is not None:
            e = reg.check_and_mark(kind, str(key))
            return e
    except Exception: pass
    done = st(s, "_replay", dict).setdefault(kind, [])
    if str(key) in done: return R.ERR.get(R.REPLAY_ERR.get(kind, ""), 2)
    done.append(str(key)); return None

# ---- esqueleto schema-driven
_DEF = {"integer": 0, "string": "", "boolean": False, "double": 0.0, "binary": b""}

def skel_fields(fields, depth=2, full=False):
    o = {}
    for f in fields:
        if f["arr"]: continue
        t = f["type"]
        try: t = schema().resolve(t, f["owner"])      # tipos inline (nested) sombreiam os globais
        except Exception: pass
        if t in _DEF:
            if full: o[f["name"]] = _DEF[t]
        elif depth > 0:
            o[f["name"]] = skel_fields(schema().types.get(t, []), depth - 1)
    return o

def skel(typename, depth=2): return skel_fields(schema().types.get(typename, []), depth)

def rsp(s, m, code=0, **over):
    """Envia a resposta de m com esqueleto + overrides. Nunca lança."""
    try:
        spec = schema().c2s_by_name[m["name"]]["response"]
        fields = schema().fields_of(spec)
    except KeyError:
        return None                       # req fora do schema (ex.: so no MSGMAP): nao ha o que responder
    except Exception:
        spec, fields = 0, []
    if spec is None: return None      # req sem response no proto: n�o responde
    o = skel_fields(fields)
    if any(f["name"] == "code" for f in fields): o["code"] = code
    o.update(over)
    try: s.reply(m, o)
    except Exception: pass
    return o

def push(s, name, **over):
    try:
        p = schema().s2c_by_name[name]; fields = schema().fields_of(p["request"])
        o = skel_fields(fields); o.update(over); s.push(name, o)
    except Exception: pass

ERRORS = []   # excecoes engolidas (os testes exigem vazio)

def handler(fn):
    """Decorator: captura qualquer exceção e responde code genérico de erro (param_illegal=2)."""
    @functools.wraps(fn)
    def w(s, m):
        try: return fn(s, m)
        except Exception as e:
            ERRORS.append((m.get("name") if isinstance(m, dict) else "?", repr(e)))
            try:
                rsp(s, m, code=2)
            except Exception: pass
    return w

def has_response(name):
    try: return schema().c2s_by_name[name]["response"] is not None
    except Exception: return False

def obj(m): return (m.get("obj") if isinstance(m, dict) else None) or {}

def rng(seed): return random.Random(seed)
