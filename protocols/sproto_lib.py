#!/usr/bin/env python3
"""sproto_lib.py — sproto schema-driven ENCODE/DECODE + 0-pack/unpack + camada XOR + framing do gateway.

Base: protocols/sproto_py.py (parser de schema-texto). Aqui: encoder genérico (inverso do Dec),
decoder próprio (corrige boolean[]/double[]), 0-pack de referência, XOR 4B periódico, helpers de mensagem.
"""
import os, sys, struct, json

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROTO_DIRS = [os.environ.get("KS_PROTOCOLS", ""), os.path.join(_HERE, "..", "protocols"),
               r"C:/Users/prs/projects/game-of-kingshot-re/protocols", _HERE]
for _d in _PROTO_DIRS:
    if _d and os.path.exists(os.path.join(_d, "sproto_py.py")):
        sys.path.insert(0, _d); break
import sproto_py as _sp   # parser original (parse/unpack/Dec) — importado só p/ parse + validação cruzada

XOR_KEY = bytes.fromhex("ecbabcb9")   # cap115 / 1.14.27 (por-sessão; configurável)
PRIMS = ("integer", "string", "boolean", "double", "binary")

# ---------------------------------------------------------------- 0-pack
def pack(data: bytes) -> bytes:
    """0-pack de referência (sproto.c): grupos de 8 B; 0xFF = corrida de grupos densos (n>=6 não-zeros)."""
    data = bytes(data)
    if len(data) % 8:
        data += b"\0" * (8 - len(data) % 8)
    out = bytearray()
    groups = [data[i:i + 8] for i in range(0, len(data), 8)]
    i = 0
    while i < len(groups):
        g = groups[i]
        nz = sum(1 for b in g if b)
        if nz >= 8:
            # inicia corrida FF: junta grupos consecutivos densos (>=6 não-zeros), máx 256
            j = i
            while j < len(groups) and j - i < 256 and sum(1 for b in groups[j] if b) >= 6:
                j += 1
            run = groups[i:j]
            out.append(0xFF); out.append(len(run) - 1)
            for r in run: out += r
            i = j
            continue
        hdr = 0; body = bytearray()
        for k, b in enumerate(g):
            if b: hdr |= 1 << k; body.append(b)
        out.append(hdr); out += body
        i += 1
    return bytes(out)

unpack = _sp.unpack   # 0-unpack original

# ---------------------------------------------------------------- schema
class Schema:
    def __init__(self, c2s_path, s2c_path):
        self.tc, self.pc = _sp.parse(open(c2s_path, encoding="utf8").read())
        self.ts, self.ps = _sp.parse(open(s2c_path, encoding="utf8").read())
        self.types = dict(self.tc); self.types.update(self.ts)
        self._res = _sp.Dec(self.types)
        self.c2s_by_tag = {p["tag"]: (n, p) for n, p in self.pc.items()}
        self.s2c_by_tag = {p["tag"]: (n, p) for n, p in self.ps.items()}
        self.c2s_by_name = self.pc; self.s2c_by_name = self.ps
        self.package = self.types["package"]

    def resolve(self, ty, owner):
        return self._res.resolve(ty, owner)

    def fields_of(self, spec):
        if spec is None: return []
        return self.types[spec] if isinstance(spec, str) else spec

def default_schema():
    base = os.path.join(next(d for d in _PROTO_DIRS if d and os.path.exists(os.path.join(d, "game_proto_c2s.sproto"))))
    return Schema(os.path.join(base, "game_proto_c2s.sproto"), os.path.join(base, "game_proto_s2c.sproto"))

# ---------------------------------------------------------------- encode
def _int_bytes(v):
    return struct.pack("<i", v) if -2**31 <= v < 2**31 else struct.pack("<q", v)

def _lp(b):  # u32 len + bytes
    return struct.pack("<I", len(b)) + b

def enc_struct(S: Schema, fields, obj, owner=None):
    """serializa dict -> bytes (struct sproto, sem pack). Chaves '?N' (campos desconhecidos) viram dados crus."""
    if owner is None and fields: owner = fields[0]["owner"]
    hdr = []; data = bytearray(); tag = 0
    items = []
    for f in fields:
        if f["name"] in obj and obj[f["name"]] is not None: items.append((f["tag"], f, obj[f["name"]]))
    for k, v in obj.items():
        if k.startswith("?"): items.append((int(k[1:]), None, v))
    for t, f, v in sorted(items, key=lambda x: x[0]):
        if t > tag: hdr.append(2 * (t - tag) - 1); tag = t
        if f is None:                       # unknown: bytes crus (hex)
            hdr.append(0); data += _lp(bytes.fromhex(v))
        else:
            ty = S.resolve(f["type"], f["owner"])
            if f["arr"]:
                hdr.append(0); data += _lp(_enc_array(S, ty, v))
            elif ty in ("integer", "boolean"):
                iv = int(v)
                if 0 <= iv <= 0x7ffe: hdr.append((iv + 1) * 2)
                else: hdr.append(0); data += _lp(_int_bytes(iv))
            elif ty == "double":
                hdr.append(0); data += _lp(struct.pack("<d", float(v)))
            elif ty == "string":
                hdr.append(0); data += _lp(v.encode("utf8"))
            elif ty == "binary":
                hdr.append(0); data += _lp(bytes.fromhex(v))
            else:
                hdr.append(0); data += _lp(enc_struct(S, S.types[ty], v, ty))
        tag = t + 1
    return struct.pack("<H", len(hdr)) + b"".join(struct.pack("<H", h) for h in hdr) + bytes(data)

def _enc_array(S, ty, lst):
    if ty == "boolean":
        return bytes(1 if x else 0 for x in lst)
    if ty == "integer":
        if not lst: return b""
        big = any(not (-2**31 <= x < 2**31) for x in lst)
        sz = 8 if big else 4
        return bytes([sz]) + b"".join(int(x).to_bytes(sz, "little", signed=True) for x in lst)
    if ty == "double":
        return (bytes([8]) + b"".join(struct.pack("<d", float(x)) for x in lst)) if lst else b""
    if ty == "string": return b"".join(_lp(x.encode("utf8")) for x in lst)
    if ty == "binary": return b"".join(_lp(bytes.fromhex(x)) for x in lst)
    return b"".join(_lp(enc_struct(S, S.types[ty], x, ty)) for x in lst)

# ---------------------------------------------------------------- decode
def dec_struct(S: Schema, fields, b, p=0):
    fc = struct.unpack_from("<H", b, p)[0]; hp = p + 2; dp = hp + fc * 2; tag = 0; res = {}; pend = []
    for k in range(fc):
        v = struct.unpack_from("<H", b, hp + k * 2)[0]
        if v % 2 == 1: tag += (v + 1) // 2; continue
        f = next((f for f in fields if f["tag"] == tag), None)
        if v == 0: pend.append((tag, f))
        elif f: res[f["name"]] = bool(v // 2 - 1) if S.resolve(f["type"], f["owner"]) == "boolean" else v // 2 - 1
        else: res["?%d" % tag] = v // 2 - 1   # (inline desconhecido; não re-encodável)
        tag += 1
    for tag, f in pend:
        ln = struct.unpack_from("<I", b, dp)[0]; d = b[dp + 4:dp + 4 + ln]; dp += 4 + ln
        if f is None: res["?%d" % tag] = d.hex(); continue
        res[f["name"]] = _dec_data(S, f, d)
    return res, dp

def _dec_data(S, f, d):
    ty = S.resolve(f["type"], f["owner"])
    if f["arr"]:
        if ty == "boolean": return [bool(x) for x in d]
        if ty in ("integer", "double"):
            if not d: return []
            sz = d[0]; body = d[1:]
            if ty == "double": return [struct.unpack("<d", body[k:k + 8])[0] for k in range(0, len(body), 8)]
            return [int.from_bytes(body[k:k + sz], "little", signed=True) for k in range(0, len(body), sz)]
        r = []; p = 0
        while p < len(d):
            ln = struct.unpack_from("<I", d, p)[0]; e = d[p + 4:p + 4 + ln]; p += 4 + ln
            r.append(e.decode("utf8", "replace") if ty == "string" else e.hex() if ty == "binary"
                     else dec_struct(S, S.types[ty], e)[0])
        return r
    if ty == "integer": return int.from_bytes(d, "little", signed=True)
    if ty == "double": return struct.unpack("<d", d)[0]
    if ty == "string": return d.decode("utf8", "replace")
    if ty == "binary": return d.hex()
    if ty == "boolean": return bool(d and d[0])
    return dec_struct(S, S.types[ty], d)[0]

# ---------------------------------------------------------------- XOR
def xor(data: bytes, key: bytes = XOR_KEY) -> bytes:
    return bytes(x ^ key[i % len(key)] for i, x in enumerate(data))

# ---------------------------------------------------------------- mensagens
def _wrap(S, header, body, key=None):
    """header dict (package) + body bytes -> frame empacotado. Se header.ud.crypt_method==1, body XOR."""
    if header.get("ud", {}).get("crypt_method") == 1 and key:
        body = xor(body, key)
    return pack(enc_struct(S, S.package, header, "package") + body)

def build_request(S, name, obj, session, key=None, crypt=False):
    n, p = name, S.c2s_by_name[name]
    body = enc_struct(S, S.fields_of(p["request"]), obj, n + ".request") if p["request"] else b""
    h = {"type": p["tag"], "session": session}
    if crypt:
        body_len = len(body); h["ud"] = {"crypt_method": 1, "crypt_length": body_len}
    return _wrap(S, h, body, key)

def build_response(S, name, obj, session, ud=None, key=None):
    p = S.c2s_by_name[name]
    body = enc_struct(S, S.fields_of(p["response"]), obj, name + ".response") if p["response"] else b""
    h = {"session": session}
    if ud: h["ud"] = ud
    return _wrap(S, h, body, key)

def build_push(S, name, obj, key=None, crypt=False):
    p = S.s2c_by_name[name]
    body = enc_struct(S, S.fields_of(p["request"]), obj, name + ".request") if p["request"] else b""
    h = {"type": p["tag"]}
    if crypt: h["ud"] = {"crypt_method": 1, "crypt_length": len(body)}
    return _wrap(S, h, body, key)

class Peer:
    """Decodifica frames de uma direção; casa sessão->protocolo (resp). side='server' recebe c2s; 'client' recebe s2c+resp."""
    def __init__(self, S, key=XOR_KEY): self.S = S; self.key = key; self.sess = {}
    def note_request(self, session, name): self.sess[session] = name
    def parse(self, raw, direction):
        S = self.S
        b = unpack(raw); h, n = dec_struct(S, S.package, b); body = b[n:]
        if h.get("ud", {}).get("crypt_method") == 1: body = xor(body, self.key)
        ty, se = h.get("type"), h.get("session")
        if direction == "C>S":
            name, p = S.c2s_by_tag[ty]; spec = p["request"]; kind = "req"; self.sess[se] = name
        elif ty is None and se in self.sess:
            name = self.sess[se]; spec = S.c2s_by_name[name]["response"]; kind = "resp"
        else:
            name, p = S.s2c_by_tag[ty]; spec = p["request"]; kind = "push"
        v, e = dec_struct(S, S.fields_of(spec), body) if spec else ({}, 0)
        return dict(hdr=h, kind=kind, name=name, obj=v, consumed=e, blen=len(body))

# framing TCP uint16 BE
def frame(body): return struct.pack(">H", len(body)) + body
