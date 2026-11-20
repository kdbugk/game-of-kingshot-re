#!/usr/bin/env python3
"""Gerador de fixtures sinteticos para todas as req_* do schema c2s (offline).
Uso: python gen_fixtures.py [dir_protocols]   -> fixtures_all.json, failures.json, stats.json
Valida: build_request -> Peer.parse; so entra quem faz round-trip com valores identicos."""
import sys, os, json, re, random, collections
PROTO = sys.argv[1] if len(sys.argv) > 1 else r"C:/Users/prs/projects/game-of-kingshot-re/protocols"
os.environ["KS_PROTOCOLS"] = PROTO
sys.path.insert(0, PROTO)
import sproto_lib as L

MAXD = 3
TS = 1790000000
_CM=None
def comments(path=None):
    global _CM
    if _CM is None: _CM = _comments()
    return _CM
def _comments():
    """(owner_struct, campo) -> comentario (best effort)"""
    out = {}; cur = None
    for line in open(os.path.join(PROTO, "game_proto_c2s.sproto"), encoding="utf8"):
        m = re.match(r"\s*[.]?([\w]+)\s*(\d*)\s*\{", line)
        if m and not re.match(r"\s*\w+\s+\d+\s*:", line): cur = m.group(1)
        m = re.match(r"\s*(\w+)\s+\d+\s*:[^#]*#(.*)", line)
        if m and cur: out[(cur, m.group(1))] = m.group(2).strip()
    return out

def gen_int(name, cmt, rnd):
    n = name.lower(); c = cmt or ""
    if re.search(r"time|ts$|_at$|timestamp|expire|end$|start$", n) or "时间" in c: return TS + rnd.randint(0, 99999)
    if re.search(r"lev|level|grade|star", n) or "等级" in c: return rnd.randint(1, 30)
    if re.search(r"count|num|amount|cnt|total", n) or "数量" in c or "次数" in c: return rnd.randint(1, 99)
    if n in ("x", "y") or re.search(r"pos[xy]?$", n): return rnd.randint(1, 1199)
    if re.search(r"type|kind|idx|index|pos|slot|sort|page", n): return rnd.randint(1, 9)
    return rnd.randint(1000, 999999)

class Gen:
    def __init__(self, S, rnd):
        self.S = S; self.rnd = rnd; self.cm = comments(PROTO); self.notes = collections.Counter()
    def value(self, f, depth, ownername):
        S = self.S; ty = S.resolve(f["type"], f["owner"])
        cmt = self.cm.get((f["owner"].split(".")[-1], f["name"]))
        def one():
            if ty == "integer": return gen_int(f["name"], cmt, self.rnd)
            if ty == "boolean": return self.rnd.random() < 0.5
            if ty == "string": return "test"
            if ty == "double": return 1.5
            if ty == "binary": return "deadbeef"
            if depth >= MAXD: return None
            return self.struct(S.types[ty], depth + 1)
        if f["arr"]:
            vals = [one() for _ in range((1 if f['key'] is not None else self.rnd.randint(1, 2) if depth == 0 else 1))]
            if any(v is None for v in vals): return None
            if ty == "boolean": pass
            return vals
        return one()
    def struct(self, fields, depth):
        o = {}
        for f in fields:
            v = self.value(f, depth, None)
            if v is not None: o[f["name"]] = v
        return o

def main():
    S = L.default_schema(); P = L.Peer(S)
    ok = {}; fail = {}; stats = collections.Counter()
    for name, p in sorted(S.c2s_by_name.items()):
        rnd = random.Random(name)           # deterministico por mensagem
        g = Gen(S, rnd)
        fields = S.fields_of(p["request"]) if p["request"] else []
        try:
            obj = g.struct(fields, 0)
            raw = L.build_request(S, name, obj, 1)
            r = P.parse(L.unpack(raw) and raw, "C>S")
            if r["name"] != name: raise ValueError("nome decodificado %s" % r["name"])
            # unpack 0-pack pode deixar padding (<8B) e req vazio consome 0 -> so acusa sobra grande
            if r["blen"] - r["consumed"] >= 8: raise ValueError("bytes sobrando %d/%d" % (r["consumed"], r["blen"]))
            if r["obj"] != obj: raise ValueError("valores diferem: %s != %s" % (json.dumps(r["obj"])[:150], json.dumps(obj)[:150]))
            ok[name] = obj
            stats["vazio" if not obj else "com_campos"] += 1
        except Exception as e:
            fail[name] = "%s: %s" % (type(e).__name__, e)
    json.dump(ok, open("fixtures_all.json", "w"), indent=1, ensure_ascii=False)
    json.dump(fail, open("failures.json", "w"), indent=1, ensure_ascii=False)
    print("ok %d / %d ; vazios(sem campos) %d ; falhas %d" % (len(ok), len(S.c2s_by_name), stats["vazio"], len(fail)))
main()
