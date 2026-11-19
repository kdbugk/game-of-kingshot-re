#!/usr/bin/env python3
"""Rebuild metadata with EXACT boundaries from token chains (evidence-driven sizes)."""
import struct, sys

VER = sys.argv[1] if len(sys.argv) > 1 else "114"
dec = open(f"/tmp/meta_dec_{VER}.bin", "rb").read()
N = len(dec)

def chain_bounds(prefix, stride):
    """longest run of tokens incrementing by 1 at `stride`; returns (start_of_token1, count)"""
    best = (None, 0)
    lo, hi = 0x2b2708, 0x99b140
    hits = {}
    for off in range(lo, hi - 4, 4):
        v = struct.unpack_from("<I", dec, off)[0]
        if v >> 24 == prefix and 0 < (v & 0xFFFFFF) < 0x100000:
            hits[off] = v & 0xFFFFFF
    # para cada valor inicial plausível, segue a cadeia via dict de valor→offset
    byval = {}
    for off, val in hits.items():
        byval.setdefault(val, off)
    for val0, off0 in byval.items():
        if val0 > 8: continue
        n = 0
        v = val0
        while (v) in byval:
            n += 1; v += 1
        if n > best[1]:
            best = (off0, n)
    return best

# strides da evidência (Δoff dominante)
tables = [("methods", 0x06, 36), ("fields", 0x04, 12), ("params", 0x08, 12),
          ("properties", 0x17, None), ("events", 0x14, None)]
# descobre strides de properties/events/typeDefs pelos deltas dominantes
from collections import Counter
for name, prefix, stride in tables:
    if stride is None:
        hits = []
        for off in range(0x2b2708, 0x99b140-4, 4):
            v = struct.unpack_from("<I", dec, off)[0]
            if v >> 24 == prefix and (v & 0xFFFFFF) < 0x100000:
                hits.append((off, v & 0xFFFFFF))
        c = Counter()
        for i in range(len(hits)-1):
            do = hits[i+1][0]-hits[i][0]; dv = hits[i+1][1]-hits[i][1]
            if dv == 1: c[do] += 1
        stride = c.most_common(1)[0][0] if c else 12
        print(f"{name}: stride descoberto = {stride} ({dict(c.most_common(3))})")
        tables[tables.index((name, prefix, None))] = (name, prefix, stride)

bounds = {}
for name, prefix, stride in tables:
    off0, count = chain_bounds(prefix, stride)
    if off0 is None:
        print(f"{name}: cadeia não achada"); continue
    start = off0 - (stride - 4)  # token é o último u32
    end = off0 + count * stride
    bounds[name] = (start, end, count)
    print(f"{name}: 0x{start:x}..0x{end:x} ({count} entradas × {stride}B)")
bounds["parameters"] = bounds.pop("params")

# monta os pares finais na ordem v31
ORDER = ["stringLiteral", "stringLiteralData", "string", "events", "properties",
         "methods", "parameterDefaultValues", "fieldDefaultValues",
         "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters",
         "fields", "genericParameters", "genericParameterConstraints",
         "genericContainers", "nestedTypes", "interfaces", "vtableMethods",
         "interfaceOffsets", "typeDefinitions", "images", "assemblies", "fieldRefs"]

# conhecidos sólidos
sl_start, sl_end = 0x110, None
i = 0x110
ln0, di0 = struct.unpack_from("<II", dec, i)
prev = di0 + ln0; i += 8
while i + 8 <= N:
    ln, di = struct.unpack_from("<II", dec, i)
    if di != prev or ln > 0x200000: break
    prev = di + ln; i += 8
sl_end = i
sld_size = prev
a4 = lambda x: (x+3) & ~3
string_start = a4(a4(sl_end) + sld_size)  # após a SLD
string_end = string_start
# hmm: SLD é dados; string table vem depois do SLD
# ajusta: SL | SLD | string
string_end_real = None
# usa text-heuristic como antes, refinada: string começa após SLD
# (o valor de string_start calculado acima já pula o SLD)
def find_string_end(start):
    j = start
    last = start
    while j + 256 <= N:
        w = dec[j:j+256]
        npr = sum(1 for x in w if 32 <= x < 127)
        if npr > 200: last = j + 256
        elif npr < 100: break
        j += 256
    return a4(last)

string_end_real = find_string_end(string_start)
print(f"SL 0x{sl_start:x}..0x{sl_end:x} | SLD 0x{string_start - a4(sl_end) + a4(sl_end):x} size 0x{sld_size:x} | string 0x{string_start:x}..0x{string_end_real:x}")

sizes = {}
sizes["stringLiteral"] = (sl_end - sl_start)
sizes["stringLiteralData"] = string_start - a4(sl_end)
sizes["string"] = string_end_real - string_start
for name in ("events", "properties", "methods", "parameters", "fields"):
    if name in bounds:
        s, e, c = bounds[name]
        sizes[name] = e - s

# miolo restante por contiguidade entre fronteiras conhecidas
known_anchors = sorted((v[0], k) for k, v in bounds.items() if v)
print("âncoras ordenadas:", [(hex(a), k) for a, k in known_anchors])

# escreve o header final: pares desconhecidos = diferenças entre âncoras vizinhas
final_off = struct.unpack_from("<II", dec, 128)[0]
# monta offsets na ordem, preenchendo buracos com contiguidade
ORDER_POS = {k: i for i, k in enumerate(ORDER)}
anchor_by_pos = sorted((ORDER_POS[{"params": "parameters"}.get(k, k)], a, k) for a, k in known_anchors)
pairs = [None] * len(ORDER)
# seed: par[15] em di = conhecidos do arquivo
for k in range(15, len(ORDER)):
    o, s = struct.unpack_from("<II", dec, 128 + (k-15)*8)
    pairs[k] = (o, s)
# âncoras de token
for pos, a, k in anchor_by_pos:
    if k in sizes:
        pairs[pos] = (bounds[k][0], sizes[k])
# frente: SL/SLD/string
pairs[0] = (sl_start, sizes["stringLiteral"])
pairs[1] = (a4(sl_end), sizes["stringLiteralData"])
pairs[2] = (string_start, sizes["string"])
# buracos: preenche por contiguidade crescente
prev_end = 0x110
for i in range(len(ORDER)):
    if pairs[i] is None:
        # acha próxima âncora conhecida
        nxt = None
        for j in range(i+1, len(ORDER)):
            if pairs[j] is not None:
                nxt = pairs[j][0]; break
        if nxt is None: nxt = final_off
        # simples: buracos consecutivos a partir de i até a próxima âncora
        holes = []
        j = i
        while j < len(ORDER) and pairs[j] is None:
            holes.append(j); j += 1
        avail = nxt - prev_end
        each = a4(avail // len(holes))
        for idx, hj in enumerate(holes):
            sz = each if idx < len(holes) - 1 else nxt - prev_end
            pairs[hj] = (prev_end, sz)
            prev_end += sz
        continue
    prev_end = a4(pairs[i][0] + pairs[i][1])

print("\npares finais:")
for i, p in enumerate(pairs):
    print(f"  par[{i:2}] {ORDER[i]:36} (0x{p[0]:x}, 0x{p[1]:x})")

out = bytearray()
out += struct.pack("<II", 0xFAB11BAF, 31)
for p in pairs:
    out += struct.pack("<II", *p)
out += bytes(dec[0x110:])
path = f"/home/re/work/apk/global_metadata_{VER}_rebuilt2.dat"
open(path, "wb").write(bytes(out))
print(f"→ {path} ({len(out):,} bytes)")
