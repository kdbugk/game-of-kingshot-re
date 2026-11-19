#!/usr/bin/env python3
"""v24 header rebuild — 33 tables, correct order, token-anchored + file pairs."""
import struct, sys

VER = sys.argv[1] if len(sys.argv) > 1 else "114"
dec = open(f"/tmp/meta_dec_{VER}.bin", "rb").read()
N = len(dec)
a4 = lambda x: (x + 3) & ~3

string_start, string_size = 0xcda08, 0x28de00
# anchors (validados por token-runs)
ANCH = {"events": 0x35b8cc, "properties": 0x35d57c, "methods": 0x393dcc,
        "parameters": 0x780ff0, "fields": 0x8b8fa0}
SZ = {"events": 24, "properties": 20, "methods": 36, "parameters": 12, "fields": 12}
# counts pela extensão dos token-runs
CNT = {"events": 57, "properties": 2474, "methods": 38860, "parameters": 44430, "fields": 38637}

ORDER = ["stringLiteral", "stringLiteralData", "string", "events", "properties",
         "methods", "parameterDefaultValues", "fieldDefaultValues",
         "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters",
         "fields", "genericParameters", "genericParameterConstraints",
         "genericContainers", "nestedTypes", "interfaces", "vtableMethods",
         "interfaceOffsets", "typeDefinitions", "images", "assemblies", "fieldRefs",
         "referencedAssemblies", "attributeData", "attributeDataRange",
         "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
         "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions",
         "metadataUsageLists", "metadataUsagePairs"]
assert len(ORDER) == 33

# stringLiteral + data
i = 0x110
ln0, di0 = struct.unpack_from("<II", dec, i)
prev = di0 + ln0; i += 8
while i + 8 <= N:
    ln, di = struct.unpack_from("<II", dec, i)
    if di != prev or ln > 0x200000: break
    prev = di + ln; i += 8
sl_end = i; sld_size = prev
sld_start = a4(sl_end)
string_start = a4(sld_start + sld_size)
# string end: heuristic
def find_string_end(start):
    j, last = start, start
    while j + 256 <= N:
        npr = sum(1 for x in dec[j:j+256] if 32 <= x < 127)
        if npr > 200: last = j + 256
        elif npr < 100: break
        j += 256
    return a4(last)
string_end = find_string_end(string_start)

pairs = [None] * 33
# seed: pares do ARQUIVO para as posições 15..32 (o header real está lá!)
for k in range(15, 33):
    o, s = struct.unpack_from("<II", dec, 128 + (k - 15) * 8)
    pairs[k] = (o, s)
# frente
pairs[0] = (0x110, sl_end - 0x110)
pairs[1] = (sld_start, string_start - sld_start)
pairs[2] = (string_start, string_end - string_start)
# âncoras por token
for name, addr in ANCH.items():
    pos = ORDER.index(name)
    pairs[pos] = (addr, CNT[name] * SZ[name])

# buracos: 6..9, 12..14 — preencher por contiguidade respeitando âncoras
prev_end = 0x110
for i in range(33):
    if pairs[i] is not None:
        # garante contiguidade: se buracos anteriores faltam tamanho, ajusta
        prev_end = a4(pairs[i][0] + pairs[i][1]) if pairs[i][0] >= prev_end else prev_end
        continue
    nxt = None
    for j in range(i + 1, 33):
        if pairs[j] is not None:
            nxt = pairs[j][0]; break
    if nxt is None:
        nxt = pairs[32][0] + pairs[32][1] if pairs[32] else N
    holes = []
    j = i
    while j < 33 and pairs[j] is None:
        holes.append(j); j += 1
    avail = nxt - prev_end
    each = a4(avail // len(holes))
    for hidx, hj in enumerate(holes):
        sz = each if hidx < len(holes) - 1 else max(4, nxt - prev_end)
        pairs[hj] = (prev_end, sz)
        prev_end += sz

# sanity check: par15 (nestedTypes) deve casar com o valor do arquivo!
chk = struct.unpack_from("<II", dec, 128)
if pairs[15] != chk:
    print(f"[!] par15 divergente: montado {hex(pairs[15][0])} vs arquivo {hex(chk[0])}")
    # força alinhamento total aos pares do arquivo p/ 15..32 já seedados

out = bytearray()
out += struct.pack("<II", 0xFAB11BAF, 24)  # v24!
for p in pairs:
    out += struct.pack("<II", *p)
out += bytes(dec[0x110:])
path = f"/home/re/work/apk/global_metadata_{VER}_v24.dat"
open(path, "wb").write(bytes(out))
print(f"→ {path} ({len(out):,})")
for i, p in enumerate(pairs):
    print(f"  par[{i:2}] {ORDER[i]:38} (0x{p[0]:x}, 0x{p[1]:x})")
