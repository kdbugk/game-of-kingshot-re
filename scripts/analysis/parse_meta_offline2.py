#!/usr/bin/env python3
"""Offline parse v2: robust string-heap bounds + table discovery."""
import struct, json, sys

d = open("/home/re/work/apk/metadata_live_dump.bin", "rb").read()
N = len(d)

ANCHOR = 0xa0e0  # dentro de 'Assembly-CSharp'

def printable_run(s, e):
    """string [s,e) é válida se toda printable e len<512"""
    if e <= s or e - s > 512: return False
    return all(32 <= d[i] < 127 for i in range(s, e))

# backward: 0xa0df é o 'A' (o \0 antes dele em 0xa0de)
s = ANCHOR - 1  # 'A'
while True:
    p = d.rfind(b"\0", 0, s)
    if p < 0: break
    if printable_run(p + 1, s):
        s = p
    else:
        break
# forward
e = ANCHOR
while True:
    q = d.find(b"\0", e)
    if q < 0 or q > N: break
    nxt = q + 1
    # próxima string começa em nxt; checar se ela é válida (para decidir continuar)
    q2 = d.find(b"\0", nxt)
    if q2 < 0 or q2 - nxt > 512 or not all(32 <= d[i] < 127 for i in range(nxt, min(q2, nxt + 512))):
        e = q + 1
        break
    e = q + 1
s_start, s_end = s, e
print(f"string table: 0x{s_start:x}..0x{s_end:x} ({s_end - s_start:,} B)")
print("first:", d[s_start:s_start + 60])
print("last :", d[s_end - 60:s_end])

# índice de u32s apontando para dentro do heap
def str_off_ok(v):
    return s_start <= v < s_end

hits = []
for off in range(0x110, N - 4, 4):
    v = struct.unpack_from("<I", d, off)[0]
    if str_off_ok(v):
        hits.append((off, v))
print(f"\nu32 refs ao heap: {len(hits):,}")

clusters = []
if hits:
    cs, ce = hits[0][0], hits[0][0]
    for h, _ in hits[1:]:
        if h - ce <= 0x40:
            ce = h
        else:
            clusters.append((cs, ce)); cs, ce = h, h
    clusters.append((cs, ce))

print(f"clusters: {len(clusters)}")
big = [(cs, ce) for cs, ce in clusters if ce - cs > 0x400]
for cs, ce in big:
    # amostra: primeiros 8 bytes de cada cluster
    print(f"  0x{cs:07x}..0x{ce:07x} ({ce-cs:7,} B)  head={d[cs:cs+16].hex()}")
