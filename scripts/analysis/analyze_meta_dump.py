#!/usr/bin/env python3
"""Analyze the dumped 24MB runtime metadata buffer: map tables, string heap extents,
and find anchors to rebuild an Il2CppMetadataHeader."""
import struct, re, sys

d = open("/home/re/work/apk/metadata_live_dump.bin", "rb").read()
print(f"size: {len(d):,} (0x{len(d):x})")

# 1) onde estão as strings conhecidas?
for pat in (b"mscorlib\x00", b"Assembly-CSharp\x00", b"UnityEngine\x00", b"NetSecProtect\x00"):
    idxs = [m.start() for m in re.finditer(re.escape(pat), d)]
    print(f"{pat!r:30} hits: {[hex(i) for i in idxs[:5]]}")

# 2) mapa de estrutura: para cada 64KB, características
print("\n── mapa 64KB (entropia|zeros|ascii-run) ──")
import math
from collections import Counter
def ent(b):
    if not b: return 0
    c = Counter(b); t = len(b)
    return -sum(v/t*math.log2(v/t) for v in c.values())
for off in range(0, len(d), 0x40000):
    chunk = d[off:off+0x40000]
    e = ent(chunk[:65536])
    z = chunk.count(0) / len(chunk)
    asciiish = sum(1 for b in chunk[:4096] if 32 <= b < 127 or b == 0) / min(4096, len(chunk))
    tag = ""
    if z > 0.95: tag = "ZEROS"
    elif z > 0.6: tag = "sparse"  # tables of pointers/ints
    elif asciiish > 0.95: tag = "STRINGS"
    print(f"  +0x{off:07x}: ent={e:.2f} z={z:.2f} asc={asciiish:.2f} {tag}")

# 3) procurar o fim do buffer útil (última região não-zero)
last_nonzero = len(d)
while last_nonzero > 0 and d[last_nonzero-1] == 0:
    last_nonzero -= 1
print(f"\núltimo byte não-zero: 0x{last_nonzero:x} ({last_nonzero/1048576:.1f} MB)")

# 4) o começo clobbered: até onde vai a sujeira? (primeira sequência longa de estrutura limpa)
# heurística: procurar onde começa algo parecido com tabela de strings contígua
m = re.search(rb"(?:[\x20-\x7e]\x00){8,}", d)  # UTF-16-ish? não — metadata usa utf8
print("utf16-run:", m and hex(m.start()))
