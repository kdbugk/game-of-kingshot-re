#!/usr/bin/env python3
"""Offline parse of the runtime metadata buffer (header clobbered).
Finds: string table, images table (85 .dll entries), typeDefinitions, methods.
Emits il2cpp_dump-compatible JSONs."""
import struct, json, re, sys
from pathlib import Path

d = open("/home/re/work/apk/metadata_live_dump.bin", "rb").read()
N = len(d)
print(f"buffer: {N:,}")

# ── 1) string table: região de strings \0-terminated ──
# âncora: 'Assembly-CSharp' em 0xa0e0. Expandir para trás/frente enquanto parecer string heap.
def is_str_byte(b):
    return 32 <= b < 127 or b in (0,)

def string_run_bounds(anchor):
    # trás
    s = anchor
    while s > 0 and d[s-1] != 0 and is_str_byte(d[s-1]):
        s -= 1
    if s > 0: s -= 1  # incluir o \0 anterior
    # frente
    e = anchor
    while e < N:
        # para quando achar uma janela de 64 bytes não-string
        if all(is_str_byte(b) for b in d[e:e+64]) and any(b != 0 for b in d[e+1:e+64]):
            # avança até próximo \0
            while e < N and d[e] != 0:
                e += 1
            e += 1
        else:
            break
    return s, e

s_start, s_end = string_run_bounds(0xa0e0)
print(f"string table candidate: 0x{s_start:x}..0x{s_end:x} ({s_end-s_start:,} B)")
print("  first strings:", d[s_start:s_start+80])

def valid_str(off):
    return s_start <= off < s_end

# ── 2) scan por tabelas: u32 pares apontando pra string table ──
# varre 4-aligned, conta "valid u32 in [s_start, s_end)" density por região de 4KB
WIN = 0x1000
regions = []
for off in range(0x110, N - 4, 4):
    pass  # (varredura fina abaixo, otimizada)

# otimização: índice de posições onde u32 aponta pro string table
hits = []
for off in range(0x110, N - 4, 4):
    v = struct.unpack_from("<I", d, off)[0]
    if s_start <= v < s_end and (v - s_start) < 0x200000:
        hits.append(off)
print(f"u32-string-refs: {len(hits):,}")

# agrupa em clusters contíguos (gap < 64 bytes)
clusters = []
if hits:
    cs, ce = hits[0], hits[0]
    for h in hits[1:]:
        if h - ce <= 64:
            ce = h
        else:
            clusters.append((cs, ce)); cs, ce = h, h
    clusters.append((cs, ce))
print(f"clusters: {len(clusters)}")
for cs, ce in clusters[:30]:
    print(f"  0x{cs:x}..0x{ce:x} ({ce-cs:,} B)")
