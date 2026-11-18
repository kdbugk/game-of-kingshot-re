#!/usr/bin/env python3
"""Derive 1.9.5 unpacker constants: init_array ctors from its RELA, CRYPT via fuzzy sig."""
import struct

P195 = "/home/re/work/apk/xapk195/native_extract/lib/arm64-v8a/libil2cpp.so"
P114 = "/home/re/work/apk/xapk/native_extract/lib/arm64-v8a/libil2cpp.so"

def parse(path):
    d = open(path, "rb").read()
    e_phoff, = struct.unpack_from("<Q", d, 0x20)
    e_phnum, = struct.unpack_from("<H", d, 0x38)
    LOADS, DYN = [], None
    for i in range(e_phnum):
        o = e_phoff + i * 56
        t, fl = struct.unpack_from("<II", d, o)
        off, va, pa, fs, ms = struct.unpack_from("<QQQQQ", d, o + 8)
        if t == 1: LOADS.append((off, va, fs, ms))
        if t == 2: DYN = (off, va)
    dyn = {}
    o = DYN[0]
    while True:
        tag, val = struct.unpack_from("<qQ", d, o); o += 16
        if tag == 0: break
        dyn.setdefault(tag, val)
    def v2f(v):
        for off, va, fs, ms in LOADS:
            if va <= v < va + fs: return off + (v - va)
        return None
    return d, LOADS, dyn, v2f

d95, L95, dyn95, v2f95 = parse(P195)
d14, L14, dyn14, v2f14 = parse(P114)
print("195 LOADS:", [(hex(o), hex(v), hex(f)) for o, v, f, m in L95])
print("195 dyn: RELA=%#x sz=%d INIT_ARRAY=%#x sz=%d" % (dyn95[7], dyn95[8], dyn95[25], dyn95[27]))

# ctors from RELA
ctors = []
RELA_V, RELA_SZ, INIT_V, INIT_SZ = dyn95[7], dyn95[8], dyn95[25], dyn95[27]
for i in range(RELA_SZ // 24):
    off = v2f95(RELA_V) + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d95, off)
    if INIT_V <= r_offset < INIT_V + INIT_SZ:
        ctors.append(r_addend)
print("195 ctors:", [hex(c) for c in ctors])

# CRYPT sig: first 48 bytes of 1.14.27's FUN_04949e48 (vaddr 0x4849e48)
CRYPT14 = 0x4849e48
sig = d14[v2f14(CRYPT14): v2f14(CRYPT14) + 48]
# find in 195 .note.gnu.text (vaddr base)
t95_start, t95_va = 0x3db0040, 0x4490040
t95 = d95[t95_start:t95_start + 0xb4360]
# fuzzy: require 75% byte match per 48-byte window
best = None
for i in range(0, len(t95) - 48, 4):
    win = t95[i:i + 48]
    m = sum(1 for a, b in zip(win, sig) if a == b)
    if m >= 40:
        best = (t95_va + i, m)
        break
print("195 CRYPT candidate:", best and (hex(best[0]), best[1], "/48 match"))
