#!/usr/bin/env python3
"""Derive libnesec packer constants (ctors from RELA, CRYPT by signature vs libunity's)."""
import struct

N = "/home/re/work/apk/xapk/native_extract/lib/arm64-v8a/libnesec.so"
U = "/home/re/work/apk/xapk/native_extract/lib/arm64-v8a/libunity.so"
dn = open(N, "rb").read()
du = open(U, "rb").read()

def parse(d):
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
    return LOADS, dyn

Ln, dnn = parse(dn)
Lu, dun = parse(du)
print("nesec LOADS:", [(hex(o), hex(v), hex(f)) for o, v, f, m in Ln])
print("nesec RELA=%#x sz=%d INIT_ARRAY=%#x sz=%d" % (dnn[7], dnn[8], dnn[25], dnn[27]))
print("unity  RELA=%#x sz=%d INIT_ARRAY=%#x sz=%d" % (dun[7], dun[8], dun[25], dun[27]))

def v2f(LOADS, v):
    for off, va, fs, ms in LOADS:
        if va <= v < va + fs: return off + (v - va)

# ctors do nesec pela RELA própria
ctors = []
off = v2f(Ln, dnn[7])
for i in range(dnn[8] // 24):
    o = off + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", dn, o)
    if dnn[25] <= r_offset < dnn[25] + dnn[27]:
        ctors.append(r_addend)
print("nesec ctors:", [hex(c) for c in ctors])

# CRYPT do nesec por assinatura: pega os primeiros 48B da CRYPT conhecida do libunity
# unity: CRYPT vaddr? usa derive_195-style: assinatura do FUN que processa payload
# procura seção executável de baixa entropia (stub) do nesec e usa fuzzy
# atalho: o stub é ~idêntico entre libs → achar pela assinatura do prólogo do CRYPT do unity
# unity CRYPT está em unpack_unity outputs? usa emu_unpack_unity.py p/ achar constante:
import re
src = open("/mnt/c/Users/prs/work/emu_unpack_unity.py").read()
m = re.search(r"CRYPT\s*=\s*(0x[0-9a-fA-F]+)", src)
print("unity CRYPT const:", m and m.group(1))
UC = int(m.group(1), 16) if m else None
if UC:
    # file offset no unity packed
    uo = v2f(Lu, UC)
    sig = du[uo:uo + 48]
    # procura no stub do nesec (varre seções de código < ent 6)
    best = None
    for off in range(0, min(len(dn), 0x1000000), 4):
        win = dn[off:off + 48]
        if sum(1 for a, b in zip(win, sig) if a == b) >= 40:
            va = None
            for fo, va_, fs, ms in Ln:
                if fo <= off < fo + fs: va = va_ + (off - fo)
            best = (off, va); break
    print("nesec CRYPT candidate:", best and (hex(best[0]), hex(best[1] or 0)))
