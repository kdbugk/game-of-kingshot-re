#!/usr/bin/env python3
"""INLINE-XREF: acha call sites no-PLT (ADRP+LDR+BLR) de imports-alvo em ELFs pequenos."""
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TERM = {"exit", "_exit", "abort", "kill", "pthread_kill", "raise", "tgkill"}

def parse(path):
    d = open(path, "rb").read()
    e_phoff, = struct.unpack_from("<Q", d, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
    LOADS, DYN_V = [], None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        t, fl = struct.unpack_from("<II", d, o)
        off, va, pa, fs, ms = struct.unpack_from("<QQQQQ", d, o + 8)
        if t == 1: LOADS.append((off, va, fs, ms, fl))
        if t == 2: DYN_V = va
    def v2f(v):
        for off, va, fs, ms, fl in LOADS:
            if va <= v < va + fs: return off + (v - va)
        return None
    if DYN_V is None:
        print(path, ": sem PT_DYNAMIC"); return
    dyn = {}
    o = v2f(DYN_V)
    while True:
        tag, val = struct.unpack_from("<qQ", d, o); o += 16
        if tag == 0: break
        dyn.setdefault(tag, val)
    SYMTAB, STRTAB = dyn[6], dyn[5]
    def symname(idx):
        so = v2f(SYMTAB)
        if so is None: return "?"
        so += idx * 24
        st_name, = struct.unpack_from("<I", d, so)
        stro = v2f(STRTAB)
        if stro is None: return "?"
        stro += st_name
        return d[stro:d.index(b"\0", stro)].decode("ascii", "replace")
    got_want = {}
    for base, sz in ((dyn.get(23, 0), dyn.get(2, 0)), (dyn.get(7, 0), dyn.get(8, 0))):
        bo = v2f(base)
        if bo is None: continue
        for i in range(sz // 24):
            ro = bo + i * 24
            r_off, r_info, r_add = struct.unpack_from("<QQq", d, ro)
            nm = symname(r_info >> 32)
            if nm in TERM: got_want[r_off] = nm
    if not got_want:
        print(path, ": nenhum GOT alvo"); return
    # scan ADRP+LDR(+ADD)+BLR em segmentos executáveis (flags & 1)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    sites = []
    for off, va, fs, ms, fl in LOADS:
        if not (fl & 1): continue
        code = d[off:off + fs]
        insns = list(md.disasm(code, va))
        for i, ins in enumerate(insns):
            if ins.mnemonic != "adrp": continue
            reg = ins.op_str.split(", ")[0]
            try: page = int(ins.op_str.split(", #")[1], 16)
            except: continue
            for k in range(1, 6):
                if i + k >= len(insns): break
                nx = insns[i + k]
                if nx.mnemonic == "ldr" and nx.op_str.startswith(reg + ", [" + reg):
                    try: imm = int(nx.op_str.split("#")[1].rstrip("]"), 16)
                    except: imm = 0
                    got = page + imm
                    nm = got_want.get(got)
                    if nm:
                        for j in range(k + 1, min(k + 6, len(insns))):
                            bl = insns[i + j]
                            if bl.mnemonic == "blr" and reg in bl.op_str:
                                sites.append((ins.address, got, nm))
                                break
                            if bl.mnemonic not in ("mov", "nop") and bl.address > insns[i + k].address + 4:
                                break
                elif nx.mnemonic == "add" and nx.op_str.startswith(reg + ", " + reg):
                    continue
                else:
                    break
    print(path)
    for a, g, n in sites: print("   %-14s got=%x  site=%x" % (n, g, a))
    if not sites: print("   (0 sites no-PLT encontrados)")

for p in sys.argv[1:]:
    try: parse(p)
    except Exception as e: print(p, "ERRO", e)
