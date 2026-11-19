#!/usr/bin/env python3
"""TERMO-MAP: cataloga call sites de exit/_exit/abort/kill/pthread_kill/raise/tgkill
em ELF (via dynsym→GOT→PLT→BL) e raw image (via wrappers svc)."""
import struct, sys, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TERM_SYMS = {"exit", "_exit", "abort", "kill", "pthread_kill", "raise", "tgkill", "exit_group"}

def scan_elf(path):
    d = open(path, "rb").read()
    e_phoff, = struct.unpack_from("<Q", d, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
    LOADS, DYN_V = [], None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        t, fl = struct.unpack_from("<II", d, o)
        off, va, pa, fs, ms = struct.unpack_from("<QQQQQ", d, o + 8)
        if t == 1: LOADS.append((off, va, fs, ms))
        if t == 2: DYN_V = va
    def v2f(v):
        for off, va, fs, ms in LOADS:
            if va <= v < va + fs: return off + (v - va)
        return None
    if DYN_V is None or v2f(DYN_V) is None:
        print(f"{path}: sem PT_DYNAMIC utilizável (imagem reconstruída?) — scan bruto de svc");
        scan_raw(path); return
    dyn = {}
    o = v2f(DYN_V)
    while True:
        tag, val = struct.unpack_from("<qQ", d, o); o += 16
        if tag == 0: break
        dyn.setdefault(tag, val)
    SYMTAB, STRTAB, JMPREL, JMPREL_SZ, RELA, RELASZ = dyn[6], dyn[5], dyn.get(23, 0), dyn.get(2, 0), dyn.get(7, 0), dyn.get(8, 0)
    def symname(idx):
        so = v2f(SYMTAB) + idx * 24
        st_name, = struct.unpack_from("<I", d, so)
        stro = v2f(STRTAB) + st_name
        return d[stro:d.index(b"\0", stro)].decode("ascii", "replace")
    # GOT slots for terminal symbols
    term_got = {}
    for base, sz in ((JMPREL, JMPREL_SZ), (RELA, RELASZ)):
        for i in range(sz // 24):
            ro = v2f(base) if v2f(base) is not None else None
            if ro is None: continue
            ro = v2f(base) + i * 24
            r_off, r_info, r_add = struct.unpack_from("<QQq", d, ro)
            nmu = v2f(SYMTAB)
            if nmu is None or v2f(STRTAB) is None: continue
            nm = symname(r_info >> 32)
            if nm in TERM_SYMS:
                term_got.setdefault(r_off, set()).add(nm)
    if not term_got:
        print(f"{path}: nenhum GOT de terminacao"); return
    # find PLT stubs: scan executable segment for adrp x16,+ldr x17,[x16,#imm]+br
    plt_stubs = {}  # got -> stub addr
    for off, va, fs, ms in LOADS:
        seg = d[off:off + fs]
        for i in range(0, len(seg) - 12, 4):
            w1 = struct.unpack_from("<I", seg, i)[0]
            if (w1 & 0x9F000000) != 0x90000000: continue
            rd = w1 & 0x1F
            if rd != 16: continue
            immlo = (w1 >> 29) & 3; immhi = (w1 >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & 0x100000: imm -= 0x200000
            pc = va + i
            page = (pc & ~0xFFF) + (imm << 12)
            w2 = struct.unpack_from("<I", seg, i + 4)[0]
            # ldr x17,[x16,#imm12] (64-bit LDR unsigned): 1111 1001 01 imm12 x16 x17
            if (w2 & 0xFFC00000) != 0xF9400000: continue
            imm12 = (w2 >> 10) & 0xFFF
            got = page + imm12
            w3 = struct.unpack_from("<I", seg, i + 8)[0]
            w4 = struct.unpack_from("<I", seg, i + 12)[0] if i + 16 <= len(seg) else 0
            if (w3 & 0xFFFFFC1F) == 0xD61F0200 or (w4 & 0xFFFFFC1F) == 0xD61F0200:  # br x17 (com/sem add)
                plt_stubs.setdefault(got, pc)
    stubs = {plt_stubs[g]: nms for g, nms in term_got.items() if g in plt_stubs}
    # direct GOT loads too (adrp+ldr x?,[x?,#imm] targeting term GOT, then blr)
    # scan BL to stubs
    callers = {}
    for off, va, fs, ms in LOADS:
        seg = d[off:off + fs]
        for i in range(0, len(seg) - 4, 4):
            w = struct.unpack_from("<I", seg, i)[0]
            if (w & 0xFC000000) != 0x94000000: continue
            disp = w & 0x3FFFFFF
            if disp & 0x2000000: disp -= 0x4000000
            tgt = va + i + disp * 4
            if tgt in stubs:
                callers.setdefault(tgt, []).append(va + i)
    print(f"== {path}")
    for stub, nms in stubs.items():
        cs_ = callers.get(stub, [])
        print(f"  {sorted(nms)} PLT@{stub:#x}: {len(cs_)} BL callers {' '.join(hex(c) for c in cs_[:16])}")

def scan_raw(path, code_start=0, delta=0):
    d = open(path, "rb").read()
    wrappers = {}
    for i in range(0, len(d) - 8, 4):
        w = struct.unpack_from("<I", d, i)[0]
        w2 = struct.unpack_from("<I", d, i + 4)[0]
        if (w & 0xFFE0001F) == 0xD2800008 and w2 == 0xD4000001:
            nr = (w >> 5) & 0xFFFF
            if nr in (93, 94, 129, 131, 62):
                wrappers[i + delta] = nr
    callers = {}
    for i in range(0, len(d) - 4, 4):
        w = struct.unpack_from("<I", d, i)[0]
        if (w & 0xFC000000) != 0x94000000: continue
        disp = w & 0x3FFFFFF
        if disp & 0x2000000: disp -= 0x4000000
        tgt = i + delta + disp * 4
        if tgt in wrappers:
            callers.setdefault(wrappers[tgt], []).append(i + delta)
    print(f"== {path} (raw)")
    for nr in (93, 94, 129, 131, 62):
        if nr in {v for v in wrappers.values()}:
            ws = [hex(a) for a, n in wrappers.items() if n == nr]
            print(f"  syscall {nr}: wrappers {ws}; callers {callers.get(nr, [])[:16]}")

if __name__ == "__main__":
    for p in sys.argv[1:]:
        try:
            if open(p, "rb").read(4) == b"\x7fELF": scan_elf(p)
            else: scan_raw(p)
        except Exception as e:
            print(f"== {p}: ERRO {e}")
