#!/usr/bin/env python3
"""Unicorn emulator for the libnesec.so packer variant (Kingshot 1.14.27).

Maps the packed ELF, applies RELATIVE relocations, stubs imports (incl. a
working sscanf for the /proc/self/maps parser), runs the 4 .init_array
constructors, and dumps the decrypted image.

Addresses are file vaddrs (image mapped at 0)."""
import struct, sys
from unicorn import *
from unicorn.arm64_const import *

PATH = "/mnt/c/Users/prs/work/nes-unpack/libnesec.so"
OUT  = "/mnt/c/Users/prs/work/nes-unpack/nesec_image.bin"

STACK = 0x7f0000000000
STACK_SZ = 8 * 1024 * 1024
TLS    = 0x7e0000000000
HEAP   = 0x700000000000
HEAP_SZ = 512 * 1024 * 1024
TRAMP  = 0x6f0000000000
STOP   = 0x600000000000

d = open(PATH, "rb").read()
log = []

e_phoff, = struct.unpack_from("<Q", d, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
LOADS, DYN_V = [], None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", d, o)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", d, o + 8)
    if p_type == 1: LOADS.append((p_offset, p_vaddr, p_filesz, p_memsz))
    if p_type == 2: DYN_V = p_vaddr
def v2f(v):
    for off, va, fsz, msz in LOADS:
        if va <= v < va + fsz: return off + (v - va)
    raise ValueError(hex(v))

dyn = {}
o = v2f(DYN_V)
while True:
    tag, val = struct.unpack_from("<qQ", d, o); o += 16
    if tag == 0: break
    dyn.setdefault(tag, val)
RELA_V, RELA_SZ = dyn[7], dyn[8]
JMPREL_V, JMPREL_SZ = dyn[23], dyn[2]
INIT_ARRAY, INIT_ARRAY_SZ = dyn[25], dyn[26]
SYMTAB, STRTAB = dyn[6], dyn[5]
log.append("[DYN] RELA=0x%x/+0x%x JMPREL=0x%x/+0x%x INIT_ARRAY=0x%x/+0x%x" %
           (RELA_V, RELA_SZ, JMPREL_V, JMPREL_SZ, INIT_ARRAY, INIT_ARRAY_SZ))

def symname(idx):
    so = v2f(SYMTAB) + idx * 24
    st_name, = struct.unpack_from("<I", d, so)
    stro = v2f(STRTAB) + st_name
    return d[stro:d.index(b"\0", stro)].decode("ascii", "replace")

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
for off, va, fsz, msz in LOADS:
    PAGE = 0x1000
    start = va & ~0xFFF; end = (va + msz + PAGE - 1) & ~0xFFF
    uc.mem_map(start, end - start, UC_PROT_ALL)
    uc.mem_write(va, d[off:off + fsz])
uc.mem_map(STACK, STACK_SZ, UC_PROT_ALL)
uc.mem_map(TLS, 0x10000, UC_PROT_ALL)
uc.mem_map(HEAP, HEAP_SZ, UC_PROT_ALL)
uc.mem_map(TRAMP, 0x10000, UC_PROT_ALL)
uc.mem_map(STOP & ~0xFFF, 0x1000, UC_PROT_ALL)
uc.mem_write(TLS + 0x28, struct.pack("<Q", 0xDEADBEEFCAFEBABE))
uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SZ - 0x10000)

heap_ptr = HEAP
def halloc(n):
    global heap_ptr
    n = max((n + 0xFFF) & ~0xFFF, 0x1000)
    p = heap_ptr; heap_ptr += n
    return p

FAKE_MAPS = (
    "000000000000-00000110000 r-xp 00000000 00:00 0                              /data/app/com.run.tower.defense/libnesec.so\n"
    "700000000000-70020000000 rw-p 00000000 00:00 0                              [heap]\n"
    "7f0000000000-7f0000800000 rw-p 00000000 00:00 0                              [stack]\n"
)

import_got = {}
imports = []
for i in range(JMPREL_SZ // 24):
    ro = v2f(JMPREL_V) + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, ro)
    imports.append((r_offset, symname(r_info >> 32)))
for i in range(RELA_SZ // 24):
    ro = v2f(RELA_V) + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, ro)
    rt = r_info & 0xFFFFFFFF
    if rt in (1025, 1026):
        imports.append((r_offset, symname(r_info >> 32)))
taken = {}
for i, (got, name) in enumerate(imports):
    if got in taken: continue
    taken[got] = name
    tramp = TRAMP + 0x10 * i
    import_got[tramp] = name
    uc.mem_write(got, struct.pack("<Q", tramp))
log.append("[SETUP] imports: " + ", ".join(sorted(set(import_got.values()))))

rel_count = 0
for i in range(RELA_SZ // 24):
    ro = v2f(RELA_V) + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, ro)
    if r_info & 0xFFFFFFFF == 1027:
        uc.mem_write(r_offset, struct.pack("<Q", r_addend)); rel_count += 1
log.append("[SETUP] %d RELATIVE relocs applied" % rel_count)

# read init_array AFTER relocs
ctors = list(struct.unpack("<4Q", bytes(uc.mem_read(INIT_ARRAY, 0x20))))
log.append("[CTOR LIST] " + ", ".join(hex(c) for c in ctors))

# ── sscanf impl for the maps formats ──────────────────────
def do_sscanf(uc, inp, fmt, args):
    # supports %lx %4s %*x %*d %n and literal chars incl ':'
    i = j = 0; assigned = 0; n_off = None
    inp = bytes(uc.mem_read(inp, 0x400)); inp = inp[:inp.index(b"\0")] if b"\0" in inp else inp
    fmt = bytes(uc.mem_read(fmt, 0x100)); fmt = fmt[:fmt.index(b"\0")] if b"\0" in fmt else fmt
    args = [uc.reg_read(UC_ARM64_REG_X2 + k) for k in range(6)]
    ai = 0
    while j < len(fmt):
        c = fmt[j]
        if c == 0x20:
            while i < len(inp) and inp[i:i+1] == b" ": i += 1
            j += 1; continue
        if c != ord('%'):
            if i < len(inp) and inp[i] == c: i += 1; j += 1; continue
            return assigned
        j += 1
        star = fmt[j:j+1] == b'*'
        if star: j += 1
        width = 0
        while fmt[j:j+1].isdigit(): width = width*10 + int(fmt[j:j+1]); j += 1
        conv = fmt[j:j+1]; j += 1
        if conv == b'n':
            if not star:
                uc.mem_write(args[ai], struct.pack("<I", i)); ai += 1
            continue
        while i < len(inp) and inp[i:i+1] == b" ": i += 1
        if conv == b'x':
            start = i
            while i < len(inp) and chr(inp[i]) in "0123456789abcdefABCDEF": i += 1
            if start == i: return assigned
            v = int(inp[start:i], 16)
            if not star:
                uc.mem_write(args[ai], struct.pack("<Q", v)); ai += 1; assigned += 1
        elif conv == b'd':
            start = i
            while i < len(inp) and (chr(inp[i]) in "-0123456789"): i += 1
            if start == i: return assigned
            if not star:
                uc.mem_write(args[ai], struct.pack("<I", int(inp[start:i]))); ai += 1; assigned += 1
        elif conv == b's':
            start = i
            while i < len(inp) and inp[i:i+1] not in (b" ", b"\n", b"\0"):
                if width and i - start >= width: break
                i += 1
            if start == i: return assigned
            if not star:
                uc.mem_write(args[ai], inp[start:i] + b"\0"); ai += 1; assigned += 1
        else:
            return assigned
    return assigned

def impl(name, uc, virt):
    x0 = uc.reg_read(UC_ARM64_REG_X0); x1 = uc.reg_read(UC_ARM64_REG_X1)
    x2 = uc.reg_read(UC_ARM64_REG_X2); x3 = uc.reg_read(UC_ARM64_REG_X3)
    if name in ("malloc", "calloc"): return halloc(x0 if name == "malloc" else x0 * x1)
    if name == "free": return 0
    if name == "memset":
        uc.mem_write(x0, bytes([x1 & 0xFF]) * x2); return x0
    if name in ("memcpy", "__memcpy_chk", "memmove", "strncpy"):
        uc.mem_write(x0, bytes(uc.mem_read(x1, x2))); return x0
    if name in ("strlen", "__strlen_chk"):
        b = uc.mem_read(x0, 0x10000); return b.index(b"\0")
    if name == "strcmp" or name == "strncmp":
        a = bytes(uc.mem_read(x0, 64)); b = bytes(uc.mem_read(x1, 64))
        n = x2 if name == "strncmp" else min(a.index(b"\0") if b"\0" in a else 64, b.index(b"\0") if b"\0" in b else 64)
        return int(a[:n] != b[:n])
    if name == "memcmp":
        return int(bytes(uc.mem_read(x0, x2)) != bytes(uc.mem_read(x1, x2)))
    if name == "mmap":
        sz = (x1 + 0xFFF) & ~0xFFF
        p = halloc(max(sz, 0x1000))
        log.append("[mmap] 0x%x -> 0x%x prot=%d" % (x1, p, x2))
        return p
    if name in ("mprotect", "munmap", "close", "fflush", "fputc", "fseek", "ferror", "fclose", "fdopen"):
        return 0
    if name == "sysconf": return 0x1000
    if name == "__errno": return TLS + 0x2000
    if name == "getenv": return 0
    if name in ("dlopen", "__loader_dlopen"):
        fn = bytes(uc.mem_read(x0, 64)); fn = fn[:fn.index(b"\0")] if b"\0" in fn else fn
        log.append("[dlopen] %r -> fake handle" % fn)
        globals()['_dlhandle'] = 1
        return 0x6e0000000100
    if name == "dlsym":
        nm = bytes(uc.mem_read(x1, 64)); nm = nm[:nm.index(b"\0")] if b"\0" in nm else nm
        for t, n in import_got.items():
            if n == nm.decode("ascii", "replace"):
                log.append("[dlsym] %s -> tramp 0x%x" % (nm, t))
                return t
        log.append("[dlsym] %s -> CATCHALL" % nm)
        return TRAMP + 0xfff0
    if name == "dlclose": return 0
    if name in ("open", "openat"):
        log.append("[open] " + repr(bytes(uc.mem_read(x0 if name=="open" else x1, 32))))
        return 7
    if name == "read": return 0
    if name == "lseek": return 0
    if name == "fopen":
        fn = bytes(uc.mem_read(x0, 64)); fn = fn[:fn.index(b"\0")]
        if b"maps" in fn:
            fp = halloc(0x100)
            globals()["_maps_fp"] = fp; globals()["_maps_pos"] = 0
            return fp
        log.append("[fopen] unsupported " + repr(fn)); return 0
    if name == "fgets":
        fp = x2
        if fp == globals().get("_maps_fp", -1):
            data = FAKE_MAPS.encode(); pos = globals().get("_maps_pos", 0)
            if pos >= len(data): return 0
            nl = data.index(b"\n", pos) + 1
            chunk = data[pos:nl]
            uc.mem_write(x0, chunk + b"\0")
            globals()["_maps_pos"] = nl
            return x0
        return 0
    if name in ("sscanf", "__isoc99_sscanf"):
        return do_sscanf(uc, x0, x1, None)
    if name in ("pthread_create",):
        log.append("[pthread_create] STUBBED-OK")
        return 0
    if name in ("abort", "__stack_chk_fail"):
        raise RuntimeError("stub abort/__stack_chk_fail called: " + name)
    log.append("[stub] unhandled %s(x0=%x)" % (name, x0))
    return 0

interesting = {0xed534: "ctor1-maps-check", 0xed5e4: "ctor2-ctx", 0xedd38: "ctor3-gate",
               0xee000: "CRYPT-byte-xor", 0xedff8: "CRYPT2-byte-xor",
               0x1f16e8: "stage-crypt-rolling", 0x1f33c8: "ctx-factory",
               0x1ee578: "self-locate", 0x1f314c: "reloc-apply", 0x1fb300: "pre-init?"}

SVC_NAMES = {56:"openat",57:"close",63:"read",64:"write",78:"readlinkat",113:"clock_gettime",
             134:"rt_sigaction",135:"rt_sigprocmask",160:"uname",215:"munmap",222:"mmap",
             226:"mprotect",214:"brk",29:"ioctl",169:"gettimeofday",172:"getpid",
             174:"getuid",175:"geteuid",176:"getgid",177:"getegid",99:"setxattr?"}

def hook_intr(uc, intno, user_data):
    if intno != 2:
        return
    nr = uc.reg_read(UC_ARM64_REG_X8)
    x0 = uc.reg_read(UC_ARM64_REG_X0); x1 = uc.reg_read(UC_ARM64_REG_X1)
    x2 = uc.reg_read(UC_ARM64_REG_X2); x3 = uc.reg_read(UC_ARM64_REG_X3)
    rv = 0
    if nr == 226:  # mprotect — keep RWX always (emulation)
        rv = 0
    elif nr == 222:  # mmap
        sz = (x1 + 0xFFF) & ~0xFFF
        rv = halloc(max(sz, 0x1000))
        log.append("[svc mmap] 0x%x -> 0x%x prot=%d" % (x1, rv, x2))
    elif nr == 56:  # openat
        try:
            fn = bytes(uc.mem_read(x1, 64)); fn = fn[:fn.index(b"\0")]
        except Exception:
            fn = b"?"
        log.append("[svc openat] %r fd=10" % fn)
        rv = 10
    elif nr == 78:  # readlinkat
        try:
            p = b"/data/app/com.run.tower.defense/libnesec.so\0"
            uc.mem_write(x2, p[:x3 - 1] + b"\0")
            rv = len(p) - 1
        except Exception:
            rv = 0
    elif nr == 160:  # uname
        uc.mem_write(x0, b"Linux\0" + b"\0" * 60)
        rv = 0
    elif nr in (113, 169):  # clock_gettime/gettimeofday
        uc.mem_write(x1 if nr == 113 else x0, struct.pack("<QQ", 0x1000, 0))
        rv = 0
    elif nr == 63:  # read
        rv = 0
    elif nr in (134, 135, 29, 99, 57, 64, 215, 214):
        rv = 0
    else:
        nm = SVC_NAMES.get(nr, "?")
        log.append("[svc %d/%s] x0=%x x1=%x -> 0" % (nr, nm, x0, x1))
        rv = 0
    uc.reg_write(UC_ARM64_REG_X0, rv & 0xFFFFFFFFFFFFFFFF)
    pc = uc.reg_read(UC_ARM64_REG_PC)
    insn = struct.unpack("<I", bytes(uc.mem_read(pc, 4)))[0] if pc else 0
    if insn & 0xFFE0001F == 0xD4000001:  # svc #0 at pc -> skip
        uc.reg_write(UC_ARM64_REG_PC, pc + 4)

uc.hook_add(UC_HOOK_INTR, hook_intr)

def hook_code(uc, address, size, user_data):
    if address in import_got:
        name = import_got[address]
        rv = impl(name, uc, address)
        uc.reg_write(UC_ARM64_REG_X0, rv & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
    elif address == TRAMP + 0xfff0:
        log.append("[CATCHALL] x0=%x x1=%x lr_ret" % (uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1)))
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
    elif address in interesting:
        log.append("[>> %s] x0=%x x1=%x x2=%x x3=%x" % (interesting[address],
                   uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1),
                   uc.reg_read(UC_ARM64_REG_X2), uc.reg_read(UC_ARM64_REG_X3)))

uc.hook_add(UC_HOOK_CODE, hook_code)

def run(addr, *args):
    for i, a in enumerate(args):
        uc.reg_write(UC_ARM64_REG_X0 + i, a)
    uc.reg_write(UC_ARM64_REG_LR, STOP)
    try:
        uc.emu_start(addr, STOP, timeout=180 * 1000000)
        return True
    except UcError as e:
        pc = uc.reg_read(UC_ARM64_REG_PC)
        log.append("[!] UcError %s at pc=0x%x (orig=0x%x)" % (e, pc, addr))
        return False

ok = True
for i, c in enumerate(ctors):
    if c == 0: continue
    log.append("[CTOR %d] 0x%x" % (i, c))
    if not run(c):
        ok = False; break

img = bytearray(0x110000)
for _off, _va, _fsz, _msz in LOADS:
    try:
        img[_va:_va+_msz] = bytes(uc.mem_read(_va, _msz))
    except UcError as e:
        log.append("[!] dump seg va=0x%x failed: %s" % (_va, e))
img = bytes(img)
open(OUT, "wb").write(img)
import re
strs = [m.group()[:32] for m in re.finditer(rb"[\x20-\x7e]{10,}", img[:0xd8000])]
log.append("[IMAGE] saved 0x110000 bytes; %d strings in fragment zone; sample: %s" %
           (len(strs), strs[:12]))
meta = struct.unpack("<Q", bytes(uc.mem_read(0x101e30, 8)))[0]
log.append("[META] ptr=0x%x +0x8c=%x +0x90=%x +0x94=%x +0x98=%x +0x9c=%x" % (
    meta,
    struct.unpack("<I", bytes(uc.mem_read(meta+0x8c, 4)))[0],
    struct.unpack("<I", bytes(uc.mem_read(meta+0x90, 4)))[0],
    struct.unpack("<I", bytes(uc.mem_read(meta+0x94, 4)))[0],
    struct.unpack("<I", bytes(uc.mem_read(meta+0x98, 4)))[0],
    struct.unpack("<I", bytes(uc.mem_read(meta+0x9c, 4)))[0]))
det = struct.unpack("<I", bytes(uc.mem_read(0x2020e0, 4)))[0] if 0x2020e0 < 0x110000 else -1
log.append("[DETECT-LEVEL] 0x2020e0 = %s" % hex(det))

print("\n".join(log))
