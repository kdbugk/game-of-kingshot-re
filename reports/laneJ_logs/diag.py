#!/usr/bin/env python3
"""Unicorn emulator for the Kingshot libil2cpp.so packer (HTProtect).

Maps the packed ELF, applies RELATIVE relocations, stubs imports, runs the
.init_array constructors and the unpack driver FUN_0494fb64, and captures the
decrypted/decompressed payload via hooks on the crypto (FUN_04949e48) and
decompressor (FUN_04957a9c).

All addresses are file vaddrs (image mapped at 0).
"""
import struct, sys, json
from unicorn import *
from unicorn.arm64_const import *

PATH = "/home/re/work/apk/xapk/native_extract/lib/arm64-v8a/libil2cpp.so"

CRYPT = 0x4949e48 - 0x100000      # FUN_04949e48 vaddr
DECOMP = 0x4957a9c - 0x100000
DRIVER = 0x494fb64 - 0x100000     # FUN_0494fb64
CTORS = [0x48d6eb4, 0x48d7384, 0x48bb3f0, 0x48bbc5c, 0x48bc354, 0x48a3ffc, 0x48b1f1c]
GLOBAL_HDR = 0x48e9158            # *(this) = arg2 of driver
GLOBAL_CFG = 0x48e9168            # DAT = arg1 of driver

STACK = 0x7f0000000000
STACK_SZ = 8 * 1024 * 1024
TLS    = 0x7e0000000000
HEAP   = 0x700000000000
HEAP_SZ = 512 * 1024 * 1024
TRAMP  = 0x6f0000000000           # import trampolines
FAKE_FD_TABLE_BASE = 0x6e0000000000

d = open(PATH, "rb").read()
log = []
captured = {"crypt": [], "decomp": []}

# ── parse ELF ─────────────────────────────────────────────
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

# dynamic tags
dyn = {}
o = v2f(DYN_V)
while True:
    tag, val = struct.unpack_from("<qQ", d, o); o += 16
    if tag == 0: break
    dyn.setdefault(tag, val)
RELA_V, RELA_SZ = dyn[7], dyn[8]
JMPREL_V, JMPREL_SZ = dyn[23], dyn[2]
SYMTAB, STRTAB = dyn[6], dyn[5]

def symname(idx):
    so = v2f(SYMTAB) + idx * 24
    st_name, = struct.unpack_from("<I", d, so)
    stro = v2f(STRTAB) + st_name
    return d[stro:d.index(b"\0", stro)].decode("ascii", "replace")

# ── unicorn setup ─────────────────────────────────────────
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
uc.mem_write(TLS + 0x28, struct.pack("<Q", 0xDEADBEEFCAFEBABE))  # canary
uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SZ - 0x10000)

heap_ptr = HEAP
def halloc(n):
    global heap_ptr
    n = (n + 0xFFF) & ~0xFFF
    p = heap_ptr; heap_ptr += n
    return p

fake_strs = {  # __system_property_get buffers
    b"ro.arch": b"aarch64\n",
}
FAKE_MAPS = (
    "7f0000000000-7f0000800000 rw-p 00000000 00:00 0                          [stack]\n"
    "700000000000-70200000000 rw-p 00000000 00:00 0                          [heap]\n"
    "1000000000-1100000000 r-xp 00000000 00:00 0                             libil2cpp.so\n"
)
RET_MAGIC = 0x5BAD0000  # code address used as "return here after stub"

# trampoline addresses for each import (from JMPREL + symbolic RELA entries)
import_got = {}   # tramp addr -> name
imports = []
for i in range(JMPREL_SZ // 24):
    ro = v2f(JMPREL_V) + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, ro)
    symidx = r_info >> 32
    imports.append((r_offset, symname(symidx)))
for i in range(RELA_SZ // 24):
    ro = v2f(RELA_V) + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, ro)
    rt = r_info & 0xFFFFFFFF
    if rt in (1025, 1026):  # GLOB_DAT / JUMP_SLOT
        imports.append((r_offset, symname(r_info >> 32)))

taken = {}
for i, (got, name) in enumerate(imports):
    if got in taken:
        continue
    taken[got] = name
    tramp = TRAMP + 0x10 * i
    import_got[tramp] = name
    uc.mem_write(got, struct.pack("<Q", tramp))
log.append(f"[SETUP] {len(import_got)} import GOT slots patched: " + ", ".join(sorted(set(import_got.values()))))

# apply RELATIVE relocs
rel_count = 0
for i in range(RELA_SZ // 24):
    ro = v2f(RELA_V) + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, ro)
    if r_info & 0xFFFFFFFF == 1027:
        uc.mem_write(r_offset, struct.pack("<Q", r_addend)); rel_count += 1
log.append(f"[SETUP] {rel_count} RELATIVE relocs applied")

log.append(f"[SETUP] {len(import_got)} import GOT slots patched")

def impl(name, uc, virt):
    x0 = uc.reg_read(UC_ARM64_REG_X0); x1 = uc.reg_read(UC_ARM64_REG_X1)
    x2 = uc.reg_read(UC_ARM64_REG_X2); x3 = uc.reg_read(UC_ARM64_REG_X3)
    if name == "malloc": return halloc(x0)
    if name == "calloc": return halloc(x0 * x1)
    if name == "free": return 0
    if name == "memset":
        uc.mem_write(x0, bytes([x1 & 0xFF]) * x2); return x0
    if name == "strncpy":
        src = bytes(uc.mem_read(x1, min(x2, 0x100)))
        src = src[:src.index(b"\0")+1] if b"\0" in src else src
        out = src + b"\0" * (x2 - len(src))
        uc.mem_write(x0, out); return x0
    if name in ("memcpy", "__memcpy_chk", "memmove"):
        uc.mem_write(x0, bytes(uc.mem_read(x1, x2))); return x0
    if name in ("strlen", "__strlen_chk"):
        b = uc.mem_read(x0, 0x10000); return b.index(b"\0")
    if name == "strncmp":
        a = uc.mem_read(x0, 64); b = uc.mem_read(x1, 64)
        n = min(x2, a.index(b"\0") if b"\0" in a else 64, b.index(b"\0") if b"\0" in b else 64)
        return int(a[:n] != b[:n])
    if name == "strcmp":
        a = uc.mem_read(x0, 256); b = uc.mem_read(x1, 256)
        return int(a[:a.index(b"\0")] != b[:b.index(b"\0")])
    if name == "memcmp":
        return int(bytes(uc.mem_read(x0, x2)) != bytes(uc.mem_read(x1, x2)))
    if name == "mmap":
        sz = (x1 + 0xFFF) & ~0xFFF; return halloc(max(sz, 0x1000))
    if name in ("mprotect", "munmap", "close", "fflush", "fputc", "fseek", "ferror"):
        return 0
    if name == "sysconf": return 0x1000
    if name == "__errno":
        return TLS + 0x2000
    if name == "getenv": return 0
    if name == "dlopen": return halloc(0x100)
    if name in ("dlsym",): return RET_MAGIC
    if name == "dlclose": return 0
    if name == "dladdr":
        uc.mem_write(x1, struct.pack("<QQ", 0x1000000000, "libil2cpp.so\0".find("l")))
        # fake dli_fname: write a string ptr
        sp = halloc(0x40); uc.mem_write(sp, b"libil2cpp.so\0")
        uc.mem_write(x1, struct.pack("<QQQQ", 0, sp, 0, 0)); return 1
    if name == "fopen":
        fn = bytes(uc.mem_read(x0, 64)); fn = fn[:fn.index(b"\0")]
        if b"maps" in fn:
            fp = halloc(0x100); uc.mem_write(fp + 8, struct.pack("<Q", 1))  # mark=maps
            globals()["_maps_fp"] = fp; globals()["_maps_pos"] = 0
            return fp
        return 0
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
    if name in ("fclose", "fdopen"): return 0
    if name == "sscanf":
        return 0
    if name == "vsnprintf":
        return 0
    if name in ("__system_property_get",):
        key = bytes(uc.mem_read(x0, 64)); key = key[:key.index(b"\0")]
        val = fake_strs.get(key, b"\0")
        uc.mem_write(x1, val + b"\0")
        return len(val)
    if name in ("abort", "__stack_chk_fail"):
        raise RuntimeError("stub abort/__stack_chk_fail called: " + name)
    if name == "AAsset_read": return 0
    # default: ret 0
    return 0

FN=0x484d470; FEND=0x484d470+0x700
trace=[]
def R(n): return uc.reg_read(n)
def hook_code(uc, address, size, user_data):
    if FN<=address<FEND:
        if address==FN:
            log.append("[FN-ENTRY] x0=%x x1(param_2)=%x x2(param_3)=%x lr=%x"%(R(UC_ARM64_REG_X0),R(UC_ARM64_REG_X1),R(UC_ARM64_REG_X2),R(UC_ARM64_REG_LR)))
            p2=R(UC_ARM64_REG_X1)
            try: log.append("  param_2 head: "+bytes(uc.mem_read(p2,0xa8)).hex())
            except Exception as e: log.append("  param_2 unreadable %s"%e)
        trace.append(address)
        if address in (0x484d470+0x470,):pass
    if address in import_got:
        log.append("[IMP] %s x0=%x x1=%x x2=%x lr=%x"%(import_got[address],R(UC_ARM64_REG_X0),R(UC_ARM64_REG_X1),R(UC_ARM64_REG_X2),R(UC_ARM64_REG_LR)))
    if address in import_got:
        name = import_got[address]
        rv = impl(name, uc, address)
        uc.reg_write(UC_ARM64_REG_X0, rv & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
    elif address == RET_MAGIC:
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
    elif address == CRYPT:
        src, srcsz, dst, dstsz = (uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1),
                                  uc.reg_read(UC_ARM64_REG_X2), uc.reg_read(UC_ARM64_REG_X3))
        key = uc.reg_read(UC_ARM64_REG_X6)
        ks = bytes(uc.mem_read(key, 256)) if key else b""
        ks = ks[:ks.index(b"\0")] if b"\0" in ks else ks
        log.append(f"[CRYPT] src=0x{src:x} sz=0x{srcsz:x} dst=0x{dst:x} key={ks!r}")
        captured["crypt"].append({"src": src, "sz": srcsz, "dst": dst, "key": ks, "keyptr": key})
    elif address == DECOMP:
        log.append(f"[DECOMP] x0=0x{uc.reg_read(UC_ARM64_REG_X0):x} x1=0x{uc.reg_read(UC_ARM64_REG_X1):x} x2=0x{uc.reg_read(UC_ARM64_REG_X2):x} x3=0x{uc.reg_read(UC_ARM64_REG_X3):x}")
    elif address in (0x484d8ec,0x484d66c+0,):
        log.append("[AFTER-CRYPT2?] pc=%x x0=%x"%(address,R(UC_ARM64_REG_X0)))
    elif address == DRIVER:
        log.append(f"[DRIVER] arg1=0x{uc.reg_read(UC_ARM64_REG_X0):x} arg2=0x{uc.reg_read(UC_ARM64_REG_X1):x}")

uc.hook_add(UC_HOOK_CODE, hook_code)

import os
TMO=int(os.environ.get("TMO","120"))
STOP = 0x600000000000
uc.mem_map(STOP & ~0xFFF, 0x1000, UC_PROT_ALL)
def run(addr, *args):
    for i, a in enumerate(args):
        uc.reg_write(UC_ARM64_REG_X0 + i, a)
    uc.reg_write(UC_ARM64_REG_LR, STOP)
    import time; t0=time.time()
    try:
        uc.emu_start(addr, STOP, timeout=(TMO if addr==DRIVER else 5) * 1000000)
        pc=uc.reg_read(UC_ARM64_REG_PC)
        log.append("[RUN-END] start=0x%x pc=0x%x reached_STOP=%s elapsed=%.1fs"%(addr,pc,pc==STOP,time.time()-t0))
    except UcError as e:
        pc = uc.reg_read(UC_ARM64_REG_PC)
        log.append(f"[!] UcError {e} at pc=0x{pc:x} (orig=0x{addr:x})")
        return False
    return True

ok = True
for i, c in enumerate(CTORS):
    log.append(f"[CTOR {i}] 0x{c:x}")
    if not run(c):
        ok = False
        break

cfg = struct.unpack("<Q", uc.mem_read(GLOBAL_CFG, 8))[0]
hdrp = struct.unpack("<Q", uc.mem_read(GLOBAL_HDR, 8))[0]
log.append(f"[GLOBALS] cfg=0x{cfg:x} hdrptr=0x{hdrp:x}")

if ok and cfg:
    log.append("[DRIVER] calling FUN_0494fb64")
    run(DRIVER, cfg, hdrp)

print("\n".join(log))

# dump BOTH crypt outputs + cfg struct
cfg_bytes = bytes(uc.mem_read(0x481ae28, 0xC0))
pass
print("[CFG] " + " ".join(f"{b:02x}" for b in cfg_bytes[:0x60]))
for i, c in enumerate(captured["crypt"]):
    blob = bytes(uc.mem_read(c["dst"], c["sz"]))
    out = f"/tmp/crypt_out_{i}_0x{c['src']:x}.bin"
    pass
    print(f"[CRYPT-OUT {i}] src=0x{c['src']:x} sz=0x{c['sz']:x} -> {out} head={blob[:16].hex()}")

payloads = [c for c in captured["crypt"] if c["sz"] > 0x1000000]
if payloads:
    c = payloads[-1]
    blob = bytes(uc.mem_read(c["dst"], c["sz"]))
    out = "/tmp/unpacked_payload.bin"
    pass
    print(f"[SAVED] {c['sz']} bytes -> {out}")
    print(f"[HEAD] {blob[:64].hex()}")


def _hx(a,n):
    try: return bytes(uc.mem_read(a,n))
    except Exception as e: return b"ERR"
import collections
print("[TRACE] last 80 pcs in FN: "+" ".join("%x"%a for a in trace[-80:]))
print("[TRACE] distinct pcs=%d total=%d"%(len(set(trace)),len(trace)))
print("[TRACE] max pc in fn=%x"%max(trace))
c=captured["crypt"][-1]
blob=bytes(uc.mem_read(c["dst"],c["sz"]))
nz=len(blob.rstrip(b"\0"))
print("[PROGRESS] last crypt dst=%x total=%x last_nonzero_off=%x (%.1f%%) pc=%x"%(c["dst"],c["sz"],nz,100.0*nz/c["sz"],uc.reg_read(UC_ARM64_REG_PC)))
