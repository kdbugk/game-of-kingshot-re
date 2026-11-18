#!/usr/bin/env python3
"""Extract init_array constructor addresses from packed libil2cpp RELA table."""
import struct, sys

path = sys.argv[1] if len(sys.argv) > 1 else "/home/re/work/apk/xapk/native_extract/lib/arm64-v8a/libil2cpp.so"
d = open(path, "rb").read()

# vaddr->file mapping from PT_LOADs (readelf): (vaddr, offset, filesz)
LOADS = [(0x0, 0x0, 0x4104000), (0x4828000, 0x4104000, 0x0b43a0), (0x48e03a0, 0x41b83a0, 0x0036d0), (0x48e7a70, 0x41bba70, 0xa058c8)]
def v2f(v):
    for va, off, sz in LOADS:
        if va <= v < va + sz: return off + (v - va)
    raise ValueError(hex(v))

RELA_V, RELA_SZ = 0x482a640, 34104
JMPREL_V, JMPREL_SZ = 0x4832b78, 2472
INIT_V, INIT_SZ = 0x48e3018, 56
FINI_V, FINI_SZ = 0x48e2ff8, 32

print("== R_AARCH64_RELATIVE entries targeting INIT_ARRAY ==")
ctors = []
for i in range(RELA_SZ // 24):
    off = v2f(RELA_V) + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, off)
    rtype = r_info & 0xffffffff
    if INIT_V <= r_offset < INIT_V + INIT_SZ:
        print(f"  init[{(r_offset-INIT_V)//8}] -> addend 0x{r_addend:x} (type {rtype})")
        ctors.append(r_addend)
    if FINI_V <= r_offset < FINI_V + FINI_SZ:
        print(f"  fini[{(r_offset-FINI_V)//8}] -> addend 0x{r_addend:x}")

print("\n== JMPREL (PLT) imports ==")
# dynsym for symbol names: SYMTAB 0x48eba88, STRTAB 0x48ff2a8
def symname(symidx):
    so = v2f(0x48eba88) + symidx * 24
    st_name = struct.unpack_from("<I", d, so)[0]
    stro = v2f(0x48ff2a8) + st_name
    end = d.index(b"\0", stro)
    return d[stro:end]

imports = []
for i in range(JMPREL_SZ // 24):
    off = v2f(JMPREL_V) + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, off)
    symidx = r_info >> 32
    imports.append((r_offset, symname(symidx)))
print(f"  {len(imports)} PLT relocations:")
for ro, nm in imports:
    printable = nm.decode("ascii", "replace")
    print(f"  got 0x{ro:x} <- {printable}")

# also relative reloc addrs histogram: how many target the RW data area (patching)
print("\n== RELATIVE reloc stats ==")
targets = 0
in_load3 = 0
for i in range(RELA_SZ // 24):
    off = v2f(RELA_V) + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, off)
    if r_info & 0xffffffff == 1027:
        targets += 1
        if 0x48e7a70 <= r_offset < 0x48e7a70 + 0xa058c8: in_load3 += 1
print(f"  RELATIVE total={targets}, targeting .data(LOAD3)={in_load3}")
