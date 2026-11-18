#!/usr/bin/env python3
"""ELF sanity + per-section entropy for (possibly packed) .so files."""
import sys, math, struct
from collections import Counter

def entropy(b):
    if not b: return 0
    c = Counter(b); tot = len(b)
    return -sum((v/tot)*math.log2(v/tot) for v in c.values())

def walk(path):
    print(f"\n═══ {path.split('/')[-1]} ═══")
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF":
        print("  NOT AN ELF on disk"); return
    ei_class, ei_data = d[4], d[5]
    is64 = ei_class == 2
    e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", d, 0x3a)[0]
    e_shnum = struct.unpack_from("<H", d, 0x3c)[0]
    e_shstrndx = struct.unpack_from("<H", d, 0x3e)[0]
    print(f"  size={len(d)/1e6:.1f}MB shoff={e_shoff:#x} shnum={e_shnum}")
    if e_shnum == 0 or e_shoff == 0:
        print("  >>> SECTION HEADERS STRIPPED (packed/anomalous)")
    shs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, stype, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", d, off)
        shs.append((name, stype, offset, size))
    if shs:
        shstr_off = shs[e_shstrndx][2]
        def sname(n):
            end = d.index(b"\0", shstr_off + n)
            return d[shstr_off + n:end].decode(errors="replace")
        for name, stype, offset, size in shs:
            nm = sname(name)
            ent = entropy(d[offset:offset+min(size, 300000)])
            mark = " <<< HIGH ENTROPY (encrypted?)" if ent > 7.2 and size > 4096 else ""
            print(f"  {nm:<24} type={stype:<3} size={size/1024:>9.0f}K ent={ent:.2f}{mark}")

for p in sys.argv[1:]:
    walk(p)
