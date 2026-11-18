#!/usr/bin/env python3
"""Validate 1.9.5 unpacked image vs known RVAs (dump.cs), then locate the
metadata-chain functions in 1.14.27 via fuzzy byte patterns."""
import zlib, struct

A95 = open("/home/re/work/apk/crypt_195_1_0x238.bin", "rb").read()
a95 = zlib.decompressobj().decompress(A95[8:])
open("/home/re/work/apk/partA_195.bin", "wb").write(a95)
print(f"partA_195: {len(a95):,} bytes")

A114 = open("/home/re/work/apk/crypt_out_1_0x238.bin", "rb").read()
a114 = zlib.decompressobj().decompress(A114[8:])
print(f"partA_114: {len(a114):,} bytes")

# image vaddr of partA content = 0x238 (runtime layout), RVA==vaddr for this lib
BASE = 0x238
def at95(rva, n=16):
    return a95[rva - BASE: rva - BASE + n]

# 1) sanity: known function prologues
for name, rva in [("initDecrypt", 0x19e1c2c), ("FUN_0192ca00", 0x192ca00),
                  ("FUN_0192cc00", 0x192cc00), ("FUN_0194339c", 0x194339c),
                  ("FUN_01944070", 0x19444070 % 0x1000000 + 0x1000000),
                  ("FUN_018ffd10", 0x18ffd10), ("FUN_0194b9d8", 0x194b9d8)]:
    b = at95(rva)
    ok = b[3] == 0xA9 or b[:4] in (b"\xfd\x7b\xbf\xa9",) or b[0] & 0x0F in (0x0,)
    print(f"{name:16} rva=0x{rva:x} bytes={b.hex()}")

# 2) fuzzy locate each chain function in 114
def fuzzy_find(hay, needle, min_match_ratio=0.82, window=None):
    """slide 4-byte aligned; count matching bytes"""
    n = len(needle)
    if window: needle = needle[:window]; n = len(needle)
    best = (0, -1)
    for i in range(0, len(hay) - n, 4):
        m = 0
        for j in range(n):
            if hay[i + j] == needle[j]: m += 1
        r = m / n
        if r > best[0]: best = (r, i)
        if r >= min_match_ratio:
            return (r, i)
    return best

CHAIN = [
    ("il2cpp_metadata_cache_init?", 0x18ffd10, 0x100),
    ("intermediario_192e26c", 0x192e26c, 0x100),
    ("FUN_0192ca00_wrap", 0x192ca00, 0x40),
    ("FUN_0192cc00_sched", 0x192cc00, 0x180),
    ("FUN_0194339c_open", 0x194339c, 0x100),
    ("FUN_019435dc_close", 0x19435dc, 0x80),
    ("FUN_0194b9d8_orch", 0x194b9d8, 0x120),
    ("FUN_01944070_mmap", 0x19444070 % 0x1000000 + 0x1000000, 0x100),
]
print("\n── localização fuzzy na 1.14.27 ──")
for name, rva, wlen in CHAIN:
    needle = a95[rva - BASE: rva - BASE + wlen]
    if len(needle) < wlen: continue
    r, off = fuzzy_find(a114, needle)
    print(f"{name:26} 95rva=0x{rva:x} → 114 off=0x{off + BASE:x} (match {r:.0%})" if off >= 0 else f"{name}: nada")
