#!/usr/bin/env python3
"""Reconstruct the original libil2cpp.so from emulator outputs.
- inflate both crypt outputs
- hunt for the original program-header table
- stitch image + build ELF header
"""
import zlib, struct, re

A = open("/home/re/work/apk/crypt_out_1_0x238.bin", "rb").read()
B = open("/home/re/work/apk/crypt_out_0_0x491aed8.bin", "rb").read()

def find_zlib(b):
    return [m.start() for m in re.finditer(re.escape(b"\x78\x9c"), b)][:8]

print("A zlib magic at:", find_zlib(A))
print("B zlib magic at:", find_zlib(B))

a_inf = zlib.decompressobj().decompress(A[8:])
print(f"A inflated: {len(a_inf):,} (0x{len(a_inf):x})")
open("/home/re/work/apk/partA_inflated.bin", "wb").write(a_inf)

bzs = find_zlib(B)
b_inf = None
for off in [8] + bzs:
    try:
        b_inf = zlib.decompressobj().decompress(B[off:])
        print(f"B inflated from +{off}: {len(b_inf):,} (0x{len(b_inf):x})")
        open("/home/re/work/apk/partB_inflated.bin", "wb").write(b_inf)
        break
    except Exception as e:
        print(f"B from +{off}: {e}")

# phdr hunt: 0x38-byte aligned runs with p_type in valid set
VALID = {0, 1, 2, 3, 4, 6, 7, 0x6474e550, 0x6474e551, 0x6474e552, 0x6474e553, 0x70000001, 0x70000003}
def hunt(b, name):
    print(f"-- phdr hunt in {name} --")
    for off in range(0, min(len(b), 0x1000) - 0x38 * 3, 8):
        n = 0
        while True:
            t = struct.unpack_from("<I", b, off + n * 0x38)[0] if off + n * 0x38 + 4 <= len(b) else -1
            if t in VALID and t != 0: n += 1
            else: break
        if n >= 3:
            print(f"  +0x{off:x}: {n} consecutive phdr-like entries")
            for i in range(min(n, 9)):
                o = off + i * 0x38
                pt, fl = struct.unpack_from("<II", b, o)
                po, pv, pp, fs, ms = struct.unpack_from("<QQQQQ", b, o + 8)
                print(f"    [{i}] type=0x{pt:x} flags={fl} off=0x{po:x} vaddr=0x{pv:x} filesz=0x{fs:x} memsz=0x{ms:x}")
            return off
    return None

hunt(a_inf, "A")
if b_inf: hunt(b_inf, "B")
