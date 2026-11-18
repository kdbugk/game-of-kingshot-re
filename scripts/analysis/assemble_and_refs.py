#!/usr/bin/env python3
"""Assemble decrypted libil2cpp and find code referencing 'global-metadata' string.
Runtime image layout (per unpacker): packed[0:0x238] header+phdrs + inflated A at 0x238.
"""
import struct, re, zlib

packed = open("/home/re/work/apk/xapk/native_extract/lib/arm64-v8a/libil2cpp.so", "rb").read()
A = open("/home/re/work/apk/crypt_out_1_0x238.bin", "rb").read()
a_inf = zlib.decompressobj().decompress(A[8:])

so = packed[:0x238] + a_inf
# pad to full LOAD0 memsz if needed
if len(so) < 0x4828000:
    so += b"\0" * (0x4828000 - len(so))
open("/home/re/work/apk/libil2cpp_114_decrypted.so", "wb").write(so)
print(f"assembled: {len(so):,} bytes (header from packed, body inflated A)")

# find string occurrences
for pat in (b"global-metadata", b"Metadata", b"HTPX", b"il2cpp_init"):
    idxs = [m.start() for m in re.finditer(re.escape(pat), a_inf)][:6]
    print(pat, [hex(0x238 + i) for i in idxs])

# AArch64 adrp+add scanner: find instructions encoding references to given vaddr
def find_adrp_add_refs(image, target, base_off=0x238, img_vaddr=0x238):
    """image[i] corresponds to vaddr img_vaddr+i (we treat file offsets == vaddr since 1:1)."""
    refs = []
    n = len(image) - 8
    t_page = target & ~0xFFF
    t_off = target & 0xFFF
    for i in range(0, n, 4):
        instr = struct.unpack_from("<I", image, i)[0]
        # ADRP: op=1 immlo bits30-29, imm19 bits5-23, Rd bits0-4
        if (instr >> 31) == 1 and ((instr >> 24) & 0x1F) == 0x10:
            rd = instr & 0x1F
            immlo = (instr >> 29) & 3
            immhi = (instr >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20): imm -= 1 << 21
            pc = img_vaddr + i
            page = (pc & ~0xFFF) + (imm << 12)
            if page != t_page: continue
            # next instr add immediate
            instr2 = struct.unpack_from("<I", image, i + 4)[0]
            # ADD Xd, Xn, #imm12 (shift 0): 1001000100 imm12 Rn Rd
            if (instr2 >> 22) == 0b1001000100:
                rn = (instr2 >> 5) & 0x1F
                imm12 = (instr2 >> 10) & 0xFFF
                if rn == rd and imm12 == t_off:
                    refs.append((pc, instr2 & 0x1F))
    return refs

gm = 0x238 + a_inf.index(b"global-metadata")
print(f"\n'global-metadata' string at vaddr 0x{gm:x}")
refs = find_adrp_add_refs(a_inf, gm)
print("ADRP+ADD refs:", [(hex(r[0]), f"x{r[1]}") for r in refs[:20]])

# also 'Metadata' dir string
m2 = 0x238 + a_inf.index(b"Metadata\x00")
refs2 = find_adrp_add_refs(a_inf, m2)
print("'Metadata\\0' at 0x%x refs:" % m2, [hex(r[0]) for r in refs2[:10]])
