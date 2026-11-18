#!/usr/bin/env python3
"""Dump the FINAL reconstructed image from emulator memory after full unpack.
The driver patches the module image in place at vaddr 0x238+."""
import struct, zlib

SRC = open("/mnt/c/Users/prs/projects/game-of-kingshot-re/scripts/analysis/emu_unpack.py").read()
exec(SRC.split('print("\\n".join(log))')[0])

# final state: read the whole image range
IMG_END = 0x52EE000
chunks = []
prev = 0
for off, va, fs, msz in LOADS:
    if va > prev:
        chunks.append((prev, va - prev, None))
    chunks.append((va, ((va + msz + 0xFFF) & ~0xFFF) - va, "mem"))
    prev = ((va + msz + 0xFFF) & ~0xFFF)
if prev < IMG_END:
    chunks.append((prev, IMG_END - prev, None))
final = b"".join(bytes(uc.mem_read(a, s)) if m == "mem" else b"\0" * s for a, s, m in chunks)
open("/home/re/work/apk/final_image_114.bin", "wb").write(final)
print(f"[DUMP] {len(final):,} bytes da imagem final em memória")

bias = struct.unpack("<Q", uc.mem_read(0x48e7a80, 8))[0] if False else None
# DAT_049e7a80 (Ghidra) -> vaddr 0x48e7a80
try:
    bias = struct.unpack("<Q", uc.mem_read(0x48e7a80, 8))[0]
    print(f"[BIAS] DAT_049e7a80 = 0x{bias:x}")
except Exception as e:
    print("bias read fail:", e)

# sanity: strings agora com relocs aplicados?
import re
for pat in (b"global-metadata", b"il2cpp_init", b"JNI_OnLoad", b"Metadata"):
    idxs = [m.start() for m in re.finditer(re.escape(pat), final)][:5]
    print(pat, [hex(i) for i in idxs])

# compara com partA: região 0x238.. vs partA — patches?
a114 = zlib.decompressobj().decompress(open("/home/re/work/apk/crypt_out_1_0x238.bin","rb").read()[8:])
n = min(len(a114), len(final) - 0x238)
diff = sum(1 for i in range(0, n, 4096) if a114[i:i+4096] != final[0x238+i:0x238+i+4096])
print(f"[DIFF] páginas 4K diferentes vs partA puro: {diff}/{n//4096}")
