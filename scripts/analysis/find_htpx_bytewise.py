#!/usr/bin/env python3
"""Byte-wise HTPX magic comparison hunter.
Looks for clusters of CMP W?, #imm / SUBS with imm in {0x48,0x54,0x50,0x58}
(ARM64 encoding: CMP Wd, #imm = 0x7100xxxx family with imm12 at bits 10-21)."""
import struct, sys

def scan(img, base, name):
    want = {0x48, 0x54, 0x50, 0x58}
    n = len(img) - 4
    marks = []
    for i in range(0, n, 4):
        w = struct.unpack_from("<I", img, i)[0]
        # SUBS Wd, Wn, #imm12 (31..0): 0x7100000 | (imm12<<10) | Rn<<5 | Rd  (32-bit)
        if (w & 0xFF000000) == 0x71000000:
            imm12 = (w >> 10) & 0xFFF
            if imm12 in want:
                marks.append((base + i, imm12))
    # cluster: >=3 distinct wanted imms within 16 instructions (64 bytes)
    clusters = []
    for k in range(len(marks)):
        window = [m for m in marks if 0 <= m[0] - marks[k][0] < 64]
        imms = {m[1] for m in window}
        if len(imms) >= 3:
            clusters.append((marks[k][0], sorted(imms)))
    # dedup overlapping
    out, last = [], -1
    for va, imms in clusters:
        if va >= last:
            out.append((va, imms)); last = va + 64
    print(f"[{name}] {len(marks)} cmp-marks, clusters: {len(out)}")
    for va, imms in out[:15]:
        off = va - base
        print(f"  0x{va:x} imms={[hex(i) for i in imms]} ctx={img[off:off+32].hex()}")

imgA = open("/home/re/work/apk/partA_inflated.bin", "rb").read()
scan(imgA, 0x238, "libil2cpp-dec-114")
imgN = open("/home/re/work/apk/xapk/native_extract/lib/arm64-v8a/libNetHTProtect.so", "rb").read()
scan(imgN, 0, "libNetHTProtect-114")
