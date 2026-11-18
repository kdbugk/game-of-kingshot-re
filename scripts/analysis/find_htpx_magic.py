#!/usr/bin/env python3
"""Find HTPX magic (0x58505448) construction in decrypted libil2cpp (1.14.27).
Scans MOVZ/MOVK pairs, LDR literal pools, and byte-wise compare idioms."""
import struct

img = open("/home/re/work/apk/partA_inflated.bin", "rb").read()
BASE = 0x238  # image vaddr of part A start (runtime layout)

def mov_imm(instr):
    """decode MOVZ/MOVK Wd/Xd -> (opc, imm16, hw, rd)"""
    op = None
    if (instr & 0x7F800000) == 0x52800000: op = "movz"
    elif (instr & 0x7F800000) == 0x72800000: op = "movk"
    else: return None
    rd = instr & 0x1F
    imm16 = (instr >> 5) & 0xFFFF
    hw = (instr >> 21) & 3
    sf = (instr >> 31) & 1
    return (op, imm16 << (16 * hw), rd, sf)

hits = []
n = len(img) - 16
for i in range(0, n, 4):
    w0 = struct.unpack_from("<I", img, i)[0]
    d0 = mov_imm(w0)
    if not d0: continue
    # check next 4 instructions for the complementary half
    for j in range(1, 5):
        w1 = struct.unpack_from("<I", img, i + 4 * j)[0]
        d1 = mov_imm(w1)
        if not d1 or d1[2] != d0[2]: continue
        val = d0[1] | d1[1]
        if val in (0x58505448, 0x48545250):
            va = BASE + i
            ctx = img[i:i + 4 * (j + 6)]
            hits.append((va, val, ctx.hex()))
            print(f"[MOV] vaddr 0x{va:x} val=0x{val:08x} ctx={ctx.hex()}")

# LDR literal: 0x58??0000 range loads 4-byte constants — search rodata for the 8-byte LE 48 54 50 58
needle = b"HTPX"
pos = 0
data_hits = []
while True:
    p = img.find(needle, pos)
    if p < 0: break
    data_hits.append(BASE + p)
    pos = p + 1
print("[DATA] 'HTPX' bytes in image:", [hex(h) for h in data_hits[:10]])

# byte-wise: MOV W?, #0x48/0x54/0x50/0x58 then CMPB sequences — heuristic: search for
# cmp w?, #0x58 (0x71004... encoding family) near #0x48 — skip (too noisy) unless MOV hits == 0
if not hits and not data_hits:
    print("[!] nada — tentar compares byte-a-byte na próxima rodada")
