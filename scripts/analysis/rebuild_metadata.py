#!/usr/bin/env python3
"""Reconstruct valid global-metadata.dat from HTPX + recovered keystream.
Header (first 128B of body) solved by constraints: sanity+version fixed,
table (offset,size) pairs contiguous with the known pairs at body+128."""
import struct, sys, itertools

VER = sys.argv[1] if len(sys.argv) > 1 else "114"
PATH = {"114": "/home/re/work/apk/xapk/base_extract/assets/bin/Data/Managed/Metadata/global-metadata.dat",
        "195": "/home/re/work/apk/xapk195/base_extract/assets/bin/Data/Managed/Metadata/global-metadata.dat"}[VER]
KEYHEX = open(f"/mnt/c/Users/prs/work/laneI/key1152_{VER}.hex").read().strip()
key = bytes.fromhex(KEYHEX)
assert len(key) == 1152

raw = open(PATH, "rb").read()
body = raw[8:]
print(f"{VER}: file={len(raw):,} body={len(body):,}")

# decrypt com indexing (file_offset - 8) % 1152  →  body[i] usa key[i % 1152]
dec = bytearray(len(body))
for i in range(len(body)):
    dec[i] = body[i] ^ key[i % 1152]
for s in (b"mscorlib", b"UnityEngine", b"<Module>"):
    print(f"  {s}: {dec.count(s):,} ocorrências")
open(f"/tmp/meta_dec_{VER}.bin", "wb").write(bytes(dec))

# ── header solving ──
# pairs conhecidos a partir de body+128 (header+128 = par #15)
known_pairs = []
for off in range(128, 0x110 if len(body) > 0x110 else 128 + 8 * 20, 8):
    o, s = struct.unpack_from("<II", dec, off)
    known_pairs.append((o, s))
print("pares conhecidos (a partir de header+128):")
for i, (o, s) in enumerate(known_pairs[:10]):
    print(f"  par[{15+i}] = (0x{o:x}, 0x{s:x})")

# sanity + version fixos
sanity = 0xFAB11BAF
# tabelas: par[0].offset = 0x110; contiguidade: par[k+1].offset = par[k].offset + par[k].size
# par[15] conhecido → soma dos sizes[0..14] = par15.offset - 0x110
if known_pairs:
    p15 = known_pairs[0]
    total_early = p15[0] - 0x110
    print(f"par15 offset=0x{p15[0]:x} → sizes[0..14] somam 0x{total_early:x} ({total_early:,})")

# abordagem: iterar versões e derivar sizes das tabelas iniciais do CONTEÚDO decriptado
# stringLiteral entries: {len u32, dataIndex u32} a partir de 0x110; terminam quando
# dataIndex+length != próximo dataIndex (começo do stringLiteralData)
def find_sl_end():
    i = 0x110
    prev_end = 0
    while i + 8 <= len(dec):
        ln, di = struct.unpack_from("<II", dec, i)
        if ln > 0x10000 or di != prev_end:
            return i, prev_end
        prev_end = di + ln
        i += 8
    return i, prev_end

sl_end, sl_data_size = find_sl_end()
sl_size = sl_end - 0x110
print(f"stringLiteral: {sl_size:,} B ({sl_size//8} entradas), data size=0x{sl_data_size:x}")
