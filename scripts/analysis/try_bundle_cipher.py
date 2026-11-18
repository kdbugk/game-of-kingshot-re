#!/usr/bin/env python3
"""Run the emulated packer cipher (FUN_04949e48) on UnityFS bundle blocks, then try LZ4."""
import struct, lz4.block, zipfile

SRC = open("/mnt/c/Users/prs/projects/game-of-kingshot-re/scripts/analysis/emu_unpack.py").read()
exec(SRC.split('print("\\n".join(log))')[0])

APK = "/home/re/work/apk/xapk195/game_asset.apk"
ENTRY = "assets/data/luapackage_64_1ebe3e565bc2895dbc4cf0a218f7443d.unity3d"
d = zipfile.ZipFile(APK).read(ENTRY)

class R:
    def __init__(s, b): s.b, s.p = b, 0
    def cstr(s):
        e = s.b.index(b"\0", s.p); v = s.b[s.p:e]; s.p = e + 1; return v
    def u32(s): v = struct.unpack_from(">I", s.b, s.p)[0]; s.p += 4; return v
    def i32(s): v = struct.unpack_from(">i", s.b, s.p)[0]; s.p += 4; return v
    def u64(s): v = struct.unpack_from(">Q", s.b, s.p)[0]; s.p += 8; return v
    def u16(s): v = struct.unpack_from(">H", s.b, s.p)[0]; s.p += 2; return v
    def align(s, n): s.p = (s.p + n - 1) & ~(n - 1)

r = R(d)
sig = r.cstr(); ver = r.u32(); uv = r.cstr(); gr = r.cstr()
size = r.u64(); csize = r.u32(); usize = r.u32(); flags = r.u32()
r.align(16)
bi = lz4.block.decompress(d[r.p:r.p + csize], usize)
br = R(bi); br.p = 16
nblocks = br.i32()
blocks = [(br.u32(), br.u32(), br.u16()) for _ in range(nblocks)]
p = r.p + csize
if flags & 0x400: p = (p + 15) & ~15

BLK_ADDR = 0x600030000000
DST_ADDR = 0x600040000000
uc.mem_map(BLK_ADDR & ~0xFFF, 0x100000, UC_PROT_ALL)
uc.mem_map(DST_ADDR & ~0xFFF, 0x100000, UC_PROT_ALL)
keyptr = captured["crypt"][-1]["keyptr"]

pos = p
for i, (usz, csz, bf) in enumerate(blocks[:6]):
    blk = d[pos:pos + csz]; pos += csz
    uc.mem_write(BLK_ADDR, blk + b"\0" * (0x100 - len(blk) % 0x100))
    run(CRYPT, BLK_ADDR, len(blk), DST_ADDR, len(blk),
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, keyptr)
    out = bytes(uc.mem_read(DST_ADDR, min(len(blk), 64)))
    # try lz4 on decrypted
    try:
        dec = lz4.block.decompress(bytes(uc.mem_read(DST_ADDR, len(blk))) if len(blk) == csz else out, usz)
        print(f"bloco {i}: CIPHER+LZ4 OK!! head={dec[:24].hex()}")
        continue
    except Exception:
        pass
    # also try truncating to 0x40-blocks
    try:
        n = (len(blk) // 0x40) * 0x40
        dec = lz4.block.decompress(bytes(uc.mem_read(DST_ADDR, n)), usz)
        print(f"bloco {i}: CIPHER(trunc)+LZ4 OK!! head={dec[:24].hex()}")
        continue
    except Exception as e:
        print(f"bloco {i}: csz={csz} falhou ({e}) | dec head={out[:16].hex()}")
