#!/usr/bin/env python3
"""Bundle decrypt: try_bundle_xor2's EXACT proven parser + 3-byte XOR candidates."""
import zipfile, struct, lz4.block

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
br = R(bi)
br.p = 16
nblocks = br.i32()
blocks = [(br.u32(), br.u32(), br.u16()) for _ in range(nblocks)]
p = r.p + csize
if flags & 0x400:
    p = (p + 15) & ~15
print(f"{nblocks} blocos | flags={flags:#x} | data@0x{p:x} | bloco0 ciph={d[p:p+16].hex()}")

def unxor(b, key):
    kl = len(key)
    return bytes(x ^ key[i % kl] for i, x in enumerate(b))

candidates = {
    "3B r0": bytes.fromhex("0a0024"),
    "3B r1": bytes.fromhex("00240a"),
    "3B r2": bytes.fromhex("240a00"),
    "4B": bytes.fromhex("0a002400"),
    "6B": bytes.fromhex("0a00240a0024"),
    "8B": bytes.fromhex("4233125642331256"),
}
pos = p
for i, (usz, csz, bf) in enumerate(blocks[:4]):
    blk = d[pos:pos + csz]; pos += csz
    for name, k in candidates.items():
        try:
            out = lz4.block.decompress(unxor(blk, k), usz)
            print(f"bloco {i}: *** {name} OK! head={out[:24].hex()}")
            break
        except Exception:
            pass
    else:
        print(f"bloco {i}: nenhum candidato | ciph={blk[:16].hex()}")
