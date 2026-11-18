#!/usr/bin/env python3
"""Correct UnityFS parse (UnityPy-style) + block decrypt attempts:
plain LZ4 / XOR 0x5631234256312342 variants / positional keys."""
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
print(f"sig={sig} ver={ver} unity={uv} gen={gr}")
print(f"size={size} csize={csize} usize={usize} flags={flags:#010b} (0x{flags:x})")
print("  compression:", flags & 0x3f, "| blocksInfoAtEnd:", bool(flags & 0x80),
      "| UseAssetBundleEncryption(0x200):", bool(flags & 0x200),
      "| BlockInfoNeedPadding(0x400):", bool(flags & 0x400))
r.align(16)

# blocksInfo
bi_raw = d[r.p:r.p + csize]
comp = flags & 0x3f
print("blocksInfo comp mode:", comp)
if comp in (2, 3):
    bi = lz4.block.decompress(bi_raw, usize)
elif comp == 0:
    bi = bi_raw
else:
    raise SystemExit("lzma blocksInfo — tratar depois")
br = R(bi)
hash16 = br.b[0:16]; br.p = 16
nblocks = br.i32()
blocks = [(br.u32(), br.u32(), br.u16()) for _ in range(nblocks)]
nnodes = br.i32()
nodes = []
for _ in range(nnodes):
    off = br.u64(); sz = br.u64(); fl = br.u32(); path = br.cstr()
    nodes.append((off, sz, fl, path))
print(f"blocos: {nblocks}, nodes: {nnodes}")
print("node[0..3]:", [(hex(o), hex(s)) for o, s, f, p in nodes[:3]])
print("node paths:", [p[:40] for _, _, _, p in nodes[:4]])

p = r.p + csize
if flags & 0x400:
    p = (p + 15) & ~15

KEY = bytes.fromhex("4233125642331256")
def try_dec(blk, usz):
    # plain
    try:
        lz4.block.decompress(blk, usz); return ("plain", blk)
    except Exception: pass
    # xor 8 alignments
    for al in range(8):
        x = bytes(b ^ KEY[(i + al) % 8] for i, b in enumerate(blk))
        try:
            out = lz4.block.decompress(x, usz); return (f"xor al={al}", x)
        except Exception: pass
    return None

results = {}
p0 = p
for i, (usz, csz, bf) in enumerate(blocks[:8]):
    blk = d[p:p + csz]; p += csz
    res = try_dec(blk, usz)
    results[i] = res
    print(f"  bloco {i}: usz={usz} csz={csz} flags={bf:#x} → {res[0] if res else 'FALHOU'}")
    if res:
        out = lz4.block.decompress(res[1], usz)
        print(f"    head: {out[:24].hex()}")
