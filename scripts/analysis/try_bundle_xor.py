#!/usr/bin/env python3
"""Try XOR 0x5631234256312342 on UnityFS bundle blocks (from FUN_0494f488).
Manual UnityFS parse + LZ4 block decompress with/without XOR."""
import zipfile, struct, lz4.block

APK = "/home/re/work/apk/xapk195/game_asset.apk"
ENTRY = "assets/data/luapackage_64_1ebe3e565bc2895dbc4cf0a218f7443d.unity3d"
KEY = bytes.fromhex("4233125642331256")  # LE of 0x5631234256312342

z = zipfile.ZipFile(APK)
d = z.read(ENTRY)
print("bundle size", len(d))

# UnityFS header
assert d[:8] == b"UnityFS\0"
p = 8
ver, = struct.unpack_from(">i", d, p); p += 4
unity_ver = d[p:d.index(b"\0", p)]; p = len(unity_ver) + 1
gen_rev = d[p:d.index(b"\0", p)]; p = len(gen_rev) + 1
size, csize, usize, flags = struct.unpack_from(">QIIB", d, p); p += 21
print(f"ver={ver} unity={unity_ver} gen={gen_rev} size={size} csize={csize} usize={usize} flags={flags:#x}")

# blocksInfo
comp = flags & 0x3f
blocks_info_raw = d[p:p + csize]
if comp == 0:
    bi = blocks_info_raw
else:
    try:
        bi = lz4.block.decompress(blocks_info_raw, usize)
        print("blocksInfo: LZ4 OK sem XOR")
    except Exception as e:
        xored = bytes(b ^ KEY[i % 8] for i, b in enumerate(blocks_info_raw))
        try:
            bi = lz4.block.decompress(xored, usize)
            print("*** blocksInfo: LZ4 OK COM XOR! ***")
        except Exception as e2:
            print("blocksInfo falha:", e, "|", e2)
            bi = None
if bi:
    # parse block entries: u16 hash... layout: 16B hash + int count + entries(u32 unc,u32 comp,u16 flags)
    q = 16
    n, = struct.unpack_from(">i", bi, q); q += 4
    print("blocos:", n)
    p += csize
    ok_xor = ok_plain = 0
    for i in range(min(n, 6)):
        usz, csz, bf = struct.unpack_from(">IIH", bi, q); q += 10
        blk = d[p:p + csz]; p += csz
        # try plain
        try:
            lz4.block.decompress(blk, usz); ok_plain += 1; res = "plain"
        except Exception:
            res = None
        # try xor with alignment offsets 0..7
        for al in range(8):
            x = bytes(b ^ KEY[(i + al) % 8] for i, b in enumerate(blk))
            try:
                out = lz4.block.decompress(x, usz)
                ok_xor += 1
                res = f"XOR align={al}!"
                print(f"  bloco {i}: unc={usz} comp={csz} flags={bf:#x} → {res} head={out[:8].hex()}")
                break
            except Exception:
                pass
        if not res:
            print(f"  bloco {i}: unc={usz} comp={csz} flags={bf:#x} → FALHOU ambos")
