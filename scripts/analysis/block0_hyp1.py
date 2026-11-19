#!/usr/bin/env python3
"""Hypothesis #1: block-0 uses the HTPX generator machinery with bundle params.
Oracle: K[0..48]=0x00, K[49..80]=0xA6 (established empirically).
Test matrix: seed candidates x H-source candidates x period variants."""
import struct, sys, zipfile
sys.path.insert(0, "/mnt/c/Users/prs/work/laneL")
from htpx_decrypt import crc_table, T, key_from_len, rc4_stream, u32

APK = "/home/re/work/apk/xapk195/game_asset.apk"
ENTRY = "assets/data/luapackage_64_1ebe3e565bc2895dbc4cf0a218f7443d.unity3d"
d = zipfile.ZipFile(APK).read(ENTRY)

# parse: header até blocksInfo (igual kingshot_bundle)
class R:
    def __init__(s, b): s.b, s.p = b, 0
    def cstr(s):
        e = s.b.index(b"\0", s.p); v = s.b[s.p:e]; s.p = e + 1; return v
    def u32(s): v = struct.unpack_from(">I", s.b, s.p)[0]; s.p += 4; return v
    def u64(s): v = struct.unpack_from(">Q", s.b, s.p)[0]; s.p += 8; return v
    def u16(s): v = struct.unpack_from(">H", s.b, s.p)[0]; s.p += 2; return v
r = R(d)
sig = r.cstr(); ver = r.u32(); uv = r.cstr(); gr = r.cstr()
size = r.u64(); csize = r.u32(); usize = r.u32(); flags = r.u32()
r.p = (r.p + 15) & ~15
p = (r.p + csize + 15) & ~15
blk0 = d[p:p+0x1080]
print(f"bundle: size={size} csize={csize} usize={usize} flags={flags:#x}")
print(f"blk0[0:16]: {blk0[:16].hex()}")
print(f"oracle check — blk0[49]=0x{blk0[49]:02x} (esperado 0xA6 xor plaintext~0)")

# candidatos de SEED (o que o CRC "do tamanho" poderia ser)
seeds = {
    "filesize": len(d), "size_field": size, "csize": csize, "usz": usize,
    "blk0csz_first": struct.unpack_from("<I", blk0, 0)[0],
    "usz+csize": usize ^ csize,
}

# para cada seed: gera RC4 streams e checa se XOR com blk0[49..80] vira constante
print("\n── teste: keystream[49..80] constante (0xA6 ou outro) sob cada seed? ──")
for name, n in seeds.items():
    w26 = key_from_len(n)
    for off_src, lbl in ((blk0, "blk0[0:128]"), (d[:128], "file[0:128]")):
        for keyvar, kv in (("w26", w26), ("w26^u32(blk0,4)", w26 ^ u32(blk0, 4))):
            ks = rc4_stream(struct.pack("<I", kv & 0xFFFFFFFF), 128)
            dec = bytes(a ^ b for a, b in zip(off_src[49:81], ks[49 - 0:81 - 0])) if False else bytes(off_src[49 + i] ^ ks[i] for i in range(32))
            uniq = set(dec)
            if len(uniq) <= 3:
                print(f"  *** {name}/{lbl}/{keyvar}: dec[49..80] tem {len(uniq)} valores únicos: {[hex(x) for x in uniq]}")
print("(linhas *** = candidatos; silêncio = nenhum stream direto casa)")

# variação B: stream alinhado por posição absoluta (ks[i] na posição i)
print("\n── teste B: alinhamento absoluto (posição 0 = início do bloco) ──")
for name, n in seeds.items():
    w26 = key_from_len(n)
    ks = rc4_stream(struct.pack("<I", w26), 4096)
    dec = bytes(blk0[i] ^ ks[i] for i in range(81))
    if dec[49:81] == bytes([dec[49]]) * 32:
        print(f"  *** {name}: constante 0x{dec[49]:02x} na janela!")
print("fim")
