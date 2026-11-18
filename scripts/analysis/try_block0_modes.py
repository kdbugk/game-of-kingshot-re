#!/usr/bin/env python3
import zipfile, lz4.block, traceback

try:
    SRC = open("/mnt/c/Users/prs/projects/game-of-kingshot-re/scripts/analysis/emu_unpack.py").read()
    exec(SRC.split('print("\\n".join(log))')[0])

    d = zipfile.ZipFile("/home/re/work/apk/xapk195/game_asset.apk").read(
        "assets/data/luapackage_64_1ebe3e565bc2895dbc4cf0a218f7443d.unity3d")
    blk = d[0x970:0x970 + 83236]
    BLK = 0x600030000000
    DST = 0x600040000000
    from unicorn import UC_PROT_ALL
    uc.mem_map(BLK & ~0xFFF, 0x200000, UC_PROT_ALL)
    uc.mem_map(DST & ~0xFFF, 0x200000, UC_PROT_ALL)
    uc.mem_write(BLK, blk + b"\0" * 256)
    keyptr = captured["crypt"][-1]["keyptr"]
    M = 0xFFFFFFFFFFFFFFFF
    print("### começando modos ###")
    for name, p4, p5 in [("m00", 0, 0), ("m0m", 0, M), ("mm0", M, 0), ("m064", 0, 64)]:
        run(CRYPT, BLK, 83236, DST, 83236, p4, p5, keyptr)
        out = bytes(uc.mem_read(DST, 16))
        ok = False
        try:
            lz4.block.decompress(bytes(uc.mem_read(DST, 83236)), 131072)
            ok = True
        except Exception:
            pass
        print(f"RES {name} ok={ok} head={out.hex()}", flush=True)

    K = bytes.fromhex("4233125642331256")
    for rot in range(8):
        x = bytes(b ^ K[(i + rot) % 8] for i, b in enumerate(blk[:64])) + blk[64:]
        try:
            out = lz4.block.decompress(x, 131072)
            print(f"RES XOR64 rot={rot} OK head={out[:24].hex()}", flush=True)
            break
        except Exception:
            pass
    print("RES XOR64 nada", flush=True)
except Exception:
    traceback.print_exc()
