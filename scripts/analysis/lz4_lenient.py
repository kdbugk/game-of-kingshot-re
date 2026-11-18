#!/usr/bin/env python3
"""Lenient LZ4 block decoder — decodes until error, reports position and partial output."""
import sys

def lz4_lenient(src, max_out):
    out = bytearray()
    i, n = 0, len(src)
    try:
        while i < n:
            tok = src[i]; i += 1
            lit = tok >> 4
            if lit == 15:
                while True:
                    b = src[i]; i += 1
                    lit += b
                    if b != 255: break
            if i + lit > n: raise ValueError(f"literal overrun at {i} (lit={lit})")
            out += src[i:i + lit]; i += lit
            if i >= n: break  # last literals, no match
            off = src[i] | (src[i + 1] << 8); i += 2
            if off == 0: raise ValueError(f"zero offset at {i}")
            ml = tok & 15
            if ml == 15:
                while True:
                    b = src[i]; i += 1
                    ml += b
                    if b != 255: break
            ml += 4
            start = len(out) - off
            if start < 0: raise ValueError(f"offset beyond output at {i} (off={off})")
            for k in range(ml):
                out.append(out[start + k])
    except (IndexError, ValueError) as e:
        return bytes(out), f"stop: {e}"
    return bytes(out), f"done ({len(out)} bytes)"

if __name__ == "__main__":
    import zipfile
    d = zipfile.ZipFile("/home/re/work/apk/xapk195/game_asset.apk").read(
        "assets/data/luapackage_64_1ebe3e565bc2895dbc4cf0a218f7443d.unity3d")
    blk = d[0x970:0x970 + 83236]
    for skip in (0, 8, 16):
        out, msg = lz4_lenient(blk[skip:], 131072)
        print(f"skip={skip}: {len(out)}B — {msg}")
        print(f"  head: {out[:48].hex()}")
