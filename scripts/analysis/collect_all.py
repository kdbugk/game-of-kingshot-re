#!/usr/bin/env python3
"""Lean block-0 collector: all bundles of one APK, block-0 bytes only (first 4KB)."""
import zipfile, struct, sys, pickle

APK = sys.argv[1] if len(sys.argv) > 1 else "/home/re/work/apk/xapk/game_asset.apk"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/b0_all_114.pkl"

z = zipfile.ZipFile(APK)
names = [n for n in z.namelist() if n.endswith(".unity3d")]
print(f"{len(names)} bundles")
out = []
errs = 0
for idx, n in enumerate(names):
    try:
        d = z.read(n)
        p = 8
        e = d.index(b"\0", p); p = e + 1          # sig
        p += 4                                       # ver
        e = d.index(b"\0", p); p = e + 1           # unityVer
        e = d.index(b"\0", p); p = e + 1           # genRev
        p += 8                                       # size
        csize, = struct.unpack_from(">I", d, p); p += 4
        usize, = struct.unpack_from(">I", d, p); p += 4
        flags, = struct.unpack_from(">I", d, p); p += 4
        p = (p + 15) & ~15
        p += csize
        p = (p + 15) & ~15
        out.append(d[p:p + 4096])
    except Exception:
        errs += 1
    if idx % 1000 == 0:
        print(f"  {idx}...", flush=True)
print(f"coletados: {len(out)}, erros: {errs}")
pickle.dump(out, open(OUT, "wb"))
print(f"→ {OUT}")
