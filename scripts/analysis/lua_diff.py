#!/usr/bin/env python3
"""Extract + inventory Lua packages from both APK versions, diff module lists.

Usage: lua_diff.py
"""
import UnityPy, os, sys, json, collections, zipfile

BASE = os.path.expanduser("~/work/apk")
VER = {
    "1.9.5":  f"{BASE}/xapk195/game_asset.apk",
    "1.14.27": f"{BASE}/xapk/game_asset.apk",
}

def lua_bundles(apk):
    z = zipfile.ZipFile(apk)
    return [n for n in z.namelist() if "luapackage" in n or "toluaout" in n]

def extract(apk, entries, outdir):
    os.makedirs(outdir, exist_ok=True)
    mods = {}
    for entry in entries:
        with zipfile.ZipFile(apk) as z:
            data = z.read(entry)
        env = UnityPy.load(data)
        for obj in env.objects:
            if obj.type.name != "TextAsset":
                continue
            ta = obj.read()
            name = getattr(ta, "m_Name", None) or getattr(ta, "name", "?")
            raw = ta.m_Script if hasattr(ta, "m_Script") else ta.script
            if isinstance(raw, str):
                raw = raw.encode("utf-8", "surrogateescape")
            mods[name] = raw
            safe = name.replace("/", "_")
            with open(os.path.join(outdir, safe), "wb") as f:
                f.write(raw)
    return mods

def classify(raw):
    if raw[:4] == b"\x1bLJ":
        return "luajit-bcdump"
    if raw[:4] == b"\x1bLua":
        return f"luac{raw[4]}.{raw[5]:x}"
    if raw[:2] == b"\x1b\x4c":
        return "lua-bytecode-?"
    try:
        raw.decode("utf-8"); return "plaintext"
    except Exception:
        return "binary-unknown"

report = {}
for ver, apk in VER.items():
    entries = lua_bundles(apk)
    print(f"\n═══ {ver} ═══ bundles: {entries}")
    mods = extract(apk, entries, f"{BASE}/lua_{ver.replace('.','_')}")
    kinds = collections.Counter(classify(m) for m in mods.values())
    print(f"modules: {len(mods)}  formats: {dict(kinds)}")
    # peek at first few names
    print("sample:", list(sorted(mods))[:10])
    report[ver] = set(mods)

if len(report) == 2:
    a, b = report["1.9.5"], report["1.14.27"]
    print(f"\n═══ DIFF 1.9.5 → 1.14.27 ═══")
    print(f"removed: {len(a-b)}  added: {len(b-a)}  kept: {len(a&b)}")
    print("\n--- ADDED (first 60) ---")
    for n in sorted(b-a)[:60]: print(f"  + {n}")
    print("\n--- REMOVED (first 60) ---")
    for n in sorted(a-b)[:60]: print(f"  - {n}")
    with open(f"{BASE}/lua_mods_diff.json", "w") as f:
        json.dump({"added": sorted(b-a), "removed": sorted(a-b), "kept": sorted(a&b)}, f, indent=1)
    print(f"\nfull diff → {BASE}/lua_mods_diff.json")
