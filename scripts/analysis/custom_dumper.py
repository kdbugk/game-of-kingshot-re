#!/usr/bin/env python3
"""Custom minimal dumper for the custom-format metadata (token-anchored tables).
Outputs per-image class/method surface compatible with the 1.9.5 dump JSONs."""
import struct, sys, json
from pathlib import Path

VER = sys.argv[1] if len(sys.argv) > 1 else "114"
dec = open(f"/tmp/meta_dec_{VER}.bin", "rb").read()
N = len(dec)

string_start, string_size = 0xcda08, 0x28de00
string_end = string_start + string_size
def s(idx):
    if idx >= string_size: return None
    e = dec.index(b"\0", string_start + idx)
    return dec[string_start + idx:e].decode("utf-8", "replace")

# ── typeDefs: achar por nameIndex+namespaceIndex apontando pro string table ──
# entrada: nameIndex u32, namespaceIndex u32, ... ( stride desconhecido: descobre )
# scan: para cada offset, checa pares subsequentes razoáveis
best = None
lo, hi = 0x99b140, N - 0x100
# typeDefs fica entre genericContainers-fim (~0x99b140) e images (0xb2678c)
lo2, hi2 = 0x99b140, 0xb2678c
cand = []
for stride in (0x5C, 0x58, 0x60, 0x54, 0x50, 0x48, 0x64, 0x68):
    for off in range(lo2, min(lo2 + 0x2000, hi2), 4):
        ok = 0
        for k in range(24):
            ni, nsi = struct.unpack_from("<II", dec, off + k * stride)
            if ni < string_size and nsi < string_size:
                ok += 1
        if ok >= 22:
            cand.append((stride, off, ok))
for stride, off, ok in sorted(cand, key=lambda x: -x[2])[:5]:
    print(f"candidate typeDefs: stride=0x{stride:x} @0x{off:x} score={ok}/24")

if not cand:
    # fallback: varre mais largo
    print("scan amplo...")
    for stride in (0x5C,):
        for off in range(lo2, hi2 - 24 * stride, 4):
            ni, nsi = struct.unpack_from("<II", dec, off)
            if ni < string_size and nsi < string_size:
                ni2, nsi2 = struct.unpack_from("<II", dec, off + stride)
                if ni2 < string_size and nsi2 < string_size and ni2 > ni:
                    cand.append((stride, off, 2))
    for stride, off, _ in sorted(cand, key=lambda x: x[1])[:3]:
        print(f"cand amplo: 0x{off:x}")

stride, td_off, _ = max(cand, key=lambda x: x[2])
# mede o comprimento: enquanto nameIndex < string_size
cnt = 0
while True:
    ni, nsi = struct.unpack_from("<II", dec, td_off + cnt * stride)
    if ni >= string_size or nsi >= string_size: break
    cnt += 1
    if cnt > 200000: break
print(f"typeDefs: 0x{td_off:x}, {cnt} entradas × 0x{stride:x} → fim 0x{td_off + cnt*stride:x}")

# ── images (85 × 0x40 a partir de 0xb2678c): typeStart/typeCount ──
IMG_OFF = 0xb2678c
images = []
for i in range(85):
    b = IMG_OFF + i * 0x40
    name_idx = struct.unpack_from("<I", dec, b)[0]
    nm = s(name_idx) if name_idx < string_size else f"img{i}"
    images.append((nm, b))
print("imagens:", [im[0] for im in images[:6]], "...")

# valida layout: acha typeStart/typeCount testando offsets de campo
# v24 images def: name, nameNoExt, assemblyName{...}, typeStart, typeCount...
# empírico: procura u32 com contagem plausível por imagem
probe = images[0][1]
vals = [struct.unpack_from("<I", dec, probe + k*4)[0] for k in range(16)]
print("image[0] u32[0..16]:", [hex(v) for v in vals])

# ── methods (38860 × 36 @0x393dcc): nameIndex primeiro campo ──
MET_OFF, MET_SZ, MET_CNT = 0x393dcc, 36, 38860
print(f"methods: {MET_CNT} @0x{MET_OFF:x}")

# monta dicionário image → classes
OUT = Path(f"/home/re/work/apk/il2cpp_dump_{VER}")
OUT.mkdir(exist_ok=True)
# tenta achar typeStart/typeCount nas images com validação: soma typeCounts ≈ cnt
for ts_off in range(8, 0x40, 4):
    for tc_off in range(ts_off + 4, 0x40, 4):
        tot = 0; okc = True
        for nm, b in images:
            ts = struct.unpack_from("<i", dec, b + ts_off)[0]
            tc = struct.unpack_from("<i", dec, b + tc_off)[0]
            if not (0 <= ts <= cnt and 0 <= tc <= cnt):
                okc = False; break
            tot += tc
        if okc and abs(tot - cnt) < cnt * 0.02:
            print(f"*** typeStart@+0x{ts_off:x} typeCount@+0x{tc_off:x}: soma={tot} vs typeDefs={cnt}")
            for idx, (nm, b) in enumerate(images):
                ts = struct.unpack_from("<i", dec, b + ts_off)[0]
                tc = struct.unpack_from("<i", dec, b + tc_off)[0]
                classes = []
                for k in range(tc):
                    e = td_off + (ts + k) * stride
                    ni, nsi = struct.unpack_from("<II", dec, e)
                    classes.append({"name": s(ni) or "?", "ns": s(nsi) or ""})
                out = {"name": nm + ("" if nm.endswith(".dll") else ".dll"), "classes": classes}
                (OUT / f"{idx:03d}_{nm.replace('/', '_')}.json").write_text(json.dumps(out))
            print(f"[DONE] {len(images)} imagens -> {OUT}")
            sys.exit(0)
print("[X] layout de images não validado — dumpia com ranges diretos")
