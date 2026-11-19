#!/usr/bin/env python3
"""Exact middle-table boundaries via metadata token runs (0x06/0x04/0x17/0x14/0x08...).
Each table's entries end with a monotonic token; find runs with the right stride."""
import struct, sys

VER = sys.argv[1] if len(sys.argv) > 1 else "114"
dec = open(f"/tmp/meta_dec_{VER}.bin", "rb").read()
N = len(dec)

# região intermediária: após a string table, antes de par15
# recupera os valores do solve_header (string_end ~0x2b2708, final=par15.off)
string_size = 0x1e4d00
final_off = struct.unpack_from("<II", dec, 128)[0]
lo, hi = 0x2b2708, final_off
print(f"região: 0x{lo:x}..0x{hi:x}")

def token_runs(prefix, stride, lo, hi):
    """posições onde u32 com byte3==prefix aparece com espaçamento == stride"""
    hits = []
    for off in range(lo, hi - 4, 4):
        v = struct.unpack_from("<I", dec, off)[0]
        if (v >> 24) == prefix and (v & 0xFFFFFF) < 0xFFFFFF:
            hits.append(off)
    # agrupa por stride: para cada hit, verifica se hit+stride também é hit
    runs = []
    hs = set(hits)
    for h in hits:
        run_start = h
        while (run_start - stride) in hs:
            run_start -= stride
        length = 1
        x = h
        while (x + stride) in hs:
            x += stride; length += 1
        runs.append((run_start, length, h))
    # melhor run (mais longo)
    runs.sort(key=lambda r: -r[1])
    return runs[:3], len(hits)

for name, prefix, stride in [("methods", 0x06, 0x34), ("fields", 0x04, 0x10),
                              ("properties", 0x17, 0x1C), ("events", 0x14, 0x20),
                              ("params", 0x08, 0x10), ("typeDefs", 0x02, 0x5C)]:
    runs, nh = token_runs(prefix, stride, lo, hi)
    print(f"{name}: {nh} tokens; top runs:")
    for rs, ln, _ in runs:
        print(f"   início 0x{rs:x}, {ln} entradas → fim 0x{rs + ln*stride:x}")
