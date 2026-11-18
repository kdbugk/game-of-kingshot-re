#!/usr/bin/env python3
"""Deobfuscate XOR-ramp strings found in FUN_04951fdc (packed libil2cpp unpacker).
Ghidra addr 0x49e7a90 -> vaddr 0x48e7a90 -> file offset 0x41bba70+(0x48e7a90-0x48e7a70)."""
d = open("/home/re/work/apk/xapk/native_extract/lib/arm64-v8a/libil2cpp.so", "rb").read()

def ghidra_to_file(g):
    v = g - 0x100000
    # LOAD3: vaddr 0x48e7a70 -> file 0x41bba70
    return 0x41bba70 + (v - 0x48e7a70)

def dec(gaddr, keybytes):
    off = ghidra_to_file(gaddr)
    out = bytes(d[off + i] ^ k for i, k in enumerate(keybytes))
    return out

# string 1: DAT_049e7a90 ^ ramp 0x0f.. (15 bytes: 0x0f,0x10,...,0x1d)
s1 = dec(0x49e7a90, range(0x0f, 0x0f + 15))
# string 2: DAT_049e7aa0 ^ 0x1d..0x39 (29 bytes)
s2 = dec(0x49e7aa0, range(0x1d, 0x1d + 29))
print("string1:", s1)
print("string2:", s2)

# scan surroundings for more XOR-ramp strings (try all starts with various ramps)
print("\n-- vizinhos (0x49e7a80..0x49e7b00) --")
base = ghidra_to_file(0x49e7a80)
for i in range(0, 0x80, 1):
    pass
