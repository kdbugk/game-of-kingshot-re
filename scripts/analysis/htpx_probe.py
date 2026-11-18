#!/usr/bin/env python3
"""Probe HTPX-encrypted global-metadata.dat for simple crypto.

Oracle: decrypted body must start with AF 1B B1 FA (il2cpp metadata magic)
        followed by a sane version (uint32 < 100).
"""
import sys, math
from collections import Counter

path = sys.argv[1]
data = open(path, "rb").read()
hdr, body = data[:8], data[8:]
print(f"file={len(data)} header={hdr[:4]} size_field={int.from_bytes(hdr[4:8],'little')} body={len(body)}")

def entropy(b, n=65536):
    c = Counter(b[:n]); tot = sum(c.values())
    return -sum((v/tot)*math.log2(v/tot) for v in c.values())

print(f"entropy first64k = {entropy(body):.3f} bits/byte (8.0 = perfect random)")
print(f"first 32 bytes: {body[:32].hex()}")

TARGET = bytes.fromhex("AF1BB1FA")

def try_name(name, transformed):
    if transformed[:4] == TARGET:
        ver = int.from_bytes(transformed[4:8], "little")
        if 15 <= ver <= 45:
            print(f"*** HIT: {name} — version={ver}")
            return True
    return False

# 1. single-byte xor
for k in range(256):
    if try_name(f"xor 0x{k:02x}", bytes(b ^ k for b in body[:8]) + body[8:16]):
        open(path + ".dec", "wb").write(bytes(b ^ k for b in body)); sys.exit(0)

# 2. repeating xor key up to 32 bytes (derive from oracle: key[i] = body[i]^target[i])
for klen in range(2, 33):
    key = bytes(body[i] ^ TARGET[i % 4] for i in range(klen))
    dec = bytes(body[i] ^ key[i % klen] for i in range(16))
    if try_name(f"xor klen={klen} key={key.hex()}", dec + b""):
        full = bytes(body[i] ^ key[i % klen] for i in range(len(body)))
        open(path + ".dec", "wb").write(full); sys.exit(0)

# 3. add/sub constant mod 256
for k in range(256):
    if try_name(f"add 0x{k:02x}", bytes((b + k) & 0xff for b in body[:16])):
        open(path + ".dec", "wb").write(bytes((b + k) & 0xff for b in body)); sys.exit(0)

# 4. byte-swap / bit rotations of first bytes
for r in range(1, 8):
    if try_name(f"rol {r}", bytes(((b << r) | (b >> (8 - r))) & 0xff for b in body[:16])): 
        open(path + ".dec","wb").write(bytes(((b << r) | (b >> (8 - r))) & 0xff for b in body)); sys.exit(0)

# 5. reverse chunks
if try_name("reversed", body[::-1][:16]): open(path+".dec","wb").write(body[::-1]); sys.exit(0)

# 6. skip N bytes (maybe HTPX header is bigger than 8)
for skip in range(4, 256, 4):
    if body[skip:skip+4] == TARGET:
        print(f"*** plain metadata at offset +{skip}"); sys.exit(0)

print("no simple transform matched — body is real crypto (AES/etc). Need RE of libil2cpp/libNetHTProtect.")
