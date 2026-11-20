#!/usr/bin/env python3
"""HTPX global-metadata.dat decryptor — reimplementation of libunity.so FUN @0x1447040 (Unity 'Tower' build).
usage: htpx_decrypt.py in.dat out.dat   |  keystream(): derive the 1152B periodic keystream
"""
import struct, sys
M = 0xFFFFFFFF
POLY, P1, P2 = 0x04C11EB7, 0x10, 0x82D63B78   # 12-byte blob in libunity .rodata (0x13ee328 + imm 0x82d63b78)
def crc_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8): c = ((c >> 1) ^ POLY) if c & 1 else (c >> 1)
        t.append(c)
    return t
T = crc_table()

def key_from_len(n):          # w26
    w = T[(~n) & 0xFF] ^ 0xFFFFFF; w = (w + P1) & M
    for sh in (8, 16):
        w = ((T[(w ^ (n >> sh)) & 0xFF] ^ (w >> 8)) + P1) & M
    w = ((T[((w & 0xFF) ^ (n >> 24)) & 0xFF] ^ (w >> 8)) + P1) & M
    return (P2 + ((~w) & M)) & M

def rc4_stream(key4, n):      # RC4 w/ 4-byte key (identity S0); out byte = ror8(K,2)+0x3a
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key4[i & 3]) & 0xFF; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for _ in range(n):
        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF; S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        out.append(((((k >> 2) | (k << 6)) & 0xFF) + 0x3A) & 0xFF)
    return out

def u32(b, o): return struct.unpack_from("<I", b, o)[0]

def derive(raw):
    L = len(raw); assert raw[:4] == b"HTPX" and u32(raw, 4) == L
    n = L - 8; w26 = key_from_len(n)
    w8 = u32(raw, 0x20); w9 = w8 ^ w26
    Hraw = bytearray(raw[8:8 + 128])
    ks = rc4_stream(struct.pack("<I", w9), 128)
    H = bytes(a ^ b for a, b in zip(Hraw, ks))
    h = lambda o: u32(H, o)
    w13 = ((u32(raw, 0x54) + 0x75000 + 0x568) & M)
    w14 = ((h(0x3C) + 0xA74000 + 0x98D) & M)
    w15 = ((h(0x2C) + 0x348000 + 0x2A5) & M)
    w12 = ((u32(raw, 0x28) + 0x81000 + 0x95E) & M)
    w13 ^= w9; w15 ^= w26; w9n = w14 ^ w9
    T4 = [0, 0, w15, w9n]
    w9n ^= 0x0034E00E
    w12 ^= w26
    w17 = h(0x0C) ^ 0x03914F13
    w15b = w9n ^ w15
    T4[0], T4[1] = w12, w13
    w13b = w13 ^ 0x00836E4C
    w14 = h(0x1C) ^ w17
    w16 = h(0x20) ^ w15b
    w12b = w13b ^ w12
    K9 = [w17, w9n, w14, w16, w12b, w13b, u32(raw, 0x18) ^ 0x031BB9B1, w15b, w12b ^ w8]
    hdr_ks = rc4_stream(struct.pack("<I", w26), 128)
    hdr = bytes(a ^ b for a, b in zip(raw[8:8 + 128], hdr_ks))
    return dict(n=n, w26=w26, H=H, T4=T4, K9=K9, hdr=hdr)

JT = {0: 'A', 1: 'D', 2: 'B', 3: 'C'}
def block_ks(st, idx):  # keystream (XOR mask) for the 128B block with index idx (idx mod 9 selects the class)
    H, T4, K9 = st['H'], st['T4'], st['K9']
    cls = JT[K9[idx % 9] & 3]; out = bytearray()
    for i in range(32):
        Hi = u32(H, 4 * i)
        if cls == 'A': v = i ^ Hi ^ T4[Hi & 3]
        elif cls == 'B': v = (0x20 - i) ^ Hi ^ K9[((i * 0x39) & M) // 512 and (i - 9 * (((i * 0x39) & M) >> 9)) or (i - 9 * (((i * 0x39) & M) >> 9))]
        elif cls == 'C': v = Hi ^ T4[Hi & 3]
        else: v = i ^ Hi ^ T4[K9[i - 9 * (((i * 0x39) & M) >> 9)] & 3]
        out += struct.pack("<I", v & M)
    return bytes(out), cls

def keystream1152(st):
    """returns 1152B indexed by (body offset mod 1152), i.e. lane-I convention (body block 1 = decrypt block 0)."""
    ks = bytearray(1152)
    ks[0:128] = b"\0" * 128           # body block 0 = header, not periodic
    for b in range(9):
        blk, cls = block_ks(st, b)
        pos = ((b + 1) % 9) * 128
        ks[pos:pos + 128] = blk
    return bytes(ks)

def decrypt(raw):
    st = derive(raw); n = st['n']; out = bytearray(raw)
    out[8:136] = st['hdr']
    nblk = (len(raw) - 0x88) // 128
    for b in range(nblk):
        ksb, cls = block_ks(st, b)
        o = 136 + 128 * b
        out[o:o + 128] = bytes(x ^ y for x, y in zip(raw[o:o + 128], ksb))
    # tail
    rem = n & 0x7F; start = 8 + (n & ~0x7F)
    for k in range(rem):
        q = st['T4'][k & 3] % 9
        w = st['K9'][q]
        v = raw[start + k] ^ (k & 0xFF) ^ st['H'][k]
        w16 = (w + ((w * 0x80808081) >> 39)) & M
        out[start + k] = (v ^ w16) & 0xFF
    return bytes(out), st

if __name__ == "__main__":
    raw = open(sys.argv[1], "rb").read()
    out, st = decrypt(raw)
    open(sys.argv[2], "wb").write(out)
    print("hdr", out[8:24].hex(), "w26=%08x" % st['w26'], "K9", [hex(x) for x in st['K9']])
