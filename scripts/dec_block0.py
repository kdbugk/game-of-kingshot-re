#!/usr/bin/env python3
"""Decifrador do bloco 0 de bundles (libunity_114.so F_01412580 @0x1412580) em Python puro.
Porta da analise Ghidra + disassembly (capstone) da jumptable 0x14131c0.
uso: dec_block0.py in.bin out.bin   |  import: decrypt_block0(buf, size=None) -> (ret, bytes)
Sem unicorn. Rota suportada: bundle "EE DD <u16>" (a do corpus). Rotas UnityFS/HTP8 nao portadas.
"""
import struct, sys
M = 0xFFFFFFFF
POLY, P1, P2 = 0x04C11EB7, 0x10, 0x82D63B78

def _crc_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8): c = ((c >> 1) ^ POLY) if c & 1 else (c >> 1)
        t.append(c)
    return t
T = _crc_table()

def key_derivation(w3, w1, w4, L, w2):
    """K = CRC32-variante sobre (w3,w1,w4,L,w2), 4 bytes LE cada."""
    crc = M
    for w in (w3, w1, w4, L & M, w2):
        for sh in (0, 8, 16, 24):
            crc = (((T[(crc ^ (w >> sh)) & 0xFF] ^ (crc >> 8)) + P1)) & M
    return (P2 + ((~crc) & M)) & M

def rc4_ks(key4, n):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key4[i & 3]) & 0xFF; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray(n)
    for q in range(n):
        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF; S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        out[q] = ((((k >> 2) | (k << 6)) & 0xFF) + 0x3A) & 0xFF
    return out

def u32(b, o): return struct.unpack_from('<I', b, o)[0]
OK_U16 = {0x2017, 0x2018, 0x2019, *range(0x2020, 0x2029), 0x6000, 0x7000, 0x8000, 0x9000}

def locate(b, size):
    """Fase A: acha 'EE DD u16' (<0x48), reescreve versao, devolve (hdr_off, shift, Lraw) ou None. Altera b in-place."""
    for p in range(0x48):
        if b[p] != 0xEE or b[p+1] != 0xDD: continue
        u = b[p+2] | b[p+3] << 8
        if u not in OK_U16: continue
        p4, p6 = b[p+4], b[p+6]
        if p4 == 0x2E or p6 == 0x2E: L = 0
        elif p4 == 0xAA and p6 == 0xBB: L = 0x1000
        else: L = p6 + p4 * 16
        hi = u >> 8
        b[p] = (hi >> 4) | 0x30; b[p+1] = (hi & 15) | 0x30
        b[p+2] = ((u >> 4) & 15) | 0x30; b[p+3] = (u & 15) | 0x30
        # FUN_01412300 assumido == -1 (confirmado no corpus)
        z9 = b[p+9]
        if 0x31 <= z9 <= 0x32:
            z = b[p+8]; b[p+8] = 0x66
        else: z = 0
        if 0x31 <= b[p+10] <= 0x32:
            b[p+9] = 0x66; z = z9
        a = z + 0xB
        if z == p or z == 0:
            m = 0x30 if p < 0x20 else 0x40
            off = shift = max(a, m)
        else:
            m = 0x30 if z < 0x20 else 0x40
            a = max(a, m)
            if p < z: off, shift = a - z + p, a
            else: off = shift = a
        b[p+4] = 0x2E; b[p+6] = 0x2E
        return off, shift, L
    return None

def decrypt_block0(buf, size=None):
    b = bytearray(buf)
    size = min(len(b) if size is None else size, 0x1000)
    if size < 0x30: return 0, bytes(b)
    loc = locate(b, size)
    if loc is None: return 0, bytes(b)
    off, shift, L = loc
    if L == size or L - 1 > 0xFFF or L == 0: L = size
    L = min(L, 0x1000); ret = L
    Lp = (L - shift) & M
    w = struct.unpack_from('<5I', b, off)
    K = key_derivation(w[3], w[1], w[4], Lp, w[2])
    T4 = [((u32(b, off+0x14) + 0x1985) & M) ^ K, ((u32(b, off+0x1c) + 0x1981) & M) ^ K,
          K ^ ((Lp + 0x2013) & M), ((u32(b, off+0x18) + 0x2018) & M) ^ K]
    for i in range(0x20): b[off+i] ^= 0xA6
    key = struct.pack('<I', K)
    h = off + 0x20
    if Lp < 0xA0:
        n = Lp - 0x20
        if n > 0:
            ks = rc4_ks(key, n)
            for i in range(n): b[h+i] ^= ks[i]
        return ret, bytes(b)
    enc = bytes(b[h:h+0x80])                        # copia cifrada (local_228)
    ks = rc4_ks(key, 0x80)
    for i in range(0x80): b[h+i] ^= ks[i]           # 1o RC4 (chave K) decifra in-place
    ks2 = rc4_ks(struct.pack('<I', T4[2]), 0x80)    # 2o RC4: chave = T4[2] (K^(L+0x2013)) sobre a copia -> H'
    H = struct.unpack('<32I', bytes(x ^ y for x, y in zip(enc, ks2)))
    K9 = [0x571, T4[3], 0x892, 0x750, T4[0], T4[1], 0x746, T4[2], 0x568]
    r = Lp - 0xA0
    pos = off + 0xA0
    nb = r >> 7
    for n in range(nb):
        cls = K9[n % 9] & 3
        out = []
        for i in range(32):
            c = u32(b, pos + 4*i); Hi = H[i]; m9 = i % 9
            if cls == 0:   v = c ^ (0x20 - i) ^ Hi ^ K9[m9]
            elif cls == 1: v = c ^ Hi ^ T4[Hi & 3]
            elif cls == 2: v = c ^ i ^ Hi ^ T4[Hi & 3]
            else:          v = c ^ Hi ^ i ^ T4[K9[m9] & 3]
            out.append(v & M)
        struct.pack_into('<32I', b, pos, *out)
        pos += 0x80
    hb = struct.pack('<32I', *H)
    for k in range(r & 0x7F):
        wq = K9[T4[k & 3] % 9]
        wq = (wq + ((wq * 0x80808081) >> 39)) & M
        b[pos+k] ^= hb[k] ^ k ^ (wq & 0xFF)
    return ret, bytes(b)

if __name__ == '__main__':
    raw = open(sys.argv[1], 'rb').read()
    r, out = decrypt_block0(raw[:0x1000])
    open(sys.argv[2], 'wb').write(out + raw[0x1000:]); print('ret', hex(r))
