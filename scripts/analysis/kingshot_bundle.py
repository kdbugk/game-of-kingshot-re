#!/usr/bin/env python3
"""FULL UnityFS extractor for Kingshot bundles (custom ver=8 + BlockInfoNeedPaddingAtStart).
Reconstructs the uncompressed bundle stream, then UnityPy parses the CAB assets.
Usage: kingshot_bundle.py <apk> <entry> <out.bin>"""
import zipfile, struct, lz4.block, sys

def extract_bundle(d):
    class R:
        def __init__(s, b): s.b, s.p = b, 0
        def cstr(s):
            e = s.b.index(b"\0", s.p); v = s.b[s.p:e]; s.p = e + 1; return v
        def u32(s): v = struct.unpack_from(">I", s.b, s.p)[0]; s.p += 4; return v
        def i32(s): v = struct.unpack_from(">i", s.b, s.p)[0]; s.p += 4; return v
        def u64(s): v = struct.unpack_from(">Q", s.b, s.p)[0]; s.p += 8; return v
        def u16(s): v = struct.unpack_from(">H", s.b, s.p)[0]; s.p += 2; return v
        def align(s, n): s.p = (s.p + n - 1) & ~(n - 1)
    r = R(d)
    sig = r.cstr()
    assert sig == b"UnityFS", sig
    ver = r.u32(); uv = r.cstr(); gr = r.cstr()
    size = r.u64(); csize = r.u32(); usize = r.u32(); flags = r.u32()
    r.align(16)
    comp = flags & 0x3F
    raw = d[r.p:r.p + csize]
    if comp in (2, 3):
        bi = lz4.block.decompress(raw, usize)
    elif comp == 0:
        bi = raw
    elif comp == 1:
        import lzma
        bi = lzma.decompress(raw)
    else:
        raise ValueError(f"comp {comp}")
    br = R(bi); br.p = 16
    nblocks = br.i32()
    blocks = [(br.u32(), br.u32(), br.u16()) for _ in range(nblocks)]
    nodes = []
    nn = br.i32()
    for _ in range(nn):
        off = br.u64(); sz = br.u64(); fl = br.u32(); path = br.cstr()
        nodes.append((off, sz, fl, path))
    p = r.p + csize
    if flags & 0x200:  # BlockInfoNeedPaddingAtStart (new semantics)
        p = (p + 15) & ~15
    out = bytearray()
    for usz, csz, bf in blocks:
        blk = d[p:p + csz]; p += csz
        bcomp = bf & 0x3F
        if bcomp in (2, 3):
            out += lz4.block.decompress(blk, usz)
        elif bcomp == 0:
            out += blk
        elif bcomp == 1:
            import lzma
            out += lzma.decompress(blk)
        else:
            raise ValueError(f"block comp {bcomp}")
    return bytes(out), nodes

if __name__ == "__main__":
    apk, entry, out = sys.argv[1], sys.argv[2], sys.argv[3]
    d = zipfile.ZipFile(apk).read(entry)
    data, nodes = extract_bundle(d)
    open(out, "wb").write(data)
    print(f"{entry.split('/')[-1][:50]}: {len(data):,} bytes, {len(nodes)} nodes")
    for off, sz, fl, path in nodes[:6]:
        print(f"  node {path.decode()[:60]} off=0x{off:x} sz={sz}")
