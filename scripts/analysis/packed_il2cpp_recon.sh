#!/bin/bash
# Packed libil2cpp recon: program headers, init_array, exports, unpacker section
L=~/work/apk/xapk/native_extract/lib/arm64-v8a/libil2cpp.so
echo "═══ program headers ═══"
readelf -lW "$L" 2>/dev/null | grep -E "LOAD|INTERP|INIT" | head -12
echo; echo "═══ dynamic INIT entries ═══"
readelf -dW "$L" 2>/dev/null | grep -iE "INIT|SONAME|NEEDED" | head -12
echo; echo "═══ exports definidos ═══"
readelf --dyn-syms -W "$L" | awk '$7!="UND" && $8!="" {print $8}' | sort -u | head -30
echo; echo "═══ .note.gnu.content (16K, ent 1.37 — legível!) ═══"
python3 - "$L" <<'EOF'
import sys, struct
d = open(sys.argv[1], "rb").read()
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3a)[0]
e_shnum = struct.unpack_from("<H", d, 0x3c)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3e)[0]
shs = []
for i in range(e_shnum):
    off = e_shoff + i*e_shentsize
    name, stype, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", d, off)
    shs.append((name, stype, offset, size))
shstr = shs[e_shstrndx][2]
def sname(n):
    end = d.index(b"\0", shstr+n); return d[shstr+n:end].decode()
for name, stype, offset, size in shs:
    nm = sname(name)
    if nm in (".note.gnu.content", ".note.gnu.ident"):
        blob = d[offset:offset+size]
        print(f"--- {nm} ({size}B) ---")
        print(blob[:600])
EOF
