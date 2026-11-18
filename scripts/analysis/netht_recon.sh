#!/bin/bash
# libNetHTProtect recon: exports, crypto strings, version diff
NP114=~/work/apk/xapk/native_extract/lib/arm64-v8a/libNetHTProtect.so
NP195=~/work/apk/xapk195/native_extract/lib/arm64-v8a/libNetHTProtect.so
echo "═══ diff 1.9.5 vs 1.14.27 ═══"
md5sum "$NP114" "$NP195" 2>/dev/null
echo; echo "═══ EXPORTS (dynsym defined) 1.14.27 ═══"
readelf --dyn-syms -W "$NP114" | awk '$7!="UND" && $8!="" {print $8}' | grep -v "^$" | sort -u | head -40
echo; echo "═══ STRINGS cripto/HTPX (1.14.27) ═══"
strings -a "$NP114" | grep -aiE "htpx|aes|rsa|sha1|sha256|md5|crypt|decrypt|key|metadata|unpack|lz4|xz$|zstd|magic|htprotect|nesec" | sort -u | head -50
echo; echo "═══ STRINGS 1.9.5 diff (só para comparar) ═══"
diff <(strings -a "$NP114" | sort -u) <(strings -a "$NP195" | sort -u) | head -30
