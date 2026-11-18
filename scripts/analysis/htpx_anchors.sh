#!/bin/bash
# HTPX anchor triage — both libil2cpp versions
L114=~/work/apk/xapk/native_extract/lib/arm64-v8a/libil2cpp.so
L195=~/work/apk/xapk195/native_extract/lib/arm64-v8a/libil2cpp.so
NP=~/work/apk/xapk/native_extract/lib/arm64-v8a/libNetHTProtect.so
for f in "$L195" "$L114" "$NP"; do
  echo "═══════ $(basename $(dirname $(dirname $(dirname $f))))/$(basename $f) ═══════"
  strings -a "$f" | grep -aiE "htpx|global.?metadata|metadata.*decrypt|decrypt.*metadata" | sort -u | head -25
  echo "--- exports il2cpp/metadata ---"
  readelf --dyn-syms "$f" 2>/dev/null | grep -iE "il2cpp_init|metadata" | head -8
done
echo "═══════ constante 0x58505448 (HTPX LE) no código? ═══════"
for f in "$L195" "$L114"; do
  n=$(objdump -d "$f" 2>/dev/null | grep -c "58505448")
  echo "$(basename $f): $n ocorrências em instruções"
done
