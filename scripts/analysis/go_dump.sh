#!/bin/bash
# espera jogo -> 45s boot -> dump fixo
for i in $(seq 1 120); do
  P=$(frida-ps -H 127.0.0.1:37555 2>/dev/null | grep -c -i kingshot)
  [ "$P" = "1" ] && break
  sleep 5
done
if [ "$P" != "1" ]; then echo "jogo não apareceu em ~10min"; exit 1; fi
echo "jogo detectado — 45s de boot..."
sleep 45
timeout 620 python3 -u ~/work/apk/waitgame_fixed.py
echo "=== arquivos ==="
ls ~/work/apk/il2cpp_dump_114/ | wc -l
cat ~/work/apk/il2cpp_dump_114_summary.txt 2>/dev/null
