#!/bin/bash
# lab_gm.sh — sobe o mock v4+GM, roda o console GM, mostra os dois lados, desce o mock
cd /home/re/work/apk
pkill -9 -f "[m]ock_v4" 2>/dev/null
sleep 1
python3 -u mock_v4.py --port 30101 > mock_gm.log 2>&1 &
MPID=$!
sleep 3
python3 gm_console.py
echo
echo "======= LADO DO SERVIDOR (mock_gm.log) ======="
grep GM mock_gm.log || tail -6 mock_gm.log
kill $MPID 2>/dev/null
true
