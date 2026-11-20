#!/bin/bash
# start_mock.sh — sobe o mock_v4 (com fixture) e DEIXA RODANDO; log em mock_live.log
cd /home/re/work/apk
pkill -9 -f "[m]ock_v4" 2>/dev/null
sleep 1
nohup python3 -u mock_v4.py --port 30101 > mock_live.log 2>&1 &
sleep 3
if ss -tln | grep -q 30101; then echo MOCK-V4-NO-AR; else echo FALHOU; head -5 mock_live.log; fi
