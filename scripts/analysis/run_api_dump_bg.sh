#!/bin/bash
# API dump runner (background, logs to file)
cd ~/projects/game-of-kingshot-re/dump
LOG=~/work/apk/api_dump.log
{
  date
  timeout 900 python3 -u run_il2cpp_api_dump.py
  echo "exit=$?"
  ls -la il2cpp_dump/ | head -5
  du -sh il2cpp_dump
} > "$LOG" 2>&1
