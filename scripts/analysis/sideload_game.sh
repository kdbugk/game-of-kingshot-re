#!/bin/bash
# Sideload Kingshot 1.14.27 XAPK splits via Wi-Fi adb
cd ~/work/apk/xapk
LOG=~/work/apk/sideload.log
{
  date
  ls -la *.apk
  echo "=== install-multiple começou ==="
  adb install-multiple --user 0 com.run.tower.defense.apk config.arm64_v8a.apk game_asset.apk
  echo "=== exit=$? ==="
  adb shell pm path com.run.tower.defense
  adb shell dumpsys package com.run.tower.defense | grep -E "versionName|versionCode" | head -2
} > "$LOG" 2>&1
