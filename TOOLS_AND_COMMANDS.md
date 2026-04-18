# Tools & Commands Reference

Quick reference for every command used in this project.

---

## Device Management

```bash
# check device connected
adb devices

# open root shell
adb shell su

# get process PID
adb shell "pidof com.run.tower.defense"

# view loaded native libraries
adb shell "su -c 'cat /proc/$(pidof com.run.tower.defense)/maps'" | grep "\.so"

# pull file from device
adb pull /sdcard/file.pcap local/path/
```

---

## Frida

```bash
# start frida-server on device (named fs17 = frida 17.x)
adb shell "su -c '/data/local/tmp/fs17 -l 0.0.0.0:37555 &'"

# forward port to PC
adb forward tcp:37555 tcp:37555

# list running processes
frida-ps -H 127.0.0.1:37555

# attach to running app
frida -H 127.0.0.1:37555 -n com.run.tower.defense -l script.js

# spawn (start app fresh with script loaded from the beginning)
frida -H 127.0.0.1:37555 -f com.run.tower.defense -l script.js --no-pause
```

---

## Objection (SSL unpinning)

```bash
# bypass SSL pinning with Java-layer hooks
objection -N --host 127.0.0.1 --port 37555 \
          -n com.run.tower.defense explore \
          --startup-script scripts/frida/nesec_bypass.js \
          --startup-command "android sslpinning disable"
```

Note: use `--port` (long form) to avoid conflict with the `start` subcommand's `-P` flag.

---

## tcpdump (Gateway Traffic)

```bash
# capture gateway traffic (port 30101)
adb shell "su -c 'tcpdump -i any -w /sdcard/session.pcap port 30101'"

# capture everything (larger files)
adb shell "su -c 'tcpdump -i any -w /sdcard/full.pcap'"

# pull capture
adb pull /sdcard/session.pcap captures/
```

---

## mitmproxy

```bash
# start proxy (captures HTTPS without saving to file)
mitmdump --listen-host 0.0.0.0 --listen-port 8081 --ssl-insecure

# save to .mitm file for later analysis
mitmdump --listen-host 0.0.0.0 --listen-port 8081 --ssl-insecure -w session.mitm

# replay / inspect saved file (CLI)
mitmdump --rfile session.mitm

# inspect saved file in browser UI
mitmweb --rfile session.mitm
# then open http://127.0.0.1:8081
```

---

## Analysis Scripts

```bash
# decode gateway pcap (port 30101 traffic)
python scripts/analysis/analyze_gateway.py captures/session.pcap

# inspect mitmproxy capture
python scripts/analysis/analyze_mitm.py session.mitm

# filter by URL substring
python scripts/analysis/analyze_mitm.py session.mitm --filter logagent
python scripts/analysis/analyze_mitm.py session.mitm --filter centurygame

# deep decode 0x1d state-sync frames
python scripts/analysis/decode_1d_v2.py
# (edit file path at top before running)

# full protocol analysis (coordinates, JSON, opcode 0x59)
python scripts/analysis/deep_analysis.py
```

---

## Combined Runners (Frida + mitmproxy)

```bash
# SSL unpin + HTTP capture
python scripts/proxy/run_ssl_unpin.py
# output: unpin_<ts>.log, http_<ts>.log, http_<ts>.mitm

# Button hooks + HTTP capture
python scripts/proxy/run_button_hook.py
# output: button_events_<ts>.log, http_traffic_<ts>.log, http_traffic_<ts>.mitm
```

Before running either script, edit the config block at the top:
```python
APP_ID       = "com.run.tower.defense"
FRIDA_HOST   = "127.0.0.1:37555"
PROXY_HOST   = "192.168.0.84"     # your PC's local IP
PROXY_PORT   = 8081
MITMDUMP_EXE = r"C:\path\to\mitmdump.exe"
```

---

## Frida Scripts (standalone)

```bash
# hook BestHTTP certificate validator — observe SSL decisions
frida -H 127.0.0.1:37555 -f com.run.tower.defense \
      -l scripts/frida/certval_hook.js --no-pause

# hook Unity button clicks — log UI interactions
frida -H 127.0.0.1:37555 -f com.run.tower.defense \
      -l scripts/frida/button_hook.js --no-pause

# full SSL unpin attempt (Java + IL2CPP layers)
frida -H 127.0.0.1:37555 -f com.run.tower.defense \
      -l scripts/frida/ssl_unpin.js --no-pause

# neutralize libnesec anti-tampering
# (usually loaded alongside another script, not standalone)
frida -H 127.0.0.1:37555 -f com.run.tower.defense \
      -l scripts/frida/nesec_bypass.js --no-pause
```

---

## Address Conversion (Ghidra ↔ Runtime)

```
offset       = ghidra_addr  - 0x100000
runtime_addr = runtime_base + offset
ghidra_addr  = 0x100000     + (runtime_addr - runtime_base)
```

Example for `libil2cpp.so` base `0x71012e1000`:
```
certval RVA 0x269ef4c → offset 0x169ef4c → runtime 0x71179d04c
```

---

## Key Known RVAs (libil2cpp.so)

| Symbol | RVA | Notes |
|---|---|---|
| `DefaultCertificationValidator` | `0x269ef4c` | BestHTTP SSL bypass target |
| `ButtonEx.OnPointerClick` | `0x23bed78` | Unity UI button click |
| `ButtonEx.set_interactable` | `0x23bec54` | Button enable/disable |
| `Button.Press` | `0x3c105bc` | Core button press |
| `ClickListener.Click` | `0x23a139c` | Alternative click handler |
| `Object.get_name` | `0x3b5e8f4` | Get GameObject name |
| `Component.get_gameObject` | `0x3b56c18` | Get parent GameObject |

## Key Known Offsets (libnesec.so)

| Symbol | Offset | Notes |
|---|---|---|
| `nesec_acao_kill` | `0x3a6168` | Process termination after detection |
| `nesec_nivel_deteccao` | `0x0f54c` | Returns anomaly level (0 = normal) |
| `nesec_loop_tracerpid_A` | `0x2e2339c` | TracerPid monitor thread |
| `nesec_loop_tracerpid_B` | `0x2e33494` | Redundant TracerPid monitor |

## Key Known Offsets (libNetHTProtect.so)

| Symbol | Offset | Notes |
|---|---|---|
| `nethtp_engine_central` | `0x23d5a0` | Main engine — validates params, picks pipeline |
| `nethtp_pipeline_coleta` | `0x9ed9c` | Fingerprint collection + MD5 hashes |
| `nethtp_marshal_payload` | `0x23acfc` | Serializes result, delivers to IL2CPP |
