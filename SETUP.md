# Environment Setup

Everything you need to reproduce this analysis environment from scratch.

---

## Hardware

| Component | Used in This Project |
|---|---|
| Android device | Motorola moto g(8) — codename `rav`, SDM665 |
| Android version | 11 (RPJS31.Q4U-47-35-17) |
| Root | Magisk 30.7 + Zygisk |
| Architecture | ARM64 (AArch64) |
| PC OS | Windows 11 (scripts work on Linux/macOS too) |

Any rooted ARM64 Android 8+ device should work.

---

## 1. PC Dependencies

```bash
pip install frida-tools        # frida, frida-ps, frida-trace
pip install mitmproxy          # mitmdump, mitmweb
pip install objection          # objection CLI
```

Verify:
```bash
frida --version                # 16.x or 17.x
mitmdump --version
objection --version
```

---

## 2. Frida Server on Device

Download the frida-server matching your `frida-tools` version from:
https://github.com/frida/frida/releases

```bash
# push and start (we rename it fs17 for frida 17.x)
adb push frida-server-17.x.x-android-arm64 /data/local/tmp/fs17
adb shell "su -c 'chmod +x /data/local/tmp/fs17'"

# start (run this before every session)
adb shell "su -c '/data/local/tmp/fs17 -l 0.0.0.0:37555 &'"

# forward port to PC
adb forward tcp:37555 tcp:37555

# verify
frida-ps -H 127.0.0.1:37555
```

---

## 3. mitmproxy CA on Device

Required once per device (re-run after factory reset):

```bash
python scripts/proxy/mitm_setup.py
```

This script:
1. Starts `mitmdump` temporarily to generate the CA certificate
2. Pushes it to the device
3. Installs it as a system CA (requires root)

Then configure the device WiFi proxy:
- **Host:** your PC's local IP (e.g. `192.168.0.84`)
- **Port:** `8081`

---

## 4. tcpdump on Device

For gateway traffic (port 30101) — no proxy needed:

```bash
# verify tcpdump is available
adb shell "su -c 'which tcpdump'"

# if missing, push a static binary
# download from: https://github.com/extremecoders-re/tcpdump-android-builds
adb push tcpdump /data/local/tmp/
adb shell "su -c 'chmod +x /data/local/tmp/tcpdump'"
```

---

## 5. Ghidra

Download from https://ghidra-sre.org/

Import settings for `libil2cpp.so`:
- Language: `ARM v8 LE (AARCH64)`
- Base address: `0x100000`

Address conversion formula:
```
offset      = ghidra_addr - 0x100000
runtime_addr = runtime_base + offset
ghidra_addr  = 0x100000 + (runtime_addr - runtime_base)
```

Known runtime bases (ASLR — varies per boot):
| Library | Example base |
|---|---|
| `libil2cpp.so` | `0x71012e1000` |
| `libnesec.so` | `0x716ff83000` |
| `libNetHTProtect.so` | `0x7129e4c000` |

Read current bases:
```bash
adb shell "su -c 'cat /proc/$(pidof com.run.tower.defense)/maps'" | grep "\.so"
```

---

## 6. il2cppdumper (Recommended Next Step)

Recovers all C# class/method names with RVAs from the IL2CPP binary:

```bash
# extract files from installed APK
adb shell "su -c 'cp /data/app/com.run.tower.defense-*/base.apk /sdcard/base.apk'"
adb pull /sdcard/base.apk

# unzip
unzip base.apk lib/arm64-v8a/libil2cpp.so -d apk_extracted/
unzip base.apk assets/bin/Data/Managed/Metadata/global-metadata.dat -d apk_extracted/

# run il2cppdumper
# https://github.com/Perfare/Il2CppDumper
Il2CppDumper.exe apk_extracted/lib/arm64-v8a/libil2cpp.so \
                 apk_extracted/assets/bin/Data/Managed/Metadata/global-metadata.dat \
                 output/

# search for gateway/network handlers
grep -i "gateway\|socket\|receive\|opcode\|packet" output/dump.cs
```

---

## 7. Running a Capture Session

```bash
# Terminal 1 — start frida-server
adb shell "su -c '/data/local/tmp/fs17 -l 0.0.0.0:37555 &'"
adb forward tcp:37555 tcp:37555

# Terminal 2 — capture gateway traffic
adb shell "su -c 'tcpdump -i any -w /sdcard/session.pcap port 30101'"

# Terminal 3 (optional) — capture HTTP analytics traffic
mitmdump --listen-host 0.0.0.0 --listen-port 8081 --ssl-insecure -w session.mitm

# Play the game. When done:
# Ctrl+C on terminal 2 and 3

# Pull captures
adb pull /sdcard/session.pcap captures/
```

Then analyze:
```bash
python scripts/analysis/analyze_gateway.py captures/session.pcap
python scripts/analysis/analyze_mitm.py session.mitm
```
