# got-re — Reverse Engineering: Game of Thrones: Conquest (Android)

> **Educational project.** The goal is to understand how a modern Unity/IL2CPP Android game communicates, how its native protection SDKs work, and how to apply static + dynamic analysis techniques to a real-world APK.

---

## What This Is

This repository documents an ongoing reverse engineering study of **com.run.tower.defense** (Game of Thrones: Conquest), a Unity game with IL2CPP runtime, multiple native protection SDKs, and a custom binary gateway protocol.

No cheating, no exploitation, no modification of live game data. The focus is purely on understanding internal architecture.

---

## What We Found

| Area | Status | Key Finding |
|---|---|---|
| Gateway protocol (port 30101) | **Decoded** | Custom binary, `uint16_BE` framing, varint body, no TLS |
| Opcodes | **Mapped** | `0x55` handshake, `0x5d` game actions, `0x1d` state sync, `0x15` heartbeat, `0x59` client ACK |
| Coordinate encoding | **Decoded** | ASCII85-like 4-char → uint32 (x=kingdom, y=position) |
| Analytics API | **Captured** | `logagent-wf.centurygame.com` — JSON events, not pinned |
| SSL pinning | **Partially bypassed** | Java layer bypassed (OkHttp + TrustManager); native BestHTTP layer identified |
| Anti-tampering (libnesec) | **Identified** | Kills process ~58s after Frida attach; kill function and detection level mapped |
| libxt_a64.so | **Identified** | PLT hooking SDK loaded in isolated linker namespace — invisible to Frida/maps |
| libNetHTProtect.so | **Analyzed** | Network integrity SDK; MD5 fingerprinting; protobuf-style serialization |
| IL2CPP dump | **Partial** | Assembly list recovered; BestHTTP certval RVA mapped |

---

## Repository Structure

```
got-re/
├── README.md                   ← this file
├── FLOW.md                     ← complete discovered data flow
├── SETUP.md                    ← environment setup guide
├── TOOLS_AND_COMMANDS.md       ← all commands and tools reference
├── CLAUDE.md                   ← context for AI-assisted sessions
├── captures/
│   ├── battle.pcap             ← gateway traffic sample (session 1)
│   └── battle2.pcap            ← gateway traffic sample (session 2, richer)
└── scripts/
    ├── frida/
    │   ├── certval_hook.js     ← observe BestHTTP certificate validation
    │   ├── button_hook.js      ← hook Unity UI button events
    │   ├── ssl_unpin.js        ← SSL unpinning (Java + IL2CPP layers)
    │   └── nesec_bypass.js     ← neutralize libnesec anti-tampering
    ├── analysis/
    │   ├── analyze_gateway.py  ← parse and decode port 30101 pcap captures
    │   ├── analyze_mitm.py     ← read and filter mitmproxy .mitm files
    │   ├── decode_1d_v2.py     ← deep decode of 0x1d state-sync frames
    │   └── deep_analysis.py    ← coordinates, JSON fragments, opcode 0x59
    └── proxy/
        ├── mitm_setup.py       ← install mitmproxy CA on device
        ├── run_ssl_unpin.py    ← mitmdump + Frida SSL unpin combined runner
        └── run_button_hook.py  ← mitmdump + Frida button hook combined runner
```

---

## Quick Start

```bash
# 1. Start frida-server on device
adb shell "su -c '/data/local/tmp/fs17 -l 0.0.0.0:37555 &'"
adb forward tcp:37555 tcp:37555

# 2. Capture gateway traffic
adb shell "su -c 'tcpdump -i any -w /sdcard/session.pcap port 30101'"
# ... play the game ...
adb pull /sdcard/session.pcap captures/

# 3. Analyze it
python scripts/analysis/analyze_gateway.py captures/session.pcap
```

---

## Interested in Contributing?

See [FLOW.md](FLOW.md) for the full protocol map and open questions.  
See [SETUP.md](SETUP.md) to get your environment running.

If you have Ghidra analysis, il2cppdumper output, or additional pcap captures — PRs and issues are welcome.
