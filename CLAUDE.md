# Context for AI-Assisted Sessions

This file gives Claude (or any AI assistant) the full context needed to contribute to this project without re-deriving everything from scratch.

---

## Project Goal

Educational reverse engineering of `com.run.tower.defense` (Game of Thrones: Conquest).  
No live exploitation. Focus: understand architecture, protocol, and SDK behavior.

---

## Device & Environment

| Item | Value |
|---|---|
| Device | Motorola moto g(8) — codename `rav`, SDM665 |
| Android | 11 (RPJS31.Q4U-47-35-17) |
| Root | Magisk 30.7 + Zygisk |
| Architecture | ARM64 |
| Frida server | `fs17` at `/data/local/tmp/fs17`, port `37555` |
| ADB forward | `adb forward tcp:37555 tcp:37555` |
| mitmproxy port | `8081` |
| PC local IP | `192.168.0.84` (may change — verify before running proxy scripts) |

---

## What Is Already Known — Do Not Re-Derive

### Gateway Protocol (port 30101)

- Framing: `uint16_BE(length)` + body. Length does NOT include itself.
- Body byte `[0]` = opcode, byte `[1]` = direction (`0x01`=S→C, `0x02`=C→S)
- Remaining bytes: custom varint encoding (NOT standard protobuf wire format)
- **Not TLS** — fully readable via tcpdump

Opcodes confirmed: `0x55` handshake, `0x5d` game message, `0x1d` state sync, `0x15` heartbeat, `0x59` client ACK  
Opcodes unknown: `0x7d`, `0x35` (C→S, battle-specific?), `0x0d` (S→C, rare)

### Coordinate Encoding

4-char ASCII85-like strings: `value = sum((char-33) * 85^i)`, `kingdom = value>>16`, `pos = value&0xffff`  
Suffix: `@` = global map coord, `$` = sub-object reference

### SSL Pinning

- Java layer (OkHttp + TrustManager): **bypassed** by Objection `android sslpinning disable`
- IL2CPP layer (BestHTTP `DefaultCertificationValidator`): RVA `0x269ef4c` — `retval.replace(ptr(1))` to bypass
- Process is killed by libnesec ~58s after Frida attach, before full login completes

### libnesec Anti-Tampering

- `nesec_acao_kill` offset `0x3a6168` — patch to ARM64 `RET` (`c0 03 5f d6`)
- `nesec_nivel_deteccao` offset `0x0f54c` — hook `onLeave`, `retval.replace(ptr(0))`
- **Warning:** these two patches are not sufficient — additional kill sites exist elsewhere

### libil2cpp.so Key RVAs

```
DefaultCertificationValidator : 0x269ef4c
ButtonEx.OnPointerClick       : 0x23bed78
ButtonEx.set_interactable     : 0x23bec54
Button.Press                  : 0x3c105bc
ClickListener.Click           : 0x23a139c
Object.get_name               : 0x3b5e8f4
Component.get_gameObject      : 0x3b56c18
```

### Ghidra Base Address

All libraries: `0x100000`. Conversion: `offset = ghidra_addr - 0x100000`

---

## Known Identifiers (from captures)

```
user_id (pre-login):   384601255
game_user_id:          40444746
android_id:            74fa727661b82eff
gaid:                  a377dc79-01a3-4427-bdff-265b4d690b58
sdk_distinct_id:       8c5b8051660a0e60b1b4a39716e02ba6
kingdom:               931
app_version:           1.9.5
session_token:         OEGFLbwPPabuxrSMmrqxyValDSbmQjLjOp8Ze3428BoU1rfR
```

---

## Open Work Items (Good Starting Points)

1. **Find libnesec kill sites** — hook `kill()` and `pthread_kill()` in libc to trace all callers
2. **Decode `0x7d` and `0x35` opcodes** — capture during active battle, diff against idle session
3. **Decode `0x1d` large frame structure** — compare two sessions with different game state to identify changed fields
4. **il2cppdumper** — extract `global-metadata.dat` from APK and run il2cppdumper to get all method names with RVAs
5. **Ghidra: find message dispatcher** — search for switch/compare on opcode values `0x1d`, `0x5d`, `0x55`
6. **Capture ilivedata.com:1337** — alliance/chat real-time messaging, not yet captured
7. **Identify the 27B HMAC in `0x59` frames** — find what inputs produce `Yuoo0N3p7nDUsi8hmNhCUW6UAO6mHsoxoeNg==`

---

## Frida Scripting Notes

- Always use **spawn mode** (`device.spawn` + `device.resume`) — attach mode misses early init
- `Java.perform()` **cannot** be called at script top-level in spawn mode — JVM not ready yet. Poll `Java.available` in a `setInterval`
- IL2CPP string layout: `+0x00` vtable ptr, `+0x10` int32 length, `+0x14` UTF-16 chars
- libnesec is loaded ~1-2s after spawn — scripts that hook it must poll for `Process.findModuleByName('libnesec.so')`

---

## Capture Files

| File | Contents |
|---|---|
| `captures/battle.pcap` | Gateway session 1 — 360 packets, 2 streams |
| `captures/battle2.pcap` | Gateway session 2 — 760 packets, richer (more opcodes, JSON fragments) |

Both contain: handshake, state sync, battle data (atk_uid, def_uid, Bellona alliance, SpartansFarm).  
`battle2.pcap` additionally contains: `0x59` HMAC frame, `0x7d`/`0x35` unknown opcodes, coordinate strings.
