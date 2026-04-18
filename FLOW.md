# Protocol & Data Flow

Complete map of all discovered communication channels and data flows in `com.run.tower.defense`.

---

## 1. App Startup Sequence

```
App launch
  │
  ├── GET https://got-gm-api-formal.chosenonegames.com/api/version/info
  │       ?platform=android&version=1.9.5&kingdom=931&language=pt
  │       (NOT pinned — captured via proxy)
  │       Response: gateway IPs, hotfix URLs, spectator IPs
  │
  ├── POST https://passport-got.centurygame.com/...
  │       (PINNED — SSL certificate pinning active, traffic not captured)
  │       Purpose: login / session token acquisition
  │
  └── TCP connect → got-formal-gateway-*.chosenonegames.com:30101
          Custom binary protocol (see Section 2)
```

---

## 2. Gateway Protocol — Port 30101

### Framing

Every message is framed as:
```
[ uint16_BE length ][ body (length bytes) ]
```
The `length` field does NOT include itself. Body starts immediately after.

### Header Structure (body bytes 0–1)

| Byte | Value | Meaning |
|---|---|---|
| `[0]` | opcode | Message type (see table below) |
| `[1]` | `0x01` or `0x02` | Direction: `0x01` = S→C, `0x02` = C→S |

Remaining bytes are a custom varint-encoded payload (similar to protobuf but without explicit field tags in all frames).

### Opcodes

| Hex | Dec | Direction | Name | Description |
|---|---|---|---|---|
| `0x55` | 85 | Both | **Handshake** | Session establishment; contains token, version, device info |
| `0x5d` | 93 | Both | **Game message** | Player actions (C→S) and game responses (S→C) |
| `0x1d` | 29 | S→C dominant | **State sync** | Server pushing game world state updates |
| `0x15` | 21 | Both | **Heartbeat** | Keep-alive; small 4–6B frames |
| `0x59` | 89 | C→S | **Client ACK** | Client confirmation of server events; some frames carry a 27B custom HMAC |
| `0x0d` | 13 | S→C | **Unknown** | Seen 2×; purpose unknown |
| `0x7d` | 125 | C→S | **Unknown** | 14× in battle2.pcap; possibly real-time battle actions |
| `0x35` | 53 | C→S | **Unknown** | 10× in battle2.pcap |

### Handshake Content (opcode `0x55`, C→S, 204B)

```
token:      OEGFLbwPPabuxrSMmrqxyValDSbmQjLjOp8Ze3428BoU1rfR
user_id:    384601255
version:    1.9.5
device:     motorola moto g(8)
os:         android
lang:       pt
sdk_id:     8c5b8051660a0e60b1b4a39716e02ba6
```

The token is the same across sessions — it is provisioned by the pinned passport endpoint and cached on-device.

### State Sync Frames (`0x1d`)

Three size classes observed:

| Size | Count | Purpose |
|---|---|---|
| ≤30B | 112 | ACKs, simple event notifications |
| 31–200B | 99 | Single entity updates (troop, resource tile, etc.) |
| >200B | 40 | Bulk state dumps (battle history, map sector sync) |

The largest frame observed (3824B) contained ~200 LE-uint32 timestamps spanning July–September 2025 — a full history of player events synchronized on login.

### Coordinate Encoding

Map positions are encoded as 4-character ASCII85-like strings:

```
value = (char[0]-33)*85^3 + (char[1]-33)*85^2 + (char[2]-33)*85^1 + (char[3]-33)*85^0
kingdom  = value >> 16
position = value & 0xffff
```

Examples from captures:
| Encoded | Kingdom | Position | Context |
|---|---|---|---|
| `ZdsX@` | 541 | 41249 | Battle tile (5 occurrences) |
| `931!` | 2 | 43874 | Kingdom ID reference |

Suffix character acts as a field separator: `@` = global map coord; `$` = sub-object reference (troop/farm ID).

### Embedded JSON in Binary Frames

Some `0x1d` frames embed raw JSON objects inside the binary payload:

```json
{"12":true,"13":true,"11":true,"16":true,"10":true,"15":true,"22":true}
```
→ Feature flags (numeric keys = feature IDs unlocked for this player)

```json
{"p_giftid":4000751,"device_lvl":2,"fp_countrycode":"BR"}
```
→ Pending gift ID, server-side device classification, country from network fingerprint

---

## 3. Analytics API — `logagent-wf.centurygame.com`

**Not SSL-pinned.** Captured via mitmproxy without any bypass needed.

Uses OkHttp 4.12.0. All requests are `POST /log` with JSON body.

### Event Types

| Event | When | Key Fields |
|---|---|---|
| `sdk_collection` | Each session start | `faid`, `sdk_distinct_id` (Firebase IDs) |
| `session_start` | App foreground | `user_id`, device info, `level=0`, `vip_level=0` (pre-login) |
| `session_end` | App background/close | `game_user_id=40444746`, `level=1`, `vip_level=5`, `session_length` |
| `launched_gpstore` | Google Play Store opened | Referrer app package |

### Identifiers Observed

| Field | Value | Type |
|---|---|---|
| `user_id` | `384601255` | Pre-login device/account ID |
| `game_user_id` | `40444746` | In-game player ID (only present after login) |
| `android_id` | `74fa727661b82eff` | Android hardware ID |
| `gaid` | `a377dc79-01a3-4427-bdff-265b4d690b58` | Google Advertising ID |
| `session_id` | `a020235000384601255...` | Per-session unique ID |

### URL Signature

Each request URL includes a `signature=` parameter (MD5 of the payload body). Changes per request.

---

## 4. Real-Time Messaging — `ilivedata.com:1337`

Discovered in a `0x1d` frame payload:
```
c02-rtm-intl-frontgate.ilivedata.com:1337
```

Tencent RTM service — used for in-game alliance/kingdom chat. Port **1337** (TCP). Separate connection, not captured yet.

---

## 5. Native SDK Stack

```
libxt_a64.so         (243KB, from assets/motion/libxt3.1.2_a64.so)
  └── loaded via android_dlopen_ext with isolated ClassLoaderNamespace
  └── INVISIBLE to /proc/self/maps and Frida Process.enumerateModules()
  └── reads /proc/self/maps via direct SVC #0 syscall (bypasses libc hooks)
  └── PLT hook monitor

libnesec.so          (1.1MB, NetEase MobSec SDK)
  └── monitors TracerPid via /proc/<tid>/status
  └── kills process ~58s after Frida attach
  └── nesec_acao_kill     offset 0x3a6168
  └── nesec_nivel_deteccao offset 0x0f54c  (returns anomaly level; 0 = normal)

libNetHTProtect.so   (4.9MB)
  └── collects environment fingerprint
  └── MD5 inline (no OpenSSL) — identified by constants 0xd76aa478, 0xe8c7b756
  └── serializes payload protobuf-style via vtable at DAT_005a62e8
  └── delivers to libil2cpp via vtable slot +0x180 (write) / +0x680 (write_final)

libil2cpp.so         (82MB, Unity IL2CPP runtime)
  └── all C# game logic compiled to native ARM64
  └── BestHTTP Pro for HTTPS (SSL-pinned)
  └── DefaultCertificationValidator RVA 0x269ef4c
```

---

## 6. SSL Pinning Map

| Endpoint | Pinned | Method | Notes |
|---|---|---|---|
| `passport-got.centurygame.com` | **Yes** | Native (BestHTTP) | Login/auth — not captured |
| `got-gm-api-formal.chosenonegames.com` | No | — | Version check — captured |
| `logagent-wf.centurygame.com` | No | — | Analytics — captured |
| Gateway port 30101 | N/A | Custom binary (no TLS) | Fully captured via tcpdump |
| `ilivedata.com:1337` | Unknown | — | Not yet captured |

---

## 7. Open Questions

- [ ] Decode the `0x7d` and `0x35` C→S opcodes (battle-specific actions?)
- [ ] Identify inputs to the 27B HMAC in `0x59` frames
- [ ] Bypass libnesec fully (multiple kill sites suspected beyond `nesec_acao_kill`)
- [ ] Capture `ilivedata.com:1337` RTM traffic
- [ ] Recover IL2CPP method names via il2cppdumper + `global-metadata.dat`
- [ ] Find the gateway message dispatcher in Ghidra (search `switch` on `0x1d`/`0x5d`)
- [ ] Decode the bulk 3824B `0x1d` frame structure (history record format)
