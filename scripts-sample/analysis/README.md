# Analysis Scripts

Python scripts for offline analysis of captured traffic. No device needed.

---

## analyze_gateway.py

**Purpose:** Parse and decode pcap files containing port 30101 gateway traffic.

**Usage:**
```bash
python analyze_gateway.py captures/session.pcap
```

**What it does:**
1. Parses the pcap manually using `struct` (no external pcap library required)
2. Handles Linux SLL link-type (113) from `tcpdump -i any`
3. Reassembles TCP streams across fragmented 1400B MTU segments
4. Splits the reassembled streams into gateway frames using `uint16_BE` framing
5. Outputs per-stream frame tables with: offset, length, opcode, hex preview, extracted strings
6. Prints the handshake contents, opcode distribution, and heartbeat patterns

**Key output sections:**
- `C->S frames` — player actions sent to server
- `S->C frames` — server state updates and responses
- `Strings` — human-readable strings extracted from each frame
- `HEARTBEAT` — small C→S frames (≤16B), pattern analysis

**Requirements:** Python 3.8+, no pip installs needed.

---

## analyze_mitm.py

**Purpose:** Read mitmproxy `.mitm` capture files and display HTTP flows in a readable format.

**Usage:**
```bash
# show all flows
python analyze_mitm.py session.mitm

# filter by URL substring
python analyze_mitm.py session.mitm --filter logagent
python analyze_mitm.py session.mitm --filter centurygame
python analyze_mitm.py session.mitm --filter api
```

**What it shows:**
- Request method + URL
- Interesting headers: `Authorization`, `x-token`, `cookie`, `x-uid`, `x-device-id`, `user-agent`
- Request body (JSON pretty-printed if detected, hex preview for binary)
- Response status code, content-type, body preview

**Requirements:** `pip install mitmproxy`

---

## decode_1d_v2.py

**Purpose:** Deep analysis of `0x1d` (state-sync) frames from a gateway pcap.

**What it does:**
- Buckets all `0x1d` S→C frames into small / medium / large
- Hexdumps medium frames with varint walk
- Scans large frames for:
  - Embedded ASCII strings
  - LE-uint32 timestamps (identifies scheduled events and history records)
  - BE-uint32 UIDs (player/object IDs)
- Compares header patterns across all large frames

**Key finding from battle2.pcap:**
The largest frame (3824B) contains ~200 LE-uint32 Unix timestamps spanning July–September 2025. These are player event history records synced on login (troop marches, resource collections, building completions).

**To use on a different capture:** edit the `open(...)` call at the top of the file.

**Requirements:** Python 3.8+, no pip installs needed.

---

## deep_analysis.py

**Purpose:** Three focused analyses on `battle2.pcap`.

**Analysis 1 — Coordinate encoding:**
Extracts all 4-char coordinate strings from S→C frames and decodes them using the ASCII85-like formula:
```
value = sum((char - 33) * 85^i)
kingdom  = value >> 16
position = value & 0xffff
```
Groups by suffix character (`@` = global map, `$` = sub-object reference).

**Analysis 2 — Embedded JSON:**
Scans `0x1d` frames for JSON objects embedded in binary payloads. Found in frame #66:
```json
{"12":true,"13":true,"11":true,"16":true,"10":true,"15":true,"22":true}
{"p_giftid":4000751,"device_lvl":2,"fp_countrycode":"BR"}
```

**Analysis 3 — Opcode 0x59 structure:**
Decodes all `0x59` C→S frames:
- Short frames (13B): client ACK with incrementing sequence counter
- Long frame (51B): carries `Yuoo0N3p7nDUsi8hmNhCUW6UAO6mHsoxoeNg==` — decodes to 27 raw bytes, likely a custom HMAC or session proof token

**Requirements:** Python 3.8+, no pip installs needed.
