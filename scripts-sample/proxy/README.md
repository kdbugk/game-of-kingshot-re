# Proxy Scripts

Combined runners that start mitmproxy and Frida simultaneously, correlating HTTP traffic with in-app events by timestamp.

---

## mitm_setup.py

**Purpose:** One-time setup — install the mitmproxy CA certificate on the Android device as a system trust anchor.

**Run once per device** (re-run after factory reset or system restore):
```bash
python mitm_setup.py
```

After running, configure the device WiFi proxy to your PC's IP on port 8081.

---

## run_ssl_unpin.py

**Purpose:** Start `mitmdump` and inject `ssl_unpin.js` via Frida simultaneously, logging all decrypted HTTP traffic alongside SSL bypass events.

**Config block (edit before running):**
```python
APP_ID       = "com.run.tower.defense"
FRIDA_HOST   = "127.0.0.1:37555"
PROXY_HOST   = "192.168.0.84"      # your PC's IP on the device's network
PROXY_PORT   = 8081
MITMDUMP_EXE = r"C:\path\to\mitmdump.exe"
```

**Output files:**
| File | Contents |
|---|---|
| `unpin_<ts>.log` | Frida events: SSL bypass hits, errors, libnesec events |
| `http_<ts>.log` | Decrypted HTTP requests and responses |
| `http_<ts>.mitm` | Binary mitmproxy capture (open with `mitmweb --rfile`) |

**Architecture:**
- Thread 1: `mitmdump` subprocess reading from mitmproxy addon
- Thread 2: Frida spawn + script load
- Inline mitmproxy addon (`_unpin_addon_<ts>.py`) written to disk, deleted on exit
- The addon logs `Authorization`, `x-token`, `cookie`, `x-uid` headers specifically

**Current status:** Java-layer SSL hooks fire successfully (OkHttp, TrustManager). Process is killed by libnesec before the full login flow completes. Use with `nesec_bypass.js` for improved longevity.

---

## run_button_hook.py

**Purpose:** Start `mitmdump` and inject `button_hook.js` via Frida, correlating UI button presses with HTTP requests by timestamp.

**Config block:** same fields as `run_ssl_unpin.py`.

**Output files:**
| File | Contents |
|---|---|
| `button_events_<ts>.log` | Button click events with name, label, game object |
| `http_traffic_<ts>.log` | HTTP requests/responses |
| `http_traffic_<ts>.mitm` | Binary mitmproxy capture |

**Use case:** Determine which HTTP API calls are triggered by specific UI interactions. For example: clicking "Attack" → which gateway frame follows → which analytics event fires.

**Note:** The analytics endpoint (`logagent-wf.centurygame.com`) is not SSL-pinned, so button events can be correlated with analytics events without any bypass needed.
