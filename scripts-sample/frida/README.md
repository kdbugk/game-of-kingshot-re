# Frida Scripts

All scripts target `com.run.tower.defense` in **spawn mode** via a remote frida-server (`127.0.0.1:37555`).

---

## certval_hook.js

**Purpose:** Observe BestHTTP's SSL certificate validation decisions without modifying behavior.

**What it hooks:**
- `FrameworkTLSSettings.<>c.b__6_0` — the `DefaultCertificationValidator` delegate  
  RVA `0x269ef4c` in `libil2cpp.so`
- `AbstractTls13Client.NotifyServerCertificate` (BouncyCastle path)  
  RVA `0x27ad85c` in `libil2cpp.so`

**Output:**
```
[CV] #1  host="passport-got.centurygame.com"  errors=4 (RemoteCertificateChainErrors)  → ACEITO  ⚠ ACEITO COM ERRO
```

**Key finding:** The validator accepts certificates with errors (`sslErrors != 0`) and returns `true`. This confirms the pinning is active and that our MITM cert is being detected but accepted by this specific validator.

**Note:** This script only observes. To bypass, use `ssl_unpin.js` which calls `retval.replace(ptr(1))`.

---

## button_hook.js

**Purpose:** Log every Unity UI button interaction with the button's name and game object hierarchy.

**What it hooks (all in `libil2cpp.so`):**

| Method | RVA | Notes |
|---|---|---|
| `ButtonEx.OnPointerClick` | `0x23bed78` | Main click handler |
| `ButtonEx.set_interactable` | `0x23bec54` | Enable/disable state changes |
| `ButtonEx.SetDisableKey` | `0x23bf348` | Disabled key assignment |
| `Button.Press` | `0x3c105bc` | Core Unity button press |
| `ClickListener.Click` | `0x23a139c` | Alternative click handler |
| `OnlyClickListener.Click` | `0x2481510` | Single-use click handler |

**IL2CPP string reading:**
```javascript
// IL2CPP strings layout:
// +0x00  vtable*
// +0x10  int32  length
// +0x14  utf16  chars[length]
function readManagedString(ptr) {
    const len = ptr.add(0x10).readS32();
    return ptr.add(0x14).readUtf16String(len);
}
```

**Output format:**
```
[BTN] #0001  ButtonEx       "AttackButton"  gameObject=CityAttackPanel
[BTN] #0002  Button.Press   "ConfirmAttack"
```

**Use case:** Correlate button presses with subsequent network frames to identify which game actions trigger which gateway messages.

---

## nesec_bypass.js

**Purpose:** Neutralize libnesec's anti-tampering to extend Frida session beyond ~58 seconds.

**What it patches:**

| Target | Offset | Technique | Effect |
|---|---|---|---|
| `nesec_acao_kill` | `0x3a6168` | `Memory.patchCode` → ARM64 `RET` | Kill function becomes a no-op |
| `nesec_nivel_deteccao` | `0x0f54c` | `Interceptor.attach` + `retval.replace(ptr(0))` | Always reports "no anomaly" |

**Important:** libnesec is not loaded at app start. The script polls every 200ms for `libnesec.so` to appear, then installs hooks.

**Known limitation:** Process still terminates in some sessions. There are likely additional kill sites (possibly via `kill()` / `pthread_kill()` libc calls) beyond the two hooked here. Full bypass requires finding all call sites in Ghidra.

**Usage:** Load alongside another script:
```bash
objection ... --startup-script nesec_bypass.js
# or
frida ... -l nesec_bypass.js -l your_other_script.js
```

---

## ssl_unpin.js

**Purpose:** Attempt full SSL unpinning across both Java and IL2CPP layers.

**Java layer hooks (via `Java.perform`):**
- Custom `TrustManager` registered — accepts all certificates
- `HttpsURLConnection` hostname verifier replaced
- `OkHttp3 CertificatePinner.check` and `check$okhttp` — both overloaded, made no-ops
- `TrustManagerImpl.verifyChain` and `checkTrustedRecursive` — bypassed
- `SSLContext.init` intercepted to inject the custom TrustManager dynamically

**IL2CPP layer hook:**
- `DefaultCertificationValidator` at RVA `0x269ef4c`
- On `onLeave`: `retval.replace(ptr(1))` — forces `true` (accept) for all certificates

**Spawn-mode timing fix:** `Java.perform()` cannot be called at script top-level during spawn mode (JVM not initialized). The script polls `Java.available` every 200ms before invoking Java hooks.

**Current status:** Java-layer hooks confirmed working (OkHttp and TrustManager hooks fire). Process is still killed by libnesec before enough game traffic is generated. Combine with `nesec_bypass.js` for best results.
