#!/usr/bin/env python3
"""Find decrypted metadata in memory via its string heap ('Assembly-CSharp'
next to 'mscorlib'), then dump the surrounding region for header analysis."""
import frida, sys, time, json

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
ps = [p for p in device.enumerate_processes() if "Kingshot" in p.name or "tower" in p.name]
if not ps:
    print("sem processo"); sys.exit(1)
print("pid", ps[0].pid)

JS = r"""
'use strict';
const HITS_LIMIT = 12;
let hits = [];
const ranges = Process.enumerateRanges('rw-');
let scanned = 0;
for (const r of ranges) {
  if (r.size > 0x8000000) continue;
  try {
    const res = Memory.scanSync(r.base, r.size, '00 41 73 73 65 6d 62 6c 79 2d 43 53 68 61 72 70 00');
    for (const h of res) {
      // precisa ter mscorlib perto (mesma heap)
      let near = false;
      try {
        const ctx = h.address.sub(0x2000).readCString ? null : null;
      } catch(_) {}
      hits.push({a: h.address.toString(), base: r.base.toString(), size: r.size,
                 f: r.file ? (r.file.path||'').slice(-30) : ''});
      if (hits.length >= HITS_LIMIT) break;
    }
    scanned += r.size;
  } catch (_) {}
}
send({hits: hits, scannedMb: Math.round(scanned/1048576)});
"""
session = device.attach(ps[0].pid)
out = {}
script = session.create_script(JS)
script.on("message", lambda m, d: out.update(m.get("payload", {})) if m["type"] == "send" else print("ERR", m.get("description", m)))
script.load()
time.sleep(20)
hits = out.get("hits", [])
print(f"scanned {out.get('scannedMb')} MB — {len(hits)} hits")
for h in hits:
    print(f"  {h['a']}  range={h['base']}+{h['size']//1024}K  {h['f']}")
