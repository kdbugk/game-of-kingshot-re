#!/usr/bin/env python3
"""Look for an intact-metadata-header candidate: scan rw memory for the
file-format signature (u32 pairs pattern) OR a second string-heap copy."""
import frida, sys, time, json

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
ps = [p for p in device.enumerate_processes() if "Kingshot" in p.name or "tower" in p.name]
if not ps:
    print("sem processo"); sys.exit(1)

JS = r"""
'use strict';
// padrão de header de metadata v29-31: sanity(u32)+version(u32) seguido de pares (offset,size) crescentes
// procuramos: [any][ver 29..31][0x110 (stringLiteralOffset)] — não; layout:
// +0 sanity +4 version +8 stringLiteralOffset +12 stringLiteralSize ...
// assinatura: valor em +8 == tamanho_do_header (0x110) e +12 < filesize e crescente
let found = [];
const ranges = Process.enumerateRanges('rw-');
for (const r of ranges) {
  if (r.size > 0x8000000 || r.size < 0x100000) continue;
  try {
    // varre por 8-byte aligned: [magic?][ver][0x110?][size]
    for (let off = 0; off + 0x40 < Math.min(r.size, 0x1000); off += 4) {
      const p = r.base.add(off);
      let ver, slo;
      try { ver = p.add(4).readU32(); slo = p.add(8).readU32(); } catch(_) { continue; }
      if (ver >= 24 && ver <= 40 && slo === 0x110) {
        found.push({a: p.toString(), ver: ver, r: r.base.toString(), sz: r.size});
      }
    }
  } catch (_) {}
}
send({found: found});
"""
session = device.attach(ps[0].pid)
out = {}
script = session.create_script(JS)
script.on("message", lambda m, d: out.update(m.get("payload", {})) if m["type"] == "send" else print("ERR", m.get("description", m)))
script.load()
time.sleep(20)
print(json.dumps(out, indent=1))
