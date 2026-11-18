#!/usr/bin/env python3
"""Broad scan: decrypted (AF1BB1FA) + encrypted (HTPX) metadata magics, all ranges."""
import frida, sys, time, json

JS = """
'use strict';
function scanAll() {
  var dec = [], enc = [];
  var ranges = Process.enumerateRanges('r--');
  var scanned = 0;
  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    if (r.size > 0x10000000) continue;
    var isRW = r.protection.indexOf('w') >= 0;
    try {
      var res = Memory.scanSync(r.base, r.size, 'af 1b b1 fa');
      for (var j = 0; j < res.length; j++) dec.push({a: res[j].address.toString(), rw: isRW, sz: r.size, f: r.file ? (r.file.path||'').slice(0,40) : ''});
      scanned += r.size;
    } catch (e) {}
    try {
      var res2 = Memory.scanSync(r.base, r.size, '48 54 50 58');
      for (var k = 0; k < res2.length; k++) enc.push({a: res2[k].address.toString(), rw: isRW, f: r.file ? (r.file.path||'').slice(0,40) : ''});
    } catch (e) {}
  }
  return {dec: dec, enc: enc.slice(0, 40), scannedMb: Math.round(scanned/1048576)};
}
try { send(scanAll()); } catch (e) { send({error: e.toString()}); }
"""

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
ps = [p for p in device.enumerate_processes() if "Kingshot" in p.name or "tower" in p.name]
if not ps:
    print("sem processo — o jogo morreu?"); sys.exit(1)
pid = ps[0].pid
print(f"attach pid={pid} ({ps[0].name})")
session = device.attach(pid)
script = session.create_script(JS)
out = {}
script.on("message", lambda m, d: out.update(m.get("payload", {})) if m["type"] == "send" else print("err:", m))
script.load()
t0 = time.time()
while not out and time.time() - t0 < 90:
    time.sleep(2)
print(f"scanned: {out.get('scannedMb')} MB")
print(f"DEC hits ({len(out.get('dec', []))}):")
for h in out.get("dec", [])[:20]:
    print("  ", h)
print(f"ENC(HTPX) hits ({len(out.get('enc', []))}):")
for h in out.get("enc", [])[:10]:
    print("  ", h)
