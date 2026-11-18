#!/usr/bin/env python3
"""Direct memory scan for decrypted global-metadata (AF 1B B1 FA) in live Kingshot."""
import frida, sys, time, json

JS = """
'use strict';
function scan() {
  var hits = [];
  var ranges = Process.enumerateRanges({protection: 'rw-', coalesce: true});
  var scanned = 0;
  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    if (r.size > 0x8000000) continue;          // >128MB skip
    if (r.file && r.file.path && r.file.path.indexOf('.so') >= 0) continue; // skip .so mappings
    try {
      var res = Memory.scanSync(r.base, r.size, 'af 1b b1 fa');
      for (var j = 0; j < res.length; j++) hits.push({addr: res[j].address.toString(), size: r.size});
      scanned += r.size;
    } catch (e) {}
  }
  return {hits: hits, scannedMb: Math.round(scanned/1048576)};
}
try { send(scan()); } catch (e) { send({error: e.toString()}); }
"""

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
# achar o processo
try:
    pid = int(sys.argv[1])
except Exception:
    ps = [p for p in device.enumerate_processes() if "Kingshot" in p.name or "tower" in p.name]
    if not ps:
        print("processo não encontrado"); sys.exit(1)
    pid = ps[0].pid
print(f"attach pid={pid}")
session = device.attach(pid)
script = session.create_script(JS)
out = {}
def on_msg(m, d):
    global out
    if m["type"] == "send": out = m["payload"]
    else: print("err:", m)
script.on("message", on_msg)
script.load()
time.sleep(25)
print(json.dumps(out, indent=1)[:2000])

# se achou, dump do primeiro candidato (32MB)
hits = out.get("hits", [])
if hits:
    addr = hits[0]["addr"]
    print(f"dumping a partir de {addr}...")
    JS2 = f"""
    var base = ptr('{addr}');
    var size = 32 * 1024 * 1024;
    // validar header: magic + version + stringLiteralOffset sanity
    var magic = base.readU32();
    var ver = base.add(4).readU32();
    send({{magic: magic, version: ver}});
    // achar o fim: sanity = stringLiteralOffset deve ser < size
    var slo = base.add(8).readU32();
    send({{stringLiteralOffset: slo}});
    var dump = base.readByteArray(size);
    send(dump.byteLength);
    """
    # mais simples: ler direto via script e salvar
    JS3 = f"""
    var base = ptr('{addr}');
    var chunk = 1024*1024;
    var total = 16 * 1024 * 1024;
    for (var off = 0; off < total; off += chunk) {{
        var b = base.add(off).readByteArray(Math.min(chunk, total - off));
        send({{off: off}}, b);
    }}
    """
    f = open("/home/re/projects/game-of-kingshot-re/dump/metadata_decrypted_live.dat", "wb")
    got = [0]
    def on_msg3(m, d):
        if m["type"] == "send" and d:
            f.write(d); got[0] += len(d)
    s3 = session.create_script(JS3)
    s3.on("message", on_msg3)
    s3.load()
    for _ in range(120):
        time.sleep(1)
        if got[0] >= 16 * 1024 * 1024: break
    f.close()
    print(f"dump: {got[0]:,} bytes -> metadata_decrypted_live.dat")
