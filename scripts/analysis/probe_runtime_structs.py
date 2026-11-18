#!/usr/bin/env python3
"""Empirical probe of runtime il2cpp structs (v31/2022.3):
- image struct fields (typeStart/typeCount)
- global class-pointer table location
- Il2CppClass / MethodInfo offsets validated by known names."""
import frida, sys, time, json

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
ps = [p for p in device.enumerate_processes() if "Kingshot" in p.name or "tower" in p.name]
if not ps:
    print("sem processo"); sys.exit(1)

JS = r"""
'use strict';
const mod = Process.findModuleByName('libil2cpp.so');
const dg  = new NativeFunction(mod.getExportByName('il2cpp_domain_get'), 'pointer', []);
const dga = new NativeFunction(mod.getExportByName('il2cpp_domain_get_assemblies'), 'pointer', ['pointer','pointer']);
const domain = dg();
const szp = Memory.alloc(4);
const arr = dga(domain, szp);
const nAsm = szp.readU32();
const out = { base: mod.base.toString(), nAsm: nAsm, images: [] };

function cstr(p) { try { return p.readCString(); } catch (_) { return null; } }

for (let i = 0; i < Math.min(nAsm, 6); i++) {
  const asm = arr.add(i*8).readPointer();
  const image = asm.readPointer();   // assembly+0 = image
  const name = cstr(image.readPointer()); // image+0 = name
  // dump do image struct como u32[32] e ptrs
  const u32s = [];
  for (let k = 0; k < 0x20; k++) u32s.push(image.add(k*4).readU32());
  const ptrs = [];
  for (let k = 0; k < 6; k++) ptrs.push(image.add(k*8).readPointer().toString());
  out.images.push({ name: name, image: image.toString(), u32: u32s, ptrs: ptrs });
}

// achar a tabela global de classes: varre rw em busca de runs de ponteiros
// que apontem para a região das structs (~0x6d30000000..0x6d40000000)
let tableHit = null;
(function findTable() {
  const ranges = Process.enumerateRanges('rw-');
  for (const r of ranges) {
    if (r.size < 0x10000 || r.size > 0x8000000) continue;
    if (r.base.compare(0x6d00000000) < 0 || r.base.compare(0x7000000000) > 0) continue;
    try {
      let run = 0, runStart = null;
      for (let off = 0; off + 8 <= r.size; off += 8) {
        const p = r.base.add(off).readPointer();
        if (p.compare(0x6d30000000) >= 0 && p.compare(0x6d50000000) < 0) {
          if (run === 0) runStart = r.base.add(off);
          run++;
          if (run >= 256) { tableHit = { base: runStart.toString(), range: r.base.toString(), run: run }; return; }
        } else {
          if (run >= 256) { tableHit = { base: runStart.toString(), range: r.base.toString(), run: run }; return; }
          run = 0;
        }
      }
    } catch (_) {}
  }
})();
out.table = tableHit;

// validar um Il2CppClass conhecido: percorre tabela achada e lê klass+0x10/+0x18
if (tableHit) {
  const tb = ptr(tableHit.base);
  const samples = [];
  for (let i = 0; i < 8 && samples.length < 4; i++) {
    try {
      const k = tb.add(i*8).readPointer();
      const name = cstr(k.add(0x10).readPointer());
      const ns = cstr(k.add(0x18).readPointer());
      const imgName = cstr(k.readPointer().readPointer());
      samples.push({ i: i, klass: k.toString(), name: name, ns: ns, img: imgName });
    } catch (_) {}
  }
  out.classSamples = samples;
}
send(out);
"""
session = device.attach(ps[0].pid)
out = {}
script = session.create_script(JS)
script.on("message", lambda m, dd: out.update(m.get("payload", {})) if m["type"] == "send" else print("ERR", m.get("description", str(m))[:200]))
script.load()
time.sleep(30)
print(json.dumps(out, indent=1)[:4000])
