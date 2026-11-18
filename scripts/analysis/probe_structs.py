#!/usr/bin/env python3
"""Probe: which APIs exist + verify Il2CppAssembly->image offset by hand-walking."""
import frida, sys, time, json

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
ps = [p for p in device.enumerate_processes() if "Kingshot" in p.name or "tower" in p.name]
if not ps:
    print("sem processo"); sys.exit(1)
print("pid", ps[0].pid)

JS = r"""
'use strict';
const mod = Process.findModuleByName('libil2cpp.so');
const names = ['il2cpp_init','il2cpp_domain_get','il2cpp_domain_get_assemblies',
 'il2cpp_assembly_get_image','il2cpp_image_get_name','il2cpp_image_get_filename',
 'il2cpp_image_get_class_count','il2cpp_image_get_class','il2cpp_class_get_name',
 'il2cpp_class_get_namespace','il2cpp_class_get_methods','il2cpp_method_get_name',
 'il2cpp_thread_attach','il2cpp_string_length'];
const found = {};
for (const n of names) {
  try { found[n] = mod.getExportByName(n).toString(); } catch (_) { found[n] = null; }
}
send({apis: found, base: mod.base.toString()});

const dg = new NativeFunction(mod.getExportByName('il2cpp_domain_get'), 'pointer', []);
const dga = new NativeFunction(mod.getExportByName('il2cpp_domain_get_assemblies'), 'pointer', ['pointer','pointer']);
const domain = dg();
const sz = Memory.alloc(4);
const arr = dga(domain, sz);
const n = sz.readU32();
send({n_assemblies: n, arr: arr.toString()});

// hand-walk: assembly[i] -> +8 = image (hipótese) -> dump estruturas
let ign = null;
try { ign = new NativeFunction(mod.getExportByName('il2cpp_image_get_name'), 'pointer', ['pointer']); } catch(_){}

for (let i = 0; i < 3; i++) {
  const asm = arr.add(i*8).readPointer();
  const imageHypo = asm.add(8).readPointer();
  let nameViaApi = null;
  if (ign) { try { nameViaApi = imageHypo.readPointer ? ign(imageHypo).readCString() : null; } catch(_){ nameViaApi = 'ERR'; } }
  const asmHex = hexdump(asm, {length: 0x40, ansi: false});
  const imgHex = hexdump(imageHypo, {length: 0x60, ansi: false});
  send({i: i, asm: asm.toString(), imageHypo: imageHypo.toString(), nameViaApi: nameViaApi, asmHex: asmHex, imgHex: imgHex});
}
"""
session = device.attach(ps[0].pid)
out = []
script = session.create_script(JS)
script.on("message", lambda m, d: out.append(m.get("payload", m)) if m["type"] == "send" else print("ERR", m))
script.load()
time.sleep(12)
for o in out[:2]:
    print(json.dumps(o, indent=1, default=str)[:3000])
for o in out[2:5]:
    if isinstance(o, dict):
        print(f"\n── assembly[{o.get('i')}] {o.get('asm')} → image {o.get('imageHypo')} name={o.get('nameViaApi')}")
        print(o.get("asmHex", "")[:400])
        print(o.get("imgHex", "")[:500])
