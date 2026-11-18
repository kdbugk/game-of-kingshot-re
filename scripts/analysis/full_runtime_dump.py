#!/usr/bin/env python3
"""Full runtime dump: restart game (am start), wait for boot, attach, walk structs."""
import frida, sys, time, json, subprocess
from pathlib import Path

OUT_DIR = Path("/home/re/work/apk/il2cpp_dump_114")
OUT_DIR.mkdir(exist_ok=True)
SUMMARY = "/home/re/work/apk/il2cpp_dump_114_summary.txt"

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
subprocess.run(["adb", "shell", "am", "force-stop", "com.run.tower.defense"])
time.sleep(2)
pid = device.spawn(["com.run.tower.defense"])
print(f"[*] frida-spawn pid={pid}", flush=True)
session = device.attach(pid)
device.resume(pid)

JS = r"""
'use strict';
const szp = Memory.alloc(4);
const iv = setInterval(() => {
  const mod = Process.findModuleByName('libil2cpp.so');
  if (!mod) return;
  try {
    const dg  = new NativeFunction(mod.getExportByName('il2cpp_domain_get'), 'pointer', []);
    const dga = new NativeFunction(mod.getExportByName('il2cpp_domain_get_assemblies'), 'pointer', ['pointer','pointer']);
    const domain = dg();
    if (domain.isNull()) return;
    const arr = dga(domain, szp);
    const n = szp.readU32();
    if (n >= 50) { clearInterval(iv); send({type:'ready', n: n, base: mod.base.toString()}); }
  } catch (_) {}
}, 1000);
"""
ready = {}
s0 = session.create_script(JS)
s0.on("message", lambda m, d: ready.update(m.get("payload", {})) if m["type"] == "send" else print("ERR", m.get("description", str(m))[:200]))
s0.load()
t0 = time.time()
while "ready" not in ready and time.time() - t0 < 300:
    time.sleep(2)
print("[*]", ready, flush=True)
if "ready" not in ready:
    sys.exit(1)

BASE = int(ready["base"], 16)

# ── walker ──
WALK = r"""
'use strict';
const TB = ptr('""" + "0" + r"""'); // placeholder substituído abaixo
"""
# descobrir a tabela dinamicamente no processo (mesma lógica da sonda)
FIND_TABLE = r"""
'use strict';
(function () {
  const mod = Process.findModuleByName('libil2cpp.so');
  const dg  = new NativeFunction(mod.getExportByName('il2cpp_domain_get'), 'pointer', []);
  const dga = new NativeFunction(mod.getExportByName('il2cpp_domain_get_assemblies'), 'pointer', ['pointer','pointer']);
  const domain = dg();
  const szp = Memory.alloc(4);
  const arr = dga(domain, szp);
  const nAsm = szp.readU32();
  const classLo = arr.readPointer();       // região de structs ~ ponteiros do array
  // heurística: classes estão na mesma região que assemblies/imagens
  const samples = [];
  for (let i = 0; i < nAsm; i++) samples.push(arr.add(i*8).readPointer());
  samples.sort((a,b) => a.compare(b));
  const lo = samples[0], hi = samples[samples.length-1];
  const span = hi.sub(lo);
  const lo2 = lo.sub(span), hi2 = hi.add(span);
  // varre rw atrás de runs de ponteiros dentro de [lo2, hi2]
  const ranges = Process.enumerateRanges('rw-');
  for (const r of ranges) {
    if (r.size < 0x100000 || r.size > 0x8000000) continue;
    if (r.base.compare(ptr('%s')) < 0 || r.base.compare(ptr('%s')) > 0) continue;
    try {
      let run = 0, runStart = null;
      for (let off = 0; off + 8 <= r.size; off += 8) {
        const p = r.base.add(off).readPointer();
        if (p.compare(lo2) >= 0 && p.compare(hi2) < 0) {
          if (run === 0) runStart = r.base.add(off);
          run++;
          if (run >= 4096) { send({t: 'table', base: runStart.toString(), run: run}); return; }
        } else { run = 0; }
      }
    } catch (_) {}
  }
  send({t: 'table', base: null});
})();
""" % ("0x6d00000000", "0x7000000000")

tab = {}
st = session.create_script(FIND_TABLE)
st.on("message", lambda m, d: tab.update(m.get("payload", {})) if m["type"] == "send" else print("ERR", m))
st.load()
t0 = time.time()
while "base" not in tab and time.time() - t0 < 90:
    time.sleep(2)
print("[*] table:", tab, flush=True)

# ── dump final com offsets empíricos (validados no probe anterior) ──
DUMP = r"""
'use strict';
const TB = ptr('""" + str(tab.get("base")) + r"""');
const BASE = ptr('""" + hex(BASE) + r"""');
const mod = Process.findModuleByName('libil2cpp.so');
const dg  = new NativeFunction(mod.getExportByName('il2cpp_domain_get'), 'pointer', []);
const dga = new NativeFunction(mod.getExportByName('il2cpp_domain_get_assemblies'), 'pointer', ['pointer','pointer']);
const domain = dg();
const szp = Memory.alloc(4);
const arr = dga(domain, szp);
const nAsm = szp.readU32();
function cstr(p) { try { const s = p.readCString(); return (s && s.length < 256) ? s : null; } catch (_) { return null; } }

const out = [];
let idx = 0, totC = 0, totM = 0;
for (let ai = 0; ai < nAsm; ai++) {
  const asm = arr.add(ai*8).readPointer();
  const image = asm.readPointer();
  const imgName = cstr(image.readPointer()) || ('image_' + ai);
  const obj = { name: imgName, classes: [] };
  // percorrer a tabela global: cada entrada cujo klass->image == image
  // (custo: tabela ~50k entradas × 85 imagens = alto; melhor: varrer uma vez)
  // → estratégia: varrer tabela UMA vez, agrupando por image
  send({type:'progress', asm: imgName});
  break; // substituído pela varredura única abaixo
}
send({type:'phase2'});
"""
print("[*] iniciando varredura única da tabela...", flush=True)

# varredura única: tabela → klass → image → agrupar
SCAN = r"""
'use strict';
const TB = ptr('""" + str(tab.get("base")) + r"""');
const BASE = ptr('""" + hex(BASE) + r"""');
const groups = {};  // imagePtr -> {name, classes:{klassPtr:{name,ns,methods:[...]}}}
let count = 0;
// limite: 60000 entradas
for (let i = 0; i < 60000; i++) {
  let k;
  try { k = TB.add(i*8).readPointer(); } catch (_) { break; }
  if (k.isNull()) continue;
  let img, name, ns;
  try {
    img = k.readPointer();          // klass+0 = image
    name = cstr2(k.add(0x10).readPointer());
    ns = cstr2(k.add(0x18).readPointer());
  } catch (_) { continue; }
  if (!name) continue;
  count++;
  if (!groups[img]) {
    const iname = safeName(img);
    groups[img] = { name: iname, classes: {} };
  }
  groups[img].classes[k.toString()] = { name: name, ns: ns || '' };
  if (i % 5000 === 0) send({type:'tick', i: i});
}
function cstr2(p) { try { const s = p.readCString(); return (s && s.length < 256) ? s : null; } catch (_) { return null; } }
function safeName(img) { try { return cstr2(img.readPointer()) || img.toString(); } catch (_) { return img.toString(); } }
send({type:'scan_done', count: count, images: Object.keys(groups).length});
// envia grupos em lotes
const keys = Object.keys(groups);
let idx = 0;
for (const g of keys) {
  const o = groups[g];
  send({type:'assembly', index: idx, name: o.name, class_count: Object.keys(o.classes).length}, str2ab(JSON.stringify(o)));
  idx++;
}
function str2ab(s) { const b = new Uint8Array(s.length); for (let i=0;i<s.length;i++) b[i]=s.charCodeAt(i)&0xff; return b.buffer; }
"""

state = {"asm": 0, "done": False}
assemblies = {}
def on_msg(m, d):
    if m["type"] == "send":
        p = m["payload"]
        t = p.get("type")
        if t == "tick":
            print(f"  … tabela {p['i']}", flush=True)
        elif t == "scan_done":
            print(f"[scan] {p['count']} classes em {p['images']} imagens", flush=True)
        elif t == "assembly":
            if d:
                assemblies[p["name"]] = bytes(d)
            state["asm"] += 1
        elif t == "phase2" or t == "progress":
            pass
    elif m["type"] == "error":
        print("[JS-ERR]", m.get("description", "")[:200], flush=True)

s2 = session.create_script(SCAN)
s2.on("message", on_msg)
s2.load()
t0 = time.time()
while time.time() - t0 < 600:
    time.sleep(3)
    if state["asm"] > 0:
        # aguarda assentar
        time.sleep(10)
        break
print(f"[*] {state['asm']} imagens agrupadas", flush=True)
for i, (name, data) in enumerate(sorted(assemblies.items())):
    out = OUT_DIR / f"{i:03d}_{name.replace('/', '_')}.json"
    out.write_bytes(data)
Path(SUMMARY).write_text(f"images: {len(assemblies)}\n")
print(f"[DONE] {len(assemblies)} imagens -> {OUT_DIR}")
