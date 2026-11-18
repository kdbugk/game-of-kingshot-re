#!/usr/bin/env python3
"""SPAWN + wait-for-user-login + dump in same session."""
import frida, sys, time, json
from pathlib import Path

OUT_DIR = Path("/home/re/work/apk/il2cpp_dump_114")
OUT_DIR.mkdir(exist_ok=True)
SUMMARY = "/home/re/work/apk/il2cpp_dump_114_summary.txt"

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
import subprocess
subprocess.run(["adb", "shell", "am", "force-stop", "com.run.tower.defense"])
time.sleep(2)
pid = device.spawn(["com.run.tower.defense"])
print(f"[*] spawn pid={pid} — ENTRE NO JOGO NO CELULAR (login) enquanto eu espero", flush=True)
session = device.attach(pid)
device.resume(pid)

WAIT = r"""
'use strict';
(function () {
  const szp = Memory.alloc(4);
  const iv = setInterval(() => {
    const mod = Process.findModuleByName('libil2cpp.so');
    if (!mod) return;
    try {
      const dg  = new NativeFunction(mod.getExportByName('il2cpp_domain_get'), 'pointer', []);
      const dga = new NativeFunction(mod.getExportByName('il2cpp_domain_get_assemblies'), 'pointer', ['pointer','pointer']);
      const d = dg();
      if (d.isNull()) return;
      const arr = dga(d, szp);
      const n = szp.readU32();
      if (n >= 50) { clearInterval(iv); send({type:'ready', n:n, base:mod.base.toString()}); }
    } catch (_) {}
  }, 1500);
})();
"""
ready = {}
sw = session.create_script(WAIT)
sw.on("message", lambda m, d: ready.update(m.get("payload", {})) if m["type"] == "send" else None)
sw.load()
t0 = time.time()
while "ready" not in ready and time.time() - t0 < 600:
    time.sleep(3)
    if int(time.time() - t0) % 60 < 3:
        print(f"  … esperando boot/login ({int(time.time()-t0)}s)", flush=True)
print("[*]", ready, flush=True)
if "ready" not in ready:
    print("timeout — jogo não inicializou"); sys.exit(1)

BASE = ready["base"]

# fase 1: tabela
PHASE1 = r"""
'use strict';
(function () {
const mod = Process.findModuleByName('libil2cpp.so');
const dg  = new NativeFunction(mod.getExportByName('il2cpp_domain_get'), 'pointer', []);
const dga = new NativeFunction(mod.getExportByName('il2cpp_domain_get_assemblies'), 'pointer', ['pointer','pointer']);
const domain = dg();
const szp = Memory.alloc(4);
const arr = dga(domain, szp);
const n = szp.readU32();
const samples = [];
for (let i = 0; i < n; i += 7) samples.push(arr.add(i*8).readPointer());
samples.sort((a,b)=>a.compare(b));
const lo = samples[0], hi = samples[samples.length-1];
const spanN = hi.sub(lo).toNumber();
let best = null;
const ranges = Process.enumerateRanges('rw-');
for (const r of ranges) {
  if (r.size < 0x40000 || r.size > 0x8000000) continue;
  const rn = r.base.toNumber();
  if (rn < lo.toNumber() - spanN*4 || rn > hi.toNumber() + spanN*4) continue;
  try {
    let run = 0, runStart = null;
    for (let off = 0; off + 8 <= r.size; off += 8) {
      const p = r.base.add(off).readPointer();
      const pn = p.toNumber();
      if (pn >= lo.toNumber() && pn <= hi.toNumber() + spanN*2) {
        if (run === 0) runStart = r.base.add(off);
        run++;
        if (!best || run > best.run) best = {base: runStart.toString(), run: run};
        if (run > 80000) break;
      } else { run = 0; }
    }
  } catch (_) {}
}
send({type:'table', best: best, n: n});
})();
"""
p1 = {}
s1 = session.create_script(PHASE1)
s1.on("message", lambda m, d: p1.update(m.get("payload", {})) if m["type"] == "send" else print("[ERR]", m.get("description", str(m))[:150]))
s1.load()
t0 = time.time()
while "best" not in p1 and time.time() - t0 < 180:
    time.sleep(2)
print("[*]", p1, flush=True)
if not p1.get("best"):
    print("tabela não achada"); sys.exit(1)
TB = p1["best"]["base"]; RUN = p1["best"]["run"]

# fase 2
PHASE2 = r"""
'use strict';
(function () {
const TB = ptr('""" + TB + r"""');
const RUN = """ + str(RUN) + r""";
const groups = {};
let count = 0, bad = 0;
function cstr(p) { try { const s = p.readCString(); return (s && s.length < 300) ? s : null; } catch (_) { return null; } }
for (let i = 0; i < RUN + 64; i++) {
  let k;
  try { k = TB.add(i*8).readPointer(); } catch (_) { break; }
  if (k.isNull()) { bad++; continue; }
  let img = null, name = null, ns = null;
  try {
    img = k.readPointer();
    name = cstr(k.add(0x10).readPointer());
    ns = cstr(k.add(0x18).readPointer());
  } catch (_) { bad++; continue; }
  if (!name || !img) { bad++; continue; }
  if (!groups[img]) {
    let iname = null;
    try { iname = cstr(img.readPointer()); } catch (_) {}
    groups[img] = { name: iname || ('img_' + img.toString()), classes: {} };
  }
  groups[img].classes[k.toString()] = { name: name, ns: ns || '' };
  count++;
}
send({type:'scan_done', count: count, bad: bad, images: Object.keys(groups).length});
const keys = Object.keys(groups);
let idx = 0;
function sendNext() {
  if (idx >= keys.length) { send({type:'all_sent', total: idx}); return; }
  const o = groups[keys[idx]];
  const s = JSON.stringify(o);
  const b = new Uint8Array(s.length);
  for (let j = 0; j < s.length; j++) b[j] = s.charCodeAt(j) & 0xff;
  send({type:'assembly', index: idx, name: o.name, class_count: Object.keys(o.classes).length}, b.buffer);
  idx++;
  setTimeout(sendNext, 5);
}
setTimeout(sendNext, 10);
})();
"""
state = {"asm": 0, "done": False, "scan": None}
assemblies = {}
def on2(m, d):
    if m["type"] == "send":
        p = m["payload"]; t = p.get("type")
        if t == "scan_done":
            state["scan"] = p; print(f"[scan] {p}", flush=True)
        elif t == "assembly":
            if d: assemblies[p["name"]] = bytes(d)
            state["asm"] += 1
            if state["asm"] % 10 == 0: print(f"  {state['asm']} imagens...", flush=True)
        elif t == "all_sent":
            state["done"] = True; print(f"[all_sent] {p}", flush=True)
    elif m["type"] == "error":
        print("[JS-ERR]", m.get("description", "")[:200], flush=True)

s2 = session.create_script(PHASE2)
s2.on("message", on2)
s2.load()
t0 = time.time()
while not state["done"] and time.time() - t0 < 420:
    time.sleep(3)

for i, (name, data) in enumerate(sorted(assemblies.items())):
    out = OUT_DIR / f"{i:03d}_{name.replace('/', '_')}.json"
    out.write_bytes(data)
sc = state.get("scan") or {}
Path(SUMMARY).write_text(
    f"images: {len(assemblies)}\nclasses: {sc.get('count')}\nbad: {sc.get('bad')}\nbase: {BASE}\ntable: {TB}\n")
print(f"[DONE] {len(assemblies)} imagens, {sc.get('count')} classes -> {OUT_DIR}")
