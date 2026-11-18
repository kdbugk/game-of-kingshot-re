#!/usr/bin/env python3
"""frida-il2cpp-bridge runtime dump → il2cpp_dump/*.json (compatible com diff_dumps.py)."""
import frida, sys, time, json
from pathlib import Path

OUT_DIR = Path("/home/re/work/apk/il2cpp_dump_114")
OUT_DIR.mkdir(exist_ok=True)
SUMMARY = "/home/re/work/apk/il2cpp_dump_114_summary.txt"

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
ps = [p for p in device.enumerate_processes() if "Kingshot" in p.name or "tower" in p.name]
if not ps:
    print("sem processo"); sys.exit(1)
print("pid", ps[0].pid, flush=True)

JS_DUMP = r"""
'use strict';

async function main() {
  await Il2Cpp.initialize();
  const base = Il2Cpp.module.base;
  console.log("[bridge] base=" + base);

  const assemblies = Il2Cpp.domain.assemblies;
  let idx = 0, totalC = 0, totalM = 0;
  for (const assembly of assemblies) {
    const image = assembly.image;
    const obj = { name: image.name, classes: [] };
    try {
      for (const klass of image.classes) {
        const c = { name: klass.name, namespace: klass.namespace, methods: [] };
        for (const m of klass.methods) {
          let rva = null;
          try { rva = "0x" + m.virtualAddress.sub(base).toString(16); } catch (_) {}
          c.methods.push({ name: m.name, rva: rva });
        }
        obj.classes.push(c);
        totalM += c.methods.length;
      }
    } catch (e) {
      console.log("[warn] " + image.name + ": " + e.message);
    }
    totalC += obj.classes.length;
    const payload = jsonToBinary(obj);
    send({ type: "assembly", index: idx, name: image.name, class_count: obj.classes.length }, payload);
    console.log("[dump] " + idx + " " + image.name + " classes=" + obj.classes.length);
    idx++;
    await new Promise(r => setTimeout(r, 10));
  }
  send({ type: "dump_complete", assemblies: idx, classes: totalC, methods: totalM });
}

function jsonToBinary(obj) {
  const s = JSON.stringify(obj);
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff;
  return b.buffer;
}

main().catch(e => { console.log("[FATAL] " + e.stack); send({ type: "fatal", msg: e.message }); });
"""

BRIDGE = open("/home/re/tools/il2cpp-bridge/frida-il2cpp-bridge.js", encoding="utf-8").read()
JS = BRIDGE + "\n;\n" + JS_DUMP

session = device.attach(ps[0].pid)
state = {"asm": 0, "done": False, "fatal": None}

def on_message(message, data):
    if message["type"] == "send":
        p = message["payload"]
        t = p.get("type")
        if t == "assembly":
            if data:
                out = OUT_DIR / f"{p['index']:03d}_{p['name'].replace('/', '_')}.json"
                out.write_bytes(bytes(data))
            state["asm"] += 1
            print(f"[{p['index']:03d}] {p['name']} classes={p['class_count']}", flush=True)
        elif t == "dump_complete":
            state["done"] = True
            Path(SUMMARY).write_text(
                f"assemblies: {p['assemblies']}\nclasses: {p['classes']}\nmethods: {p['methods']}\n")
            print(f"[DONE] assemblies={p['assemblies']} classes={p['classes']} methods={p['methods']}")
        elif t == "fatal":
            state["fatal"] = p.get("msg"); print("[FATAL]", p.get("msg"))
    elif message["type"] == "error":
        print("[JS-ERROR]", message.get("description"), message.get("stack", "")[:300])

script = session.create_script(JS)
script.on("message", on_message)
script.load()
t0 = time.time()
while not state["done"] and not state["fatal"] and time.time() - t0 < 840:
    time.sleep(2)
print(f"recebidos {state['asm']} assemblies em {int(time.time()-t0)}s")
