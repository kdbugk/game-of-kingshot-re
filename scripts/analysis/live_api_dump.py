#!/usr/bin/env python3
"""Live-attach il2cpp API dump: no waiting for il2cpp_init, run immediately."""
import frida, sys, time
from pathlib import Path

APP_MATCH = ("Kingshot", "tower")
OUTPUT_DIR = Path("/home/re/projects/game-of-kingshot-re/dump/il2cpp_dump")
OUTPUT_DIR.mkdir(exist_ok=True)
SUMMARY_FILE = "/home/re/projects/game-of-kingshot-re/dump/il2cpp_dump_summary.txt"

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
ps = [p for p in device.enumerate_processes() if any(m in p.name for m in APP_MATCH)]
if not ps:
    print("processo não encontrado"); sys.exit(1)
pid = ps[0].pid
print(f"[+] attach live pid={pid}")

JS = open("/home/re/projects/game-of-kingshot-re/dump/il2cpp_api_dump.js", encoding="utf-8").read()
# substitui o main() por execução imediata
JS = JS.split("function main()")[0]  # corta o main antigo
JS += """
(function() {
  const poll = setInterval(() => {
    const mod = Process.findModuleByName('libil2cpp.so');
    if (!mod) return;
    clearInterval(poll);
    console.log('[+] libil2cpp.so: base=' + mod.base + ' — dump imediato');
    setTimeout(runDump, 300);
  }, 100);
})();
"""

session = device.attach(pid)
state = {"asm": 0, "done": False}

def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        if not isinstance(payload, dict):
            print(payload); return
        t = payload.get("type")
        if t == "assembly":
            idx, name, count = payload["index"], payload["name"], payload["class_count"]
            if data:
                out = OUTPUT_DIR / f"{idx:03d}_{name.replace('/', '_')}.json"
                out.write_bytes(data)
            state["asm"] += 1
            print(f"[DUMP] {idx:03d} {name} classes={count}", flush=True)
        elif t == "dump_complete":
            state["done"] = True
            Path(SUMMARY_FILE).write_text(
                f"assemblies: {payload.get('assemblies')}\nclasses: {payload.get('classes')}\n"
                f"methods: {payload.get('methods')}\n")
            print(f"[DONE] {payload}")
    elif message["type"] == "error":
        print("[JS-ERROR]", message.get("description"))

script = session.create_script(JS)
script.on("message", on_message)
script.load()
t0 = time.time()
while not state["done"] and time.time() - t0 < 840:
    time.sleep(2)
print(f"recebidos: {state['asm']} assemblies em {int(time.time()-t0)}s")
