#!/usr/bin/env python3
"""BULLETPROOF runtime dump: manages frida-server, waits for user-opened game,
retries every phase internally. One command, one game-open, done."""
import frida, sys, time, subprocess
from pathlib import Path

OUT_DIR = Path("/home/re/work/apk/il2cpp_dump_114")
OUT_DIR.mkdir(exist_ok=True)
SUMMARY = "/home/re/work/apk/il2cpp_dump_114_summary.txt"
LOG = lambda *a: print(*a, flush=True)

def sh(cmd):
    subprocess.run(["adb", "shell", cmd], capture_output=True, timeout=30)

def restart_server():
    LOG("[*] reiniciando frida-server...")
    sh("/debug_ramdisk/su -c 'pkill -f fs17'")
    time.sleep(2)
    sh("/debug_ramdisk/su -c 'nohup /data/local/tmp/fs17 -l 0.0.0.0:37555 -D >/dev/null 2>&1 &'")
    time.sleep(4)

def get_device():
    for _ in range(5):
        try:
            d = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
            d.enumerate_processes()
            return d
        except Exception as e:
            LOG("  device retry:", str(e)[:80]); time.sleep(4); restart_server()
    return None

restart_server()
device = get_device()
if not device:
    LOG("[X] frida-server não responde"); sys.exit(1)

LOG("[*] ABRIR O JOGO NO CELULAR (janela de 10 min)...")
pid = None
t0 = time.time()
while time.time() - t0 < 600:
    try:
        ps = [p for p in device.enumerate_processes() if p.name == "Kingshot"]
        if ps: pid = ps[0].pid; break
    except Exception:
        time.sleep(5); restart_server(); device = get_device()
    time.sleep(3)
if not pid:
    LOG("[X] jogo não apareceu"); sys.exit(1)
LOG(f"[*] jogo pid={pid} — 45s boot"); time.sleep(45)

PHASE1 = r"""
'use strict';
(function () {
const N=(p)=>Number(p.toString());
const mod = Process.findModuleByName('libil2cpp.so');
if (!mod) { send({type:'table', best:null, err:'no module'}); return; }
const dg  = new NativeFunction(mod.getExportByName('il2cpp_domain_get'), 'pointer', []);
const dga = new NativeFunction(mod.getExportByName('il2cpp_domain_get_assemblies'), 'pointer', ['pointer','pointer']);
const domain = dg();
const szp = Memory.alloc(4);
const arr = dga(domain, szp);
const n = szp.readU32();
send({type:'check', n:n, base:mod.base.toString()});
if (n < 50) { send({type:'table', best:null, err:'cold: '+n}); return; }
const samples = [];
for (let i = 0; i < n; i++) samples.push(N(arr.add(i*8).readPointer()));
samples.sort((a,b)=>a-b);
const loN = samples[0], hiN = samples[samples.length-1];
const W = 0x20000000;
let best = null;
const ranges = Process.enumerateRanges('rw-');
for (const r of ranges) {
  if (r.size < 0x40000 || r.size > 0x8000000) continue;
  const rn = N(r.base);
  if (rn < loN - W || rn > hiN + W) continue;
  try {
    let run = 0, runStart = null;
    for (let off = 0; off + 8 <= r.size; off += 8) {
      const p = N(r.base.add(off).readPointer());
      if (p >= loN - W && p <= hiN + W) {
        if (run === 0) runStart = r.base.add(off);
        run++;
        if (run >= 2000 && (!best || run > best.run)) best = {base: runStart.toString(), run: run};
        if (run > 120000) break;
      } else { run = 0; }
    }
  } catch (_) {}
}
send({type:'table', best: best, n: n});
})();
"""

def run_script(js, timeout_s, want_key):
    """attach+load com retries; retorna payload dict ou None"""
    for attempt in range(3):
        try:
            session = device.attach(pid)
            out = {}
            s = session.create_script(js)
            s.on("message", lambda m, d: out.update(m.get("payload", {})) if m["type"] == "send" else LOG("  [ERR]", m.get("description", str(m))[:120]))
            s.load()
            t0 = time.time()
            while want_key not in out and time.time() - t0 < timeout_s:
                time.sleep(2)
            if want_key in out:
                return out
            LOG(f"  fase sem resposta (tentativa {attempt+1})")
        except Exception as e:
            LOG(f"  attach/load retry {attempt+1}: {str(e)[:100]}")
            time.sleep(5); restart_server()
            nonlocal_dev = get_device()
            if nonlocal_dev is None: return None
            globals()["device"] = nonlocal_dev
    return None

p1 = run_script(PHASE1, 150, "best")
LOG("[*]", p1)
if not p1 or not p1.get("best"):
    LOG("[X] tabela não achada"); sys.exit(1)
BASE = p1.get("base") or ""
TB = p1["best"]["base"]; RUN = p1["best"]["run"]
LOG(f"[*] base={BASE} tabela={TB} run={RUN}")

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

assemblies = {}
done = [False]
def collector(m, d):
    if m["type"] == "send":
        p = m["payload"]; t = p.get("type")
        if t == "assembly" and d:
            assemblies[p["name"]] = bytes(d)
        elif t == "all_sent":
            done[0] = True; LOG(f"[all_sent] {p}")

for attempt in range(3):
    try:
        session = device.attach(pid)
        s2 = session.create_script(PHASE2)
        s2.on("message", collector)
        s2.load()
        t0 = time.time()
        while not done[0] and time.time() - t0 < 420:
            time.sleep(3)
        if assemblies:
            break
    except Exception as e:
        LOG(f"  phase2 retry {attempt+1}: {str(e)[:100]}"); time.sleep(5)

for i, (name, data) in enumerate(sorted(assemblies.items())):
    (OUT_DIR / f"{i:03d}_{name.replace('/', '_')}.json").write_bytes(data)
Path(SUMMARY).write_text(f"images: {len(assemblies)}\nbase: {BASE}\ntable: {TB}\nrun: {RUN}\n")
LOG(f"[DONE] {len(assemblies)} imagens -> {OUT_DIR}")
