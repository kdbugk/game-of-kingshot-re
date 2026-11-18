#!/usr/bin/env python3
"""Dump the decrypted metadata region (0x6d10000000, 24MB) from live process."""
import frida, sys, time

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
ps = [p for p in device.enumerate_processes() if "Kingshot" in p.name or "tower" in p.name]
if not ps:
    print("sem processo"); sys.exit(1)
print("pid", ps[0].pid)

session = device.attach(ps[0].pid)

# 1) header peek
peek = {}
JS1 = r"""
const base = ptr('0x6d10000000');
const b = base.readByteArray(0x100);
send({}, b);
"""
s1 = session.create_script(JS1)
s1.on("message", lambda m, d: peek.update({"d": d}) if d else None)
s1.load()
time.sleep(4)
hdr = peek.get("d", b"")
print("header 256B:")
for i in range(0, min(len(hdr), 256), 16):
    print(f"  +0x{i:03x}: {hdr[i:i+16].hex()}  {bytes(hdr[i:i+16])}")

# 2) full dump em chunks de 1MB
CHUNK = 1024 * 1024
TOTAL = 24 * 1024 * 1024
OUT = "/home/re/work/apk/metadata_live_dump.bin"
f = open(OUT, "wb")
got = [0]

def make_js(off, size):
    return f"""
const base = ptr('0x6d10000000').add({off});
send({{off: {off}}}, base.readByteArray({size}));
"""

off = 0
while off < TOTAL:
    sz = min(CHUNK, TOTAL - off)
    got_data = {}
    s = session.create_script(make_js(off, sz))
    s.on("message", lambda m, d, g=got_data: g.update({"d": d}) if d else None)
    s.load()
    t0 = time.time()
    while "d" not in got_data and time.time() - t0 < 60:
        time.sleep(0.3)
    if "d" not in got_data:
        print(f"fail at 0x{off:x}"); break
    f.write(got_data["d"]); got[0] += len(got_data["d"])
    off += sz
    if off % (8 * CHUNK) == 0:
        print(f"  {got[0]/1048576:.0f} MB...", flush=True)
f.close()
print(f"TOTAL: {got[0]:,} bytes -> {OUT}")
