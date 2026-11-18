#!/usr/bin/env python3
"""Dump raw bytes of first class objects from the global type table."""
import frida, sys, time, json

device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
ps = [p for p in device.enumerate_processes() if "Kingshot" in p.name or "tower" in p.name]
if not ps:
    print("sem processo"); sys.exit(1)

JS = r"""
'use strict';
const tb = ptr('0x6d106fbd20');
const out = [];
for (let i = 0; i < 3; i++) {
  const k = tb.add(i*8).readPointer();
  const bytes = k.readByteArray(0x140);
  send({ i: i, klass: k.toString() }, bytes);
}
"""
session = device.attach(ps[0].pid)
chunks = []
script = session.create_script(JS)
script.on("message", lambda m, d: chunks.append((m.get("payload", {}), d)) if m["type"] == "send" else print("ERR", m))
script.load()
time.sleep(10)

for p, data in chunks:
    k = p["klass"]
    b = bytes(data)
    print(f"\n── klass[{p['i']}] @ {k}")
    for off in range(0, len(b), 16):
        row = b[off:off+16]
        hexs = " ".join(f"{x:02x}" for x in row)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in row)
        # interpreta como 2 ptrs
        import struct as st
        p1, p2 = st.unpack_from("<QQ", b, off) if off + 16 <= len(b) else (0, 0)
        print(f"  +0x{off:03x}: {hexs:<48} {asc:<16} | {p1:#018x} {p2:#018x}")
