#!/usr/bin/env python3
"""Try FUN_04949e48 (unpacker cipher) against the HTPX global-metadata body.
Replays the exact register pattern observed when it decrypted the payload."""
import struct, zlib, sys
from unicorn import *
from unicorn.arm64_const import *

# ── build emulator exactly like emu_unpack (factored version) ──
exec(open("/mnt/c/Users/prs/projects/game-of-kingshot-re/scripts/analysis/emu_unpack.py").read().split("print(\"\\n\".join(log))")[0])

# state: ctors done, driver called once via ctor_4 (+ explicit once above is fine)
META_ADDR = 0x600010000000
meta = open("/home/re/work/apk/xapk/base_extract/assets/bin/Data/Managed/Metadata/global-metadata.dat", "rb").read()
uc.mem_map(META_ADDR & ~0xFFF, (len(meta) + 0xFFFF) & ~0xFFF, UC_PROT_ALL)
uc.mem_write(META_ADDR, meta)
DST = 0x600020000000
uc.mem_map(DST, (len(meta) + 0xFFFF) & ~0xFFF, UC_PROT_ALL)

# replay register pattern from the payload crypt call:
# X0=src X1=sz X2=dst X3=sz X4=-1 X5=-1 X6=keystore(empty str addr used before)
keyptr = captured["crypt"][-1].get("keyptr", 0)
if not keyptr:
    keyptr = halloc(0x100)  # empty string
    uc.mem_write(keyptr, b"\0")

body = len(meta) - 8
for name, src, sz in [("meta+8", META_ADDR + 8, body), ("meta+0", META_ADDR, len(meta))]:
    out = run(CRYPT, src, sz, DST, sz, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, keyptr)
    blob = bytes(uc.mem_read(DST, min(sz, 64)))
    print(f"{name}: x0_ret={uc.reg_read(UC_ARM64_REG_X0):#x} head={blob[:32].hex()}")
    full = bytes(uc.mem_read(DST, sz))
    if blob[:2] == b"\x78\x9c":
        print("  *** ZLIB! inflating...")
        try:
            inf = zlib.decompressobj().decompress(full)
            print(f"  inflated {len(inf):,} magic={inf[:8].hex()}")
            open("/home/re/work/apk/global_metadata_try.bin", "wb").write(inf)
        except Exception as e:
            print("  inflate fail:", e)
    if blob[:4] == b"\xaf\x1b\xb1\xfa":
        print("  *** IL2CPP METADATA MAGIC!")
        open("/home/re/work/apk/global_metadata_decrypted.dat", "wb").write(full)
        break
