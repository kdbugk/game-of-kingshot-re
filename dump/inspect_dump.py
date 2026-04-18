"""
inspect_dump.py
Inspeciona o dump de libil2cpp.so:
  1. Mostra os 64 bytes do ELF header
  2. Tenta ler os program headers (PT_LOAD)
  3. Verifica se o código no offset 0x1943450 está decriptado (era UDF #0xa1 no Ghidra)
  4. Busca a string "global-metadata" no dump
"""

import struct, sys
from pathlib import Path

DUMP = Path(__file__).parent / "libil2cpp_decrypted.so"
OFFSET_OPEN_CALLER = 0x1943450  # instrução que chama open64 (endereço de retorno - 4)

def hexline(data, offset=0, cols=16):
    lines = []
    for i in range(0, len(data), cols):
        chunk = data[i:i+cols]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset+i:08x}:  {hex_part:<{cols*3}}  {ascii_part}")
    return "\n".join(lines)

def main():
    if not DUMP.exists():
        print(f"[!] Arquivo não encontrado: {DUMP}")
        sys.exit(1)

    data = DUMP.read_bytes()
    size = len(data)
    print(f"[+] Tamanho do dump: {size / 1024 / 1024:.2f} MB  ({size} bytes)\n")

    # ── 1. ELF header (64 bytes) ──────────────────────────────────────────────
    hdr = data[:64]
    print("=== ELF Header (primeiros 64 bytes) ===")
    print(hexline(hdr))
    print()

    magic = hdr[:4]
    print(f"  magic    : {magic.hex()}  ({'OK - 7fELF' if magic == b'\\x7fELF' else 'CORROMPIDO'})")

    if len(hdr) >= 64:
        e_class    = hdr[4]
        e_data     = hdr[5]
        e_machine  = struct.unpack_from('<H', hdr, 18)[0]
        e_phoff    = struct.unpack_from('<Q', hdr, 32)[0]
        e_shoff    = struct.unpack_from('<Q', hdr, 40)[0]
        e_ehsize   = struct.unpack_from('<H', hdr, 52)[0]
        e_phentsize= struct.unpack_from('<H', hdr, 54)[0]
        e_phnum    = struct.unpack_from('<H', hdr, 56)[0]
        e_shnum    = struct.unpack_from('<H', hdr, 58)[0]

        print(f"  e_class  : {e_class}  ({'64-bit' if e_class == 2 else '32-bit ou corrompido'})")
        print(f"  e_data   : {e_data}  ({'LE' if e_data == 1 else 'BE ou corrompido'})")
        print(f"  e_machine: 0x{e_machine:04x}  ({'AArch64' if e_machine == 0xb7 else 'outro'})")
        print(f"  e_phoff  : 0x{e_phoff:x}  (offset dos program headers)")
        print(f"  e_phentsize: {e_phentsize}  e_phnum: {e_phnum}")
        print(f"  e_shoff  : 0x{e_shoff:x}  e_shnum: {e_shnum}")
    print()

    # ── 2. Program headers ────────────────────────────────────────────────────
    print("=== Program Headers ===")
    e_phoff_val = struct.unpack_from('<Q', hdr, 32)[0] if len(hdr) >= 64 else 0
    e_phnum_val = struct.unpack_from('<H', hdr, 56)[0] if len(hdr) >= 64 else 0
    e_phent_val = struct.unpack_from('<H', hdr, 54)[0] if len(hdr) >= 64 else 56

    PT_LOAD = 1
    PT_NAMES = {0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP',
                4: 'NOTE', 6: 'PHDR', 7: 'TLS', 0x6474e550: 'GNU_EH_FRAME',
                0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO'}

    if e_phoff_val == 0 or e_phoff_val > size:
        print("  [!] e_phoff inválido — header provavelmente corrompido além do magic")
        # Tentar offset padrão para ELF64 (imediatamente após o header = 0x40)
        e_phoff_val = 0x40
        e_phent_val = 56
        print(f"  [*] Tentando offset padrão 0x40 (ELF64 padrão)...")
        print(hexline(data[0x40:0x40+56*4], offset=0x40))
    else:
        for i in range(min(e_phnum_val, 20)):
            off = e_phoff_val + i * e_phent_val
            if off + e_phent_val > size:
                break
            ph = data[off:off + e_phent_val]
            p_type   = struct.unpack_from('<I', ph, 0)[0]
            p_flags  = struct.unpack_from('<I', ph, 4)[0]
            p_offset = struct.unpack_from('<Q', ph, 8)[0]
            p_vaddr  = struct.unpack_from('<Q', ph, 16)[0]
            p_filesz = struct.unpack_from('<Q', ph, 32)[0]
            p_memsz  = struct.unpack_from('<Q', ph, 40)[0]
            name     = PT_NAMES.get(p_type, f'0x{p_type:08x}')
            flags    = ('r' if p_flags & 4 else '-') + ('w' if p_flags & 2 else '-') + ('x' if p_flags & 1 else '-')
            print(f"  [{i}] {name:<16} flags={flags}  offset=0x{p_offset:08x}"
                  f"  vaddr=0x{p_vaddr:08x}  filesz=0x{p_filesz:08x}")
    print()

    # ── 3. Verificar código no offset do caller de open64 ────────────────────
    print(f"=== Código em offset 0x{OFFSET_OPEN_CALLER:x} (caller de open64) ===")
    if OFFSET_OPEN_CALLER + 16 <= size:
        code_bytes = data[OFFSET_OPEN_CALLER:OFFSET_OPEN_CALLER + 16]
        print(hexline(code_bytes, offset=OFFSET_OPEN_CALLER))
        # UDF #0xa1 = a1 00 00 00 — se ainda for isso, a decriptação não funcionou
        if code_bytes[:4] == b'\xa1\x00\x00\x00':
            print("  [!] Ainda é UDF #0xa1 — código NÃO decriptado nesse offset")
        else:
            print("  [+] Bytes diferentes de UDF #0xa1 — parece decriptado!")
    else:
        print("  [!] Offset fora do dump")
    print()

    # ── 4. Busca string "global-metadata" ────────────────────────────────────
    print("=== Busca por strings relevantes ===")
    for needle in [b"global-metadata", b"Metadata", b"il2cpp/Metadata", b"HTPX", b".text"]:
        idx = data.find(needle)
        if idx >= 0:
            ctx = data[max(0, idx-8):idx+len(needle)+24]
            print(f"  '{needle.decode()}' @ 0x{idx:08x}")
            print(hexline(ctx, offset=max(0, idx-8)))
        else:
            print(f"  '{needle.decode()}' : não encontrado")
    print()

if __name__ == "__main__":
    main()
