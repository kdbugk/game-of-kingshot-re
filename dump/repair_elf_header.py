"""
repair_elf_header.py
Repara o ELF header de libil2cpp_decrypted.so.

O SDK de proteção corrompe deliberadamente os primeiros ~56 bytes do ELF em
memória para frustrar dumps. Os campos críticos que sobreviveram intactos:
  e_phoff  = 0x40  (program headers no offset padrão ELF64)
  e_phnum  = 7     (7 segmentos PT_LOAD)

Todos os outros campos são conhecidos (ARM64 shared library).
"""

import struct, shutil
from pathlib import Path

SRC  = Path(__file__).parent / "libil2cpp_decrypted.so"
DEST = Path(__file__).parent / "libil2cpp_fixed.so"

def main():
    if not SRC.exists():
        print(f"[!] {SRC} não encontrado")
        return

    print(f"[+] Copiando {SRC.name} → {DEST.name}...")
    shutil.copy2(SRC, DEST)

    with open(DEST, "r+b") as f:
        # ── e_ident (bytes 0..15) ──────────────────────────────────────────
        f.seek(0)
        f.write(b'\x7f\x45\x4c\x46')   # 0x00  magic: \x7fELF
        f.write(b'\x02')                # 0x04  EI_CLASS:   ELFCLASS64
        f.write(b'\x01')                # 0x05  EI_DATA:    ELFDATA2LSB (LE)
        f.write(b'\x01')                # 0x06  EI_VERSION: EV_CURRENT
        f.write(b'\x00' * 9)            # 0x07  EI_OSABI + padding

        # ── e_type / e_machine / e_version (bytes 16..23) ─────────────────
        f.seek(16)
        f.write(struct.pack('<H', 3))   # 0x10  e_type:    ET_DYN (shared library)
        f.write(struct.pack('<H', 183)) # 0x12  e_machine: EM_AARCH64 = 0xB7
        f.write(struct.pack('<I', 1))   # 0x14  e_version: EV_CURRENT

        # e_entry (0x18..0x1f): zero para .so — já está correto

        # e_phoff (0x20..0x27): 0x40 — já está correto no dump!
        # e_shoff (0x28..0x2f): zero (sem section headers no dump stripped)
        # e_flags (0x30..0x33): zero (ARM64 não usa flags obrigatórias)

        # ── e_ehsize / e_phentsize (bytes 52..55) ─────────────────────────
        f.seek(52)
        f.write(struct.pack('<H', 64))  # 0x34  e_ehsize:   64 bytes (ELF64 header)
        f.write(struct.pack('<H', 56))  # 0x36  e_phentsize: 56 bytes (PT_LOAD ELF64)

        # e_phnum (0x38..0x39): 7 — já está correto no dump!
        # e_shentsize / e_shnum / e_shstrndx: zero (stripped)

    print(f"[+] Header reparado em {DEST.name}")

    # ── Verificar program headers ──────────────────────────────────────────
    with open(DEST, "rb") as f:
        f.seek(0)
        hdr = f.read(64)
        f.seek(0x40)
        ph_data = f.read(56 * 20)  # até 20 program headers

    print(f"\n[+] Verificando program headers @ offset 0x40:")
    PT_NAMES = {
        0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP',
        4: 'NOTE',  6: 'PHDR', 7: 'TLS',
        0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK',
        0x6474e552: 'GNU_RELRO',    0x70000001: 'ARM_EXIDX',
    }
    PF = lambda f: ('r' if f&4 else '-') + ('w' if f&2 else '-') + ('x' if f&1 else '-')

    e_phnum = struct.unpack_from('<H', hdr, 56)[0]
    ok = True
    for i in range(e_phnum):
        off  = i * 56
        ph   = ph_data[off:off+56]
        if len(ph) < 56:
            print(f"  [{i}] dados insuficientes")
            ok = False
            break
        p_type   = struct.unpack_from('<I', ph,  0)[0]
        p_flags  = struct.unpack_from('<I', ph,  4)[0]
        p_offset = struct.unpack_from('<Q', ph,  8)[0]
        p_vaddr  = struct.unpack_from('<Q', ph, 16)[0]
        p_filesz = struct.unpack_from('<Q', ph, 32)[0]
        p_memsz  = struct.unpack_from('<Q', ph, 40)[0]
        name     = PT_NAMES.get(p_type, f'0x{p_type:08x}')
        print(f"  [{i}] {name:<16} {PF(p_flags)}  "
              f"offset=0x{p_offset:08x}  vaddr=0x{p_vaddr:08x}  "
              f"filesz=0x{p_filesz:08x}  ({p_filesz/1024/1024:.1f}MB)")

    if ok:
        print(f"\n[+] ELF válido — carregue '{DEST.name}' no Ghidra como ELF AArch64")
        print(f"    Language: AARCH64:LE:64:v8A")
        print(f"    (File → Import File → selecione o .so → OK)")

if __name__ == "__main__":
    main()
