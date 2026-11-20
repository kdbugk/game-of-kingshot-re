# Formato da "Part B" do packer (libil2cpp.so) — gramática, evidência e imagem reconstruída

## Resumo
A "part B" (blob decifrado, `crypt_out_0_0x491aed8.bin` / `crypt_195_0_0x4582ed8.bin`) **não é uma tabela de records (type,id) própria**.
É o **conteúdo dinâmico do ELF original**, sem o código: *phdrs originais + .dynsym (imports) + .rela.dyn/.rela.plt (428 774 relocs) + .dynamic (cauda)*.
Os pares `[01][04]`, `[01][05]`, `[01][06]`, `[02][06]` do início são `p_type, p_flags` de `Elf64_Phdr` (PT_LOAD R/RX/RW/RW, PT_DYNAMIC RW).
O que falta na parte A para "completar" o RW é aplicar as relocações: **R_AARCH64_RELATIVE (0x403) preenche .data.rel.ro/.data/.got/vtables/metadata-registration com ponteiros**.
`FUN_04950088` (tabela de rebase + CRC32C) é outra coisa (estrutura interna do unpacker); não consome este blob.

## Gramática (offsets dentro do blob; válida nas duas versões)
Descritor (no wrapper, 0xb0 bytes antes do ciphertext; 1.14.27 em file 0x41eee28; u64[i]):

| idx | valor 1.14.27 | significado (confirmado por F_494d470 / F_494f650) |
|---|---|---|
| [2] | 0x188 | offset de Elf64_Sym[] no blob (logo após phdrs) |
| [3] | 0x48ff2a8 | vaddr do dynstr do wrapper |
| [4]=[5] | 0x1d30 | offset do início de Elf64_Rela[] |
| [6]=[8] | 0x9d22c0 | offset do .dynamic (cauda) |
| [9] | 0xb0 | offset do ciphertext após o descritor |
| [0xd] | 7 | nº de phdrs (blob+0, 56 B cada) |
| [0xe] | 0x68ae6 = **428 774** | **nº de relocs** |
| u32@0x84 | 0x4101400 | tamanho da parte A decifrada |
| u32@0x88 | 0x9d2380 | tamanho do blob (= malloc de F_494d470) |

Layout:
```
0x000   Elf64_Phdr[7]            (LOAD R 0..0x1720f14 | LOAD RX 0x1724f14.. | LOAD RW 0x4109400 | LOAD RW 0x43c1970 (bss) | DYNAMIC 0x43303a0 | EH_FRAME | NOTE)
0x188   Elf64_Sym[295]           null + 294 imports (shndx=0,value=0; info 0x12 FUNC ×292, 0x11 OBJECT ×1; st_size usado como marca 2/3). Nomes = índices no dynstr (ofuscado)
0x1d30  Elf64_Rela[428774]       (r_offset, r_info, r_addend) 24 B  → termina exatamente em 0x9d22c0
0x9d22c0 .dynamic truncada       NEEDED×5, INIT_ARRAY 0x43302e0/0xc0, FINI_ARRAY 0x43302d0/0x10, VERNEED 0x11158, VERNEEDNUM 3, NULL
```
Tipos de reloc: 0x403 RELATIVE (428 481), 0x402 JUMP_SLOT (286), 0x401 GLOB_DAT (3), 0x101 ABS64 (4). `info>>32` indexa Elf64_Sym[] do blob (máx 294 < 295 ✓).
Semântica: RELATIVE → `*(base+r_offset) = base + r_addend` (base 0 na imagem estática).

## Evidência nas DUAS versões
| | 1.14.27 | 1.9.5 |
|---|---|---|
| nº phdrs / nsym | 7 / 295 | 7 / 295 |
| relocs | 428 774 (= campo [0xe] 0x68ae6 ✓) | 406 715 |
| rela termina == início .dynamic | 0x9d22c0 ✓ | 0x950eb8 ✓ |
| RELATIVE (r_offset dentro dos LOAD RW) | 428 481 / 428 481 | 406 422 / 406 422 |
| addend dentro da imagem | 428 478 (3 fora) | 406 419 (3 fora) |
| ponteiros p/ R/RX, 4-alinhados | 100 % (207 504) | 100 % (185 151) |
| amostra 2000 alvos RX com palavra ≠ 0 | 2000 | 2000 |
| JUMP_SLOT 286 / GLOB_DAT 3 / ABS64 4 | idem | idem |

O mesmo parser (sem constantes por versão) encaixa em ambas; só tamanhos mudam.

## Imagens geradas (WSL kingshot-re, ~/work/apk/)
- `libil2cpp_114_full.so` (75 661 312 B): libil2cpp_114_decrypted.so + 428 481 ponteiros RELATIVE aplicados + ELF header/4 PT_LOAD originais (file offset == vaddr, base 0).
- `libil2cpp_195_full.so` (73 312 520 B): partA_inflated.bin + 406 422 ponteiros + mesmo header.
- Parser: `/mnt/c/Users/prs/work/laneE/partb_build.py` (cópia em ~/work/apk/), validação `val.py`.
  Uso: `python3 partb_build.py <blob> <partA flat> <out.so>`.
- Importar no Ghidra: processador AArch64, **base 0**; as 4 PT_LOAD vêm do header.

## Limites / o que NÃO foi feito (sem chute)
1. **GLOB_DAT/JUMP_SLOT/ABS64 (293 slots)** ficam 0 (imports libc/liblog; não há endereço).
2. **Dados RW não-relocados** (inteiros/contagens em .data, ex.: contadores de CodeRegistration) **não estão no blob**; só existe o que a parte A traz até 0x4104000. Ver se estão em outro stream do unpacker — ainda não localizado. Ponteiros (o principal para xrefs) estão completos.
3. **dynstr é ofuscado no wrapper** (strings tipo `B|n5:Bn76FI…`, exceto libc/NEEDED em claro); `il2cpp_init` **não** é encontrável em claro no dynstr. A checagem "dynstr em 0x48ff2a8 com il2cpp_init" falha por isso, não por erro de parse. O dynsym do blob é só de IMPORTS (nomes ofuscados também); os exports il2cpp_* estão no symtab do wrapper (0x48eba88, 3329 entradas, nomes ofuscados). Decifrar a ofuscação do dynstr é o passo seguinte p/ nomear exports (padrão do tipo "tabela XOR/translit" — não analisado).
4. A imagem não tem section headers nem .dynamic funcional (só PT_LOAD); Ghidra tratará como blob AArch64 por segmento. Dica: criar funções/entries manualmente via exports resolvidos (`JNI_OnLoad` etc.).
5. 3 relocs RELATIVE com addend fora da imagem (provável sentinela) — mantidos como estão.
