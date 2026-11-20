# BLOCK0-K — Gen (sessão onda 2, 2026-11-19)

**Lane iniciada por subagente (32 turns de trabalho) + safeguard matou no meio; completada pelo pai.**
Entregas da criança preservadas em `gen/dec2/` (3 decompiles). Continuação do pai: dumpso + scans.

## O que esta sessão estabeleceu (não re-derivar)

### 1. Convenção de endereços CORRIGIDA (custou 3 tentativas)
- O gerador HTPX `0x1447040` é endereço do **libunity_114.so EMPACOTADO** (região do packer
  0x14xxxxx), NÃO da unity_image desempacotada (que tem só 19,8 MB e não contém o endereço).
- No projeto Ghidra `ghidra_unity/unity` (import do .so packed): endereço = vaddr + **0x100000**
  (base ELF do Ghidra) → **FUN_01547040**.
- No projeto `img` (unity_image.bin): endereços = file offsets, base 0, MAX=0x12e88ff.

### 2. Gerador HTPX confirmado in vitro (decomp `decomp/F_1547040.c`)
- valida magic `0x58505448` ("HTPX"), monta blob {0x04C11EB7, 0x10, 0x82D63B78}, aloca 0x400
  (tabela CRC 256×4), loop bit-a-bit da tabela — bate com htpx_decrypt.py linha a linha.

### 3. O PAR DE BUNDLE (achado da criança, gen/dec2/)
- **F_01444a50 = crypt de BUNDLE**: aceita magic HTPX **OU 0xFAB11BAF** (container Unity!),
  escreve P2 0x82d63b78 no blob, mesma vtable+0x160 de alloc.
- **F_01412580 (40 KB!) = validador/despachante de blocos 4096**: lê em chunks de 0x1000;
  magics cifrados detectados: `0xA6A6A6FB`, `0xA6A9A6A6`, `0xA6B7A6A6`, `0xAEA6A6FB`
  (família 0xA6 = a "janela" do LZ4!); para o magic 0xA6A6A6FB + byte-pattern 0xA6A6A7:
  **varre o bloco procurando "UnityFS" literal** (loop U-n-i-t-y-F-S) = o ponto onde o
  plaintext validado aparece; também caminha +1/+2/+3 para multi-formato.

### 4. Constantes no .so packed
- POLY 0x04C11EB7: **1 ocorrência** em file 0x1296328 (além do blob do HTPX em runtime).
- 0x82D63B78 e CRC32C 0x1EDC6F41: 0 ocorrências estáticas (só via blob construído em runtime).

## Hipótese de trabalho atualizada

O fluxo de bundle: F_01444a50 (crypt/decrypt com blob CRC) ↔ F_01412580 (valida UnityFS em
blocos 0x1000). A keystream de 4096 B do bloco 0 = provavelmente gerada pela MESMA família
do HTPX (blob CRC + RC4-mod + classes) mas com parâmetros do bundle (csz/usz/nome CAB) e
tamanho 4096 — os `alloc(0x400)` vistos são tabelas CRC; o gerador de 4096 deve alocar 0x1000.

## Próximos passos (concretos)

1. Decompile completo do F_01412580 (40KB — DumpFuncs2 já tem o endereço; ler as 3 rotas de
   magic LAB_0141287c/01412900/01412910) + callers (quem chama 0x1412580: scan BL).
2. Caçar `alloc(0x1000)` na região 0x1400000-0x1600000 do .so (padrão vtable+0x160 com 0x1000)
   → o gerador do bloco 0.
3. Re-rodar o emulador do libunity (emu_unpack_unity.py) com hook extra em 0x14a70e0
   (o crypt de bundle que o emu JÁ capturou: cache_crypt_payload.bin 68 MB!) e casar o
   cabeçalho decodificado com o formato F_01412580.
4. Reproduzir em Python (modelo htpx_decrypt.py) e validar: ≥95% bundles → LZ4 → UnityFS.

## Artefatos

- `gen/dec2/F_1412580.c`, `F_1444a50.c`, `F_14479b8.c` (criança) + `decomp/F_1547040.c` (pai)
- `dumpso.log` (prova da convenção +0x100000), `getbase.log` (base do img=0)
