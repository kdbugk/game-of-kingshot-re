# Bloco 0 (Kingshot) — análise de libunity.so (PARCIAL, NÃO resolvido)

## Resumo
- **Premissa corrigida:** `libunity.so` (v1.14.27, 20.984.064 B) **NÃO é um ELF limpo**. Está empacotada com o MESMO packer HTProtect do libil2cpp: bytes 0x238..0x800000 com entropia 8.0 (cifrado), seções falsas (`.note.gnu.proc` de 19 MB), 0 strings "UnityFS"/"Archive"/"Block" no arquivo.
- O stub (.note.gnu.text, 738.208 B) é 98,8% idêntico ao do libil2cpp → funções nos mesmos offsets relativos. Derivado:
  CRYPT=0x1401e48, DECOMP=0x140fa9c, DRIVER=0x1407b64 (match 256/256 bytes com il2cpp),
  ctors (init_array @0x149b018, via RELA em file 0x128a640): 0x148eeb4,0x148f384,0x14733f0,0x1473c5c,0x1474354,0x145bffc,0x1469f1c;
  globals CFG=0x14a1168 / HDR=0x14a1158 (deslocamento -0x3448000 vs il2cpp).
- **Desempacotado offline com sucesso** via Unicorn (`C:/Users/prs/work/emu_unpack_unity.py`, adaptado do emu_unpack.py):
  crypt_out_1 (19.426.144 B) = [u32 usize=0x12e8900][u32 csize=0x800ee5][zlib 78 9c…] → inflate = **19.826.944 B** (`C:/Users/prs/work/unity_image.bin`, imagem vaddr==offset, base 0). Contém strings (ex. "UnityFS"@0xff392, "UnityWeb"@0x110be2, "UnityRaw"@0xe77b5, "Failed to decompress data for the AssetBundle"@0x1450cb) e código (~0x100000–0x1287dc8, 117k ADRP). O cabeçalho ELF original não está presente (importar como binário cru AARCH64, base 0 — feito: projeto Ghidra `C:/Users/prs/work/ghidra_unity`, programa `img`).
- A parte B (crypt_out_0, 768 KB @0x14a70e0) é a config/estrutura do packer (não zlib), irrelevante.

## O que NÃO foi achado
- Nenhuma referência de código (ADRP+ADD, janela 60 insts) às strings "UnityFS", "UnityWeb", "UnityRaw", "…invalid crc", "Failed to read data…", "not a valid AssetBundle". Nenhum compare imediato de "UnityFS" (movz/movk 0x6e55,0x7469,0x4679,0x5346: só falsos positivos "UnityIns…"/"density_"). Nenhuma imediata 0x1615/0x1616/0x0a16/0x0b16 (só um falso 0xa16 @0xf296d8).
- Única ref útil: 0x4f3634 (FUN_004f3608) usa "Failed to decompress data for the AssetBundle" num laço genérico — não é o leitor.
- Heurística LZ4 (and #0xf, lsr #4, cmp #0xff/#0xf) apontou 0xb1f800, 0xf0d400, 0xf0f400, 0xf2dc00; 0xf0f800 decompilado = tracker de áudio (falso positivo). Ghidra em modo binário cru descobre poucas funções automaticamente (funções criadas on-demand pelo script).
- Interpretação: o ramo de leitura de bundles (ArchiveStorageReader) provavelmente está ofuscado/sem referência direta por string, ou fora da imagem estática (ex.: código em memória pós-relocação/stub, ou lido via ponteiros de vtable). Nenhuma evidência decompilada do formato do bloco 0 → **sem decryptor** (Deliverable B não entregue; nada de chute).

## Próximos passos sugeridos
1. Em `unity_image.bin`, aplicar as RELATIVE relocs (RELA @ file 0x128a640, 1342 entradas, addend=ponteiro) e importar com ponteiros resolvidos para achar vtables/ponteiros p/ strings (UnityFS pode ser referenciada por tabela, não por ADRP).
2. Identificar LZ4_decompress por assinatura (decompress_generic) e listar callers; procurar o caller que lê header de 8 B (u16 0x16, u16 1, u16 0x1615/6, u16 0x0a/0x0b) antes de chamar LZ4 — o bloco 0 usa `m_FileSize` cru no offset 16.
3. Alternativa dinâmica (fora do escopo; não toquei no celular): hook em LZ4 durante abertura de bundle com Frida.

## Artefatos
- `C:/Users/prs/work/unity_image.bin` — libunity desempacotado (stage 2), base 0.
- `C:/Users/prs/work/emu_unpack_unity.py`, `scan.py` (scanner ADRP/ADD), `dec.sh` + `gscripts_unity/DecompAt.java` (decompila endereços), `reports_unity/d1..d4.txt` (decompilações dos candidatos, todos falsos positivos).
