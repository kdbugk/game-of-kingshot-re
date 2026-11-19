# libunity 1.14.27 — caminho de leitura de bundles (rodada 2) — PARCIAL

Status: caminho UnityFS→LZ4 mapeado e decompilado; **nenhum tratamento especial do bloco 0 / transform XOR 0xA6 encontrado em nenhuma função desse caminho**. Todo o stack de leitura em libunity é Unity stock. Conclusão provável: o transform está FORA do leitor de archive (camada de arquivo/handler abaixo dele, ou hook do HTProtect/NetHTProtect). Detalhes e próximos passos no fim.

## 1. Mapeamento da imagem (corrigido)
`unity_image.bin` (19.826.944 B) NÃO é identidade vaddr==offset para código:
- **Código**: vaddr = file_offset + 0x4000. Prova: varredura ADRP+ADD contra 11.660 strings de .rodata → shift líquido 0x4000 domina em todo o código (ex. 311–751 refs/MB vs ≤30 nos outros shifts); estático: 7 refs a "UnityWeb" (0x110be2) só aparecem com +0x4000 (0x681638..0x6843d8 file → 0x685638.. vaddr).
- **Dados/rodata**: vaddr = file_offset (strings, ponteiros nos relocs).
- Vtables/ponteiros em RW (>0x128eb60) não estão no .bin: **os RELATIVE relocs de libunity estão na "parte B"** `unity_unpack/crypt_out_0_0x14a70e0.bin` (31.148 entradas Elf64_Rela {off, 0x403, addend}, slots 0x128eb60..0x12f6xxx). Addend de ponteiro p/ código = vaddr de código (já com +0x4000); p/ string = file offset. Dump parseado: `laneN/rel.pkl` (lista (slot, addend)).
- Ghidra: projeto `C:/Users/prs/work/ghidra_unity2` (programa `unity_image.bin`, Raw Binary AARCH64, base 0x4000 → endereços Ghidra de código == vaddr corretos; ponteiros de dados nas decompilações aparecem como file-offset, ex.: 0x110be2 = "UnityWeb"). Scripts: `laneN/dec.sh <out> <vaddr...>` (usa gs/DecompAt.java), `laneN/callers.py`, `laneN/fs.py` (acha início de função), `laneN/x.py,z.py,y.py,xs.py` (scans).
- Por que a rodada 1 falhou nas xrefs: "UnityFS" (0xff392) é referenciado por **ponteiro relocado** (slot 0x12defa0 → 0xff392) e carregado via LDR de dado, não ADRP+ADD; e o mapeamento de código estava com shift errado.

Strings-chave: "UnityFS" 0xff392, "UnityArchive" 0xcb739, "UnityWeb" 0x110be2, "UnityRaw" 0xe77b5, "Failed to decompress data for the AssetBundle" 0x1450cb.

## 2. Caminho de código (todos vaddr; decompilação em laneN/d1..d17.c)
```
FUN_0089307c  (Open bundle/ArchiveFileSystem::Mount; d2.c)
  ├ FUN_00690758(entry,&path) -> FUN_0068d008 -> FUN_0068f704(registry global @0x135e738,path) -> handler->vtbl[0x78]
  ├ FUN_00687da0(reader,0x3c)         ctor ArchiveStorageReader (obj 0xae8 B, vtable 0x1296328)
  └ FUN_0068171c(reader,path,&offset,1,1)   <- 'offset' = LoadFromFile offset (BundleEncryptOffset) ; d3.c
       ├ FUN_00682d68                 open/validate arquivo
       └ FUN_006881c8(reader, offset)         ReadHeader  ; d4.c
            ├ FUN_006855ec(stream,hdr)   lê assinatura; compara com ptr@0x12defa0 ("UnityFS"), 0xcb739 "UnityArchive", 0x110be2 "UnityWeb", 0xe77b5 "UnityRaw"
            ├ FUN_00687398 / FUN_0068575c  (IsUnityArchive|Raw / IsWeb|Raw)   -> strcmp FUN_005c96e4
            ├ FUN_00686ecc(hdr) header size; Seek(offset+hdrsize) ; FUN_00691b44
            ├ BlocksInfo: flags&0x3f -> FUN_00b21da8(type) decompressor; Read FUN_00690e88; vtbl[0x18] Decompress; parse FUN_00688cb4
            └ Web/Raw path: FUN_0068785c / FUN_006873e0
```
Snippet (FUN_006881c8, d4.c) — leitura dos BlocksInfo comprimidos:
```c
plVar7 = (long *)func_0x00b21da8(*(uint *)(param_1 + 0xa0) & 0x3f,1);   // factory por tipo de compressão
...
func_0x00690e88(lVar9,uStack_908,puVar8,&uStack_918,0);                  // Read(stream,size,buf,&read)
uVar12 = (**(code **)(*plVar7 + 0x18))(plVar7,puVar8,&uStack_908,lVar17,&uStack_910); // Decompress
```
Leitura de dados:
- `FUN_00683040` (d6.c): ReadData(offset,size,buf) — mapeia range→blocos (busca binária FUN_00688610 em tabela de offsets acumulados +0xe8), itera blocos e chama `FUN_006886b0` (bloco inteiro) ou `FUN_0068880c` (parcial/cache). Callers: 0x68300c, 0x684248, 0x89334c (verificação CRC em FUN_0089325c, lê em chunks de 0x8000).
- Entradas de bloco: 12 B {u32 usize, u32 csize, u16 flags}; compressão = flags&0x3f; bit6 = streamed (`FUN_00689694/006893ac/006897d0`, d8.c).
- `FUN_006897d0` (bloco inteiro comprimido, d8.c): lê csize bytes do stream (`FUN_00688db8`/0x691a94) → `plVar11->vtbl[0x18](comp_buf,&csize,out,&usize)`. **Nenhum teste de índice de bloco == 0, nenhum XOR.**
- `FUN_006886b0` (d7.c): bloco não-comprimido; ramo `*(char*)(lVar3+0xa50)` = quirk UnityWeb (+8 B) — não é cifra.
- Factory `FUN_00b21da8` (d8.c): tipo 1 → vtable 0x12abbd0 (LZMA), tipos 2/3 → vtable 0x12abb88 (LZ4/LZ4HC); outro → erro "Unsupported compression type %d" (string 0xccfbe).
- Vtable LZ4 0x12abb88 (via reloc map): [+0x18]=0xb21f6c, [+0x20]=0xb21fc8, [+0x28]=0xb21fd0, [+0x30]=0xb21fd4.
```c
// FUN_00b21f6c  (d10.c) — Decompress do LZ4
if ((*param_3 < 0x7fffffff) && (*param_5 < 0x7fffffff)) {
  iVar1 = func_0x00b23a78(param_2,param_4,*param_3,*param_5 & 0xffffffff);  // LZ4_decompress_safe
  *param_5 = (long)iVar1; return 0 < iVar1; }
```
- `FUN_00b23a78` (1496 B, d11.c) = `LZ4_decompress_safe` stock (token `>>4`, extensão 0xf/0xff, cópias de 8 B, checks `pbVar1-0xf`/`pbVar2-0xc`, `-(src+...)` de erro). Sem transform.

## 3. Resultados da caça por padrão
(a) `MOV W,#0xA6` (MOVZ): 13 sites (vaddr de arquivo+0x4000): 0x4f2584 0x76a60c 0x8adcc0 0x98f674 0xa8f4a8 0xa8f808 0xb5f9f8 0xb5faf4 0xf0440c 0xf0449c 0xfada48 0xfced2c 0x1231834 — decompilados (d1.c): são constantes de tamanho/flags (`param=0xa6`, `+0xa6`, `*(...+0x10)=0xa6`), nenhum EOR/loop de XOR. `MOVI v.16b,#0xA6`: 0 sites; MOVZ x #0xA6: 0. (0xA6 não é logical-immediate; EOR #imm impossível.)
(b) `CMP #0x1000` (w:39, x:29) e `MOV #0x1000` (w:451): não correlacionados com o leitor (nenhum aparece no caminho decompilado acima). Varredura heurística ldrb+strb+eor+and#0x7f em janela de 20 insts: 15 sítios (0x579428 0x90b304 0xe004a0 0xf12124 0xf13d68 0xf13e1c 0xf1eb68 0xf2c00c 0xf31418 0xf31b9c 0xf3202c 0xfaca48 0xfb7288 0xfc0870 0xfc3278 — offsets de arquivo; somar 0x4000) — NÃO triados (são, na prática, código de hash/mbedtls/áudio; um deles pode merecer olhada).
(c) LZ4: único decoder encontrado = 0xb23a78 (stock); caminho acima percorrido de baixo (LZ4) até cima (Open). Sem special-casing de bloco 0.
(d) mbedtls presente (strings mbedtls_cipher_setkey/_crypt etc.) mas é só TLS; não há ligação ao leitor.
Achado colateral: ~150 strings "il2cpp: function HTP<random> not found" + nomes "HTP..." = tabela de API il2cpp ofuscada (resolução por nome em libil2cpp). Confirma integração HTProtect no libunity, mas fora do leitor.

## 4. O que isso significa / o transform
Não localizei o transform (XOR 0xA6 janela ~49..80; keystream por-bundle ≥81; só primeiros 4096 B do bloco 0 comprimido; período 128). Em libunity, os bytes comprimidos do bloco chegam crus do `Read` do stream (`FUN_00691a94` → `handler->vtbl[0x18]`, objeto em stream+0x420) ao `LZ4_decompress_safe`. Logo o transform só pode estar:
1. **No handler de arquivo** (stream+0x410/0x420 = FileSystemHandler resolvido em runtime pelo registry global @0x135e738 → lista em +0x20/+0x30, handler default em *registry; BSS, não presente no .bin) — Read vtbl+0x18 aplicando máscara nos primeiros 4096 B relativos a (offset de LoadFromFile + dataStart). A BundleEncryptOffset já entra como `param_3` de FUN_0068171c, mas só desloca o Seek.
2. Em **hook em runtime** (libNetHTProtect_114.so / stub HTProtect que patcha vtable/slot 0x18 ou o próprio 0xb21f6c após carga — um patch em runtime explicaria por que a imagem estática é stock).
3. (menos provável) no lado managed (il2cpp/Lua) antes de passar o buffer.

## 5. Próximos passos sugeridos (prioridade)
1. Enumerar implementações de handler: no reloc map (`laneN/rel.pkl`) achar vtables cujo +0x60 (match de path) e +0x18 (Read) existem; decompilar os Read candidatos (pread/memcpy + loop eor). O registry @0x135e738 é preenchido em init (achar writers de 0x135e738 por ADRP).
2. Comparar bytes de FUN_00b21f6c/vtable 0x12abb88[+0x18] em memória do processo real vs. este .bin (se divergirem → hook runtime confirma-se).
3. Triar os 15 sítios ldrb/eor/strb/and#0x7f acima (offsets de arquivo; somar 0x4000).
4. Alternativa dinâmica (fora do escopo): Frida `Interceptor.attach(0xb21f6c)` e dump do buffer de entrada do bloco 0 vs 1º read.

## Artefatos
`laneN/d1..d17.c` (decompilações), `laneN/rel.pkl`, `laneN/*.py`, `laneN/dec.sh`, projeto `ghidra_unity2`.
