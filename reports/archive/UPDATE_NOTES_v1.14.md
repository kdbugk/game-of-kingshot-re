# UPDATE NOTES — v1.14.27 vs v1.9.5

**Status: ✅ CONCLUÍDO** (2026-11-18/19, 4 campanhas de subagentes). Meta alcançada: mapeamento completo do que mudou entre 1.9.5 (abril/2026) e 1.14.27 (nov/2026).

## ⭐⭐⭐ RESULTADO FINAL — Diff de classes (o objetivo do projeto)

Superfície completa extraída das duas versões via metadata HTPX decodificado + validação cruzada contra o dump 1.9.5 original do runtime (10.995/10.997 classes idênticas):

- **Classes**: 10.997 → **11.681** (79 → 85 assemblies)
- **Assembly-CSharp**: 3.513 → 3.998 (+530/-45)
- **6 assemblies novos**: Google.LibraryWrapper.OpenJdk8 (74), Play.Games.InputMapping (20), smartHelp (10), wjx (9), Google.LibraryWrapper.Java (5), **CenturyGame.GameFramework** (3)
- **Métodos** (classes comuns): **+2.182/-688**
- **Keywords de features (classes novas)**: towerdefense/mapa 188, battle 61, UI 43, activity 34, hero 7, gateway/net 6
- Relatório completo: `reports/diff_195_vs_114_classes.md`; dumps JSON em `~/work/apk/il2cpp_dump_{114,195}/`

## 🔓 A resposta técnica completa (como o metadata foi aberto)

1. **HTPX** = metadata v24 em claro ⊕ keystream XOR periódica de 1152 B (9×128)
2. **Gerador da keystream REPRODUZIDO** (`reports/keystream_gen.md` + `htpx_decrypt.py`): vive no libunity @0x1447040; chave CRC32 (poly 0x04C11DB7 derivada do tamanho) semeia RC4 modificado; palavras do header escolhem 1 de 4 classes de blocos XOR por 128 B — valida as duas versões byte a byte
3. **Layout v24 resolvido** (o pulo do gato: os pares do header apontam +8 além do início real): typeDefs 0x58, images 0x28 (layout completo no relatório), methods 36 B — 0 divergências em 92.976 declarações
4. Emulador semeado: packer inteiro em ~6 s (era 120 s preso na cifra)

## Bloco 0 dos bundles (estado final)

- **Keystream GLOBAL** (mesma K[i] p/ todos os bundles e ambas versões — premissa por-bundle refutada com evidência); gerada em runtime (sem tabela estática)
- Reader do libunity = Unity puro (chain toda decompilada, `reports/libunity_reader.md`); a transformação está em outro ponto do runtime — candidata natural: o mesmo gerador RC4/CRC32 do HTPX (mesma família de assinatura)
- Faltam: recuperar K[0..4095] (runs idênticos entre bundles dão o caminho) e achar a rotina que aplica

---
## ⭐ Diff de conteúdo (bundles) — PRONTO

Análise completa dos 7279 bundles (0 erros, sem precisar do bloco 0): **+2044 bundles novos / −1397 removidos / +130 MB**. Destaques:

- **Modo Tower Defense** = maior eixo novo (824 bundles `towerdefense_*`, 103,7 MB): árvore de skills (`tree_skill_*`), personagens/soldiers/monstros TD, configs versionadas 26.10/26.11, mapas A* gerados
- **6 heróis novos** (50034–50040: diego, liz, luna, lotter, bayard, daya) + captain_hendrik_octopus + hero_exhibit_king
- **Eventos novos**: peachfestival, duckmarket, midautumn, children2026, linkagemonopoly (crossover Monopoly), brawlarena, slg3arena, treasureroomnew, **VVIP castle**
- **luapackage (Lua) +40%** (72→101 MB) — alvo prioritário para diff de lógica quando o bloco 0 cair
- **Removidos**: climb tower antigo, sistema de roupas (`ui_panel_dress`), `scene_world_building`, redpacket
- Infra: gamepad cursor, CDN retry, VFX texture library, spine runtime update

Relatório completo: `reports/bundle_diff.md` (produzido por subagente; dados brutos em `bundle_diff_data.json`).

## 🔓 libunity.so TAMBÉM é packed — desempacotado offline (subagente)

A Lane Ghidra descobriu que o `libunity.so` usa **o mesmo packer HTProtect** do libil2cpp (entropia 8.0 em 0x238–0x800000, stub 98,8% idêntico). O emulador Unicorn foi adaptado (`work/emu_unpack_unity.py`) e **desempacotou o libunity offline**: payload `[usize][csize][zlib]` → imagem de 19,8 MB (`unity_image.bin`), importada no Ghidra.

O leitor do bloco 0 NÃO foi localizado na imagem desempacotada: strings UnityFS/Archive sem xrefs de código, constantes do prólogo sem refs reais, heurísticas LZ4 = falsos positivos. Relatório com próximos passos: `reports/bloco0_analise.md`.

## ❌ Correção importante: a região de 24 MB NÃO é o metadata

A hipótese da sessão anterior foi derrubada com evidência (subagente): o dump `metadata_live_dump.bin` é um **heap arena do il2cpp/Unity**, não o buffer do global-metadata — sem string heap sequencial, sem `.ctor`/`mscorlib`/`<Module>`, sem sanity 0xFAB11BAF. As âncoras "Assembly-CSharp" estavam dentro de structs runtime. Próximos passos corretos documentados em `reports/meta_recon.md`: scan por runs `<Module>\0.ctor\0`, ponteiro global do metadata na lib, ou decriptar o HTPX via emulador.

## 🔓 libil2cpp COMPLETO reconstruído + teoria IFix (campanha subagentes #2)

**Part B resolvido** (lane E): o blob = Phdr[7] + Sym[295] + Rela[428.774] do ELF original; aplicadas as RELATIVE → **`libil2cpp_114_full.so` e `libil2cpp_195_full.so` completos** (tabelas RW/vtables/GOT) — relatório `reports/partb_format.md`.

**Bloco 0 decifrado em camadas** (lane C, 119 bundles): prólogo = tokens LZ4 normais; criptografia = XOR 0xA6 (~bytes 50-80) + chave por-bundle a partir do byte ~81; **apenas os primeiros 4096 bytes são cifrados** (resto = LZ4 puro); indício de período 128 na chave. Chave derivável de campos do header (csz/usz/nome CAB). Relatório `reports/block0_statistical.md`.

**Loader hunt** (lane D): o caminho C# é Unity puro (`AssetBundle.LoadFromFile(path, 0, get_BundleEncryptOffset())`) e o offset vem de **stub IFix** — retorna 0 sem patch. `BundleLoader::Load` idêntico entre versões. **TEORIA UNIFICADA: o decryptor do bloco 0 é código IFix aplicado em runtime** (por isso ausente de todos os binários). Mapeamento 1.9.5 corrigido: file_off = RVA − 0x4000 (não −0x238). Relatório `reports/loader_hunt.md`.

**Ponte verificada 1.9.5→1.14.27** (RVAs do dump.cs): initDecrypt → 0x1b0d950 (92%), ButtonEx.OnPointerClick → 0x26de590 (95%).

---

## Aquisição

| Item | Detalhe |
|---|---|
| APK 1.14.27 | XAPK via APKPure (`apkeep -d apk-pure`), 898 MB — base.apk (20 MB) + config.arm64_v8a.apk (38 MB) + game_asset.apk (840 MB) |
| APK 1.9.5 | mesmo método, 850 MB |
| versionCode | 204 |

## Bibliotecas nativas (config.arm64_v8a.apk)

`libil2cpp.so` (79,4 MB), `libNetHTProtect.so` (4,5 MB), `libnesec.so` (1,0 MB) + `libnesec-x86.so`, `libsigner.so` (1,0 MB), `libhtpcrash.so` + `libhtpcrash_dumper.so`, `libtolua.so` (1,9 MB), `libxt3.1.2_a64.so` em `assets/motion/` (antes "libxt_a64.so"), `libunity.so` 21 MB, Firebase/CriWare etc.

## Pilha de proteção (constatada em arquivo)

1. **global-metadata.dat = HTPX**: header `HTPX` + uint32_LE(tamanho restante) + corpo cifrado. Entropia ~7,6 (compressão + cifra). Magic IL2CPP (`AF 1B B1 FA`) não aparece sob XOR simples/aditivo/rolagem até 32 bytes de chave.
2. **libil2cpp.so packed**: seção falsa `.note.gnu.proc` (66 MB, entropia 8,00) contém o payload cifrado; `.text` real vazio; unpacker nas seções `il2cpp` (38,9 MB, ent. 5,14) e `.note.gnu.text` (721 KB). Zero exports `il2cpp_*` no dynsym. Estrutura idêntica na 1.9.5 (63 MB / 36,7 MB).
3. **Bundles Unity cifrados**: todos os `.unity3d` do game_asset.apk têm header UnityFS válido (Unity 2022.3.62f1) mas blocos LZ4 corrompidos por cifra própria — padrão repetitivo (`0a0024…`) sugere XOR/stream fraca. Afeta também `luapackage_64` (40 MB de lógica Lua) e `toluaout_*`.
4. **libNetHTProtect.so é ELF limpo** (não empacotado) → alvo primário de análise estática.

## Diff il2cpp (pendente)

Dump da 1.9.5 disponível no repo (`dump/dump.cs`, 245k linhas; `il2cpp_dump/*.json`, 79 assemblies) foi gerado EM RUNTIME por `il2cpp_api_dump.js` — existe justamente por causa da criptografia em arquivo. Para a 1.14.27 são necessárias as rotas abaixo.

## Rotas para o dump 1.14.27

| Rota | Passos | Dependência |
|---|---|---|
| **A. Offline RE** ✅ PARCIAL | ~~Ghidra em libNetHTProtect + unpacker~~ → **EMULADOR UNICORN QUEBROU O PACKER** (ver § Emulação) | concluída até a imagem RX |
| **B. Runtime dump** | restaurar root (Magisk recovery-mode: `/debug_ramdisk/su` existe, aguardando grant do Shell) → jogo já instalado (sideload ✓) → frida-server (binário pronto no distro) → scripts RVA-independent | **1 tap: permitir Shell no Magisk** |

## Bundles Unity — RESOLVIDO PARCIALMENTE (2026-11-18, sessão 2)

**Os bundles NÃO estão encriptados** — a falha do UnityPy era bug de semântica de flags:

- O jogo usa header ver=**8** custom + flags `0x243` onde `0x200` = `BlockInfoNeedPaddingAtStart` (semântica NOVA — no enum antigo era `UsesAssetBundleEncryption`!)
- **Blocos 1..N decompilam LZ4 plain** após alinhar o início dos dados em 16 bytes
- `scripts/analysis/kingshot_bundle.py` = extrator completo funcional
- **Bloco 0 (o do header SerializedFile/CAB) tem prólogo custom**: `16 00 01 00 [15|16] 16 [0a|0b] 00 ...` constante entre bundles — não é XOR simples, não é a cifra do unpacker (testado em 4 modos), não é Unity-CN (flag real `0x1400` ausente)
- Decoder tolerante (`lz4_lenient.py`) mostra o header SerializedFile SE FORMANDO nos primeiros ~70B — a estrutura está quase acessível
- **Próximo alvo**: implementação no `libunity.so` (21MB, ELF limpo) — acher o leitor custom de bloco 0

## Rota runtime (pendência única)

Magisk: `/debug_ramdisk/su` existe mas Shell = "Permission denied" — falta **Acesso de superusuário = Apps e ADB** nas configurações do app (ou allow no item Shell da aba Superusuário). Destrava: frida → dump de memória → metadata decriptado garantido.

## Emulação do unpacker (2026-11-18) — O PACKER FOI QUEBRADO OFFLINE

Fluxo estático (Ghidra no `.note.gnu.text`) + emulação Unicorn (`scripts/analysis/emu_unpack.py`):


Fluxo estático (Ghidra no `.note.gnu.text`) + emulação Unicorn (`scripts/analysis/emu_unpack.py`):

1. init_array (7 ctors, endereços extraídos das RELA — slots zerados no arquivo)
2. ctor_4 → `FUN_0494fb64` = driver: `FUN_0494d470` mapeia, **`FUN_04949e48` decripta** (cifra custom ARX+permutação 64B/bloco, ~61KB decompilado), zlib inflate
3. **Saída**: payload `.note.gnu.proc` (65MB) → zlib → **73.3MB de imagem RX real do libil2cpp** (strings il2cpp/global-metadata/JNI_OnLoad confirmadas). Header ELF reconstruído em runtime pelo próprio unpacker (regra do projeto 1.9.5: `repair_elf_header.py`)
4. Artefatos em `~/work/apk/`: `libil2cpp_114_decrypted.so` (75.6MB montado), `crypt_out_*` (blobs decriptados), `partA_inflated.bin`
5. Segundo blob (RW `.data`, 10MB) decripta com header próprio (`01 00 00 00 04...`) — formato ainda não invertido
6. **Metadata HTPX NÃO decripta com a cifra do unpacker** (replay testado) — camada própria (provável: código do payload pós-unpack ou libNetHTProtect com outra chave)
7. Constantes do emulador: GOT stubs p/ 182 imports (incl. fake /proc/self/maps, __system_property_get, dlopen/dladdr), 1342 RELATIVE relocs aplicadas, TLS fake p/ stack canary

### Próximos passos (A)
- Ghidra no `libil2cpp_114_decrypted.so` (rodando em bg) → achar cadeia do metadata (equivalentes de FUN_0194b9d8/0194339c/019435dc de 1.9.5) por padrão
- Emular 1.9.5 no mesmo emulador → extrair FUN_019435dc real → binary-pattern match no 1.14.27
- Inverter o formato do part B (RW) p/ .so completo

## Ferramentas novas neste ciclo

- `scripts/analysis/htpx_probe.py` — oráculo AF1BB1FA contra transformações simples
- `scripts/analysis/elf_sanity.py` — entropia por seção ELF
- `scripts/analysis/lua_diff.py` — extrator/diff de luapackage (aguardando decrypt dos bundles)
- `scripts/analysis/diff_dumps.py` — comparador dump antigo (JSON custom) ↔ dump.cs Il2CppDumper
