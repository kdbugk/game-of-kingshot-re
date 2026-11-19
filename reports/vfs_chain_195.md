# Cadeia de carga do `global-metadata.dat` — libil2cpp 1.9.5 (imagem completa)

## 0. Resultado (resumo honesto)
- A cadeia literal → abertura → mmap → registro foi **mapeada e decompilada** (seção 3, arquivos em `decompiled/`).
- **Não existe transformação de conteúdo nessa cadeia.** O arquivo é aberto (`open`), `fstat`, e mapeado com
  `mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd)`; o ponteiro devolvido é usado direto como cabeçalho de metadata v24
  (`+0xa0 typeDefs /0x58`, `+0xac images /0x28`...). Nenhum XOR/LZ4/AES, nenhum callback de leitura.
- A premissa "duas tabelas globais de callbacks" **não se confirma**: `DAT_04277a78/90` (projeto antigo) = `0x460ee00/0x460ee18` (1.9.5)
  são **`std::map<void* base, handle*>`** (red-black tree: nó 0x30 B, chave em +0x20 = endereço mapeado, valor em +0x28 = handle do arquivo;
  inserção `FUN_01a2a0ec`, remoção `FUN_01a3fe10`). Servem só para o `Unmap` achar o handle a partir do ponteiro: é o `il2cpp::os::MemoryMappedFile` Map/Unmap padrão.
- Logo, se o `global-metadata.dat` em disco é ofuscado, a decifragem **não está nesta cadeia**: ocorre antes (asset já entregue decifrado) ou em código
  fora do caminho estático (IFix / hook em runtime — coerente com a teoria da lane D). Próximo passo: achar quem escreve no buffer mapeado (`0x460d270`) ou hooka `open/mmap`.
  Os imports (mmap, fstat, open...) aparecem como `func_0x041040xx` (GOT/PLT não relocável na imagem).

## 1. Correção importante do mapeamento da imagem
`libil2cpp_195_full.so` (lane E) é **file-offset-flat para o código**, não vaddr-flat:
1. Um ADRP em `file 0x1a0d868` calcula `0xb3f30e` (a string está em `0xb4330e`); com +0x4000 bate exatamente. Phdrs originais (`blob195.bin`):
   RX `p_offset 0x1612f04 → p_vaddr 0x1616f04` (+0x4000); RW1 `0x3daed20 → 0x3db6d20` (+0x8000); RW2 `0x40407d8 → 0x404c7d8` (+0xC000).
2. Os bytes da imagem lane E em `0x3db6d20..` (início do RW1 em vaddr) são **código** (ex. `0xf940026890002f8a`), e as 406 422 relocs RELATIVE foram gravadas em `r_offset`(vaddr)
   sobre essa área ⇒ o RW da imagem lane E está provavelmente sobreposto a bytes de código do partA (cauda 0x3dacd20..0x45ea908 do partA não é .data).
Gerei uma imagem nova **vaddr-flat** `img195_vaddr.so` (`build2.py`): `[0,0x1612f04)` idêntico; RX deslocado +0x4000 (`0x1616f04..0x3db2d20`); relocs RELATIVE aplicadas em vaddr;
cauda do partA **não** incluída. Ghidra: ELF AArch64 com `-loader-imageBase 0x0` (sem isso o ELF DYN é carregado em 0x100000).
**Endereços abaixo = vaddr = RVA do dump.cs** (= offset na imagem lane E + 0x4000, para código).

## 2. Scans brutos
- `global-metadata.dat\0` ocorre **1×**, em `0xb4330e` (vizinhança: `...UnityEngine.UI.dll\0__Generated\0r+be\0global-metadata.dat\0No native stack trace...`).
- **Zero** ponteiros u32/u64 para ela (sem tabela de descritores que a referencie; em 1.9.5 a string só é usada por código).
- Código: ADRP(página 0xb43000)+`ADD #0x30e` → **único** ponto: `0x1a11868/0x1a1186c` (vaddr) dentro de `FUN_01a11858`. Varredura de todo o RX: 33 ADRPs para a página; só esse com offset 0x30e (o outro `ADD #0x30e` em `file 0x29639e0` é de outra página).
- A tabela de descritores de literais (estilo 0xf90660 da 1.14) não é referenciada por esta cadeia.

## 3. Cadeia (callee ← caller), decompilações em `decompiled/F_<vaddr>.c`
| vaddr 1.9.5 | identificação | equivalente no projeto antigo | evidência |
|---|---|---|---|
| `0x1a854ec` | `MetadataCache::Initialize` (só caller: BL em `0x1a85518`→ chama `1a11858`) | `FUN_018ffd10` (frame #04 do backtrace Frida) | `F_1a854ec.c` |
| **`0x1a11858`** | 1ª parte de Initialize: `lRam460d270 = func_0x01a3c51c(&UNK_00b4330e)`; lê header (`+0xac`/0x28, `+0xa4`/0x58, `+0x34`/0x24, `+0xa0`) e relocaliza TypeDefs | intermediário `0x192e26c` | `F_1a11858.c` |
| **`0x1a3c51c`** | `MetadataLoader::LoadMetadataFile(const char*)`: monta `"Metadata"`(0xb292f4)+`/`+nome | **`FUN_0194b9d8`** (idêntico linha a linha; `"Metadata"` 0xa99e33, `"ERROR: Could not open %s"` 0xabaca8 no antigo ↔ 0xb292f4 / 0xb4a357 aqui) | `F_1a3c51c.c` |
| `0x1a7b478` | `os::File::Open` (open64 + fstat64 + lista global dev/ino) | `FUN_0194339c` | `F_1a7b478.c` |
| `0x1a929c4` | `MemoryMappedFile::Map` (mutex recursivo ARM64; chama 1a7bf8c, 1a7c14c; registra nos 2 `std::map`) | `FUN_0192ca00`→`FUN_0192cc00` | `F_1a929c4.c` |
| `0x1a7bf8c` | setup/validação (fstat, aloca handle 0x50) | `FUN_01943eb0` | `F_1a7bf8c.c` |
| **`0x1a7c14c`** | **mmap real**: fstat → tamanho/offset alinhados à página (`0x1a7c2e0`=getpagesize); tabela de prot/flags em `0xf18c00` (`[1]=0x21` ⇒ `PROT_READ`, `MAP_PRIVATE`); `func_0x04104020(0,len,prot,flags,fd)` | `FUN_01944070` | `F_1a7c14c.c` |
| `0x1a7c2d0` | tipo do mapeamento (flag) | `FUN_019441f4` | `F_1a7c2d0.c` |
| `0x1a2a0ec` | `std::map::emplace` (chave +0x20, valor +0x28) | `FUN_0192d1a4` | `F_1a2a0ec.c` |
| `0x460ee00` / `0x460ee18` | as duas "tabelas" = `std::map<void*,handle>` (raiz em +8 = `0x460ee08`/`0x460ee20`) | `DAT_04277a78`/`DAT_04277a90` | `F_1a929c4.c` |
| `0x1a929d4` | `MemoryMappedFile::Unmap(ptr)`: busca o nó pela chave, `1a7c284` (munmap), apaga | — | `F_1a929d4.c` |
| `0x1a7b6b8` | fecha handle (close, tira da lista global) | `FUN_019435dc` | `F_1a7b6b8.c` |
| `0x460e5b8 / 0x460e608 / 0x460e7b0` | mutex / head / tail da lista de handles | `DAT_04277da0/df0/f98` | idem |

Nota sobre âncoras do projeto antigo: os endereços **não** transpõem por deslocamento constante (LoadMetadataFile 0x194b9d8→0x1a3c51c = +0xf0b44; open 0x194339c→0x1a7b478 = +0x1380dc), e a distância
`"Metadata"`↔`"ERROR"` é 0x20e75 no antigo vs 0x21063 nas imagens 1.9.5 e 1.14.27 ⇒ o runtime dump antigo é de **outra build**. As âncoras valem por **estrutura** (decompiles equivalentes), não por endereço.

## 4. Evidência-chave
- `FUN_01a3c51c`: `func_0x01a7b478(path,3,1,1,0,&err)` (open); se ok → `func_0x01a929c4()` (Map) → `func_0x01a7b6b8(handle,&err)` (fecha fd; o mapeamento persiste) → retorna ponteiro; senão `func_0x01a92840("ERROR: Could not open %s")`.
- `FUN_01a929c4`: `uVar5=func_0x01a7bf8c(...)`; `lVar4=func_0x01a7c14c(uVar5,&uStack_58,0,1,&lStack_78,&iStack_6c)` (mmap); `func_0x01a2a0ec(0x460ee00,...)` se `func_0x01a7c2d0&1`; `func_0x01a2a0ec(0x460ee18,...)` sempre, com `*(node+0x28)=handle`; devolve `lVar4-lStack_78`.
- `FUN_01a7c14c`: `mmap(0,len,tab[1]&7 = PROT_READ, MAP_PRIVATE, fd)` — **sem transformação do conteúdo**.
- `FUN_01a11858`: usa o ponteiro como header v24 (divisores 0x28/0x58/0x24 = tamanhos de ImageDef/TypeDef/... v24) — sem decifra/checagem.

## 5. Limitações
- Ghidra **sem análise completa**: o import analisado de 74 MB foi descartado ao descobrir o erro de mapeamento/imageBase (~25 min). As decompilações usam import `-noanalysis` + criação de função por endereço (projeto `C:/Users/prs/work/ghidra_195q/q195`; `ghidra_195` ficou vazio). Imports/thunks aparecem como `func_0x...`; sem xrefs automáticos (usei ADRP/BL raw em `rawlib.py`/`scan*.py`).
- mmap/fstat/open identificados por equivalência com o decompile antigo + tabela de flags; GOT de imports não resolvida (293 slots ficam 0).
- Não foi localizado nenhum decifrador do metadata. Se ele existe, está fora desta cadeia estática.

## 6. Arquivos
`decompiled/F_*.c`; `img195_vaddr.so`, `build2.py`, `rawlib.py`, `scan*.py`, `Dec.java`, `q.ps1`, `blob195.bin` (phdrs originais).
