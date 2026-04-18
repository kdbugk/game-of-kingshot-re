# libil2cpp — Cadeia de carregamento do global-metadata.dat

Análise da chain que abre, valida e carrega o arquivo de metadata do Unity IL2CPP.
Todas as funções são do dump decriptado em memória (`libil2cpp_decrypted.so`).
Base Ghidra = `0x0` (dump carregado como Raw Binary ou ELF com p_vaddr=0).

## Backtrace Frida (confirmado em runtime)

```
open64("...global-metadata.dat")
  ← FUN_0194339c   +0x194339c   [abre o arquivo, retorna struct de file handle]
  ← FUN_0194b9d8   +0x194b9d8   [monta o path, orquestra carregamento]  (frame #02 return = 0x194baa4)
  ← FUN_019?????   +0x192e26c   [intermediário — não analisado]
  ← FUN_018ffd10   +0x18ffd10   [il2cpp_metadata_cache_init — não analisado]
  ← FUN_0194bd60   +0x194bd60   [il2cpp_init_callee_top — não analisado]
  ← il2cpp_init    (export público)
  ← libunity.so+0x6f73e0
```

## Funções analisadas

---

### FUN_0194b9d8 — Orchestrator do metadata load

**Arquivo:** `FUN_0194b9d8`
**Offset Frida:** `0x194b9d8`
**Papel:** Ponto de entrada do carregamento. Constrói o path completo "Metadata/global-metadata.dat" e coordena abertura + leitura.

**Fluxo:**
1. Inicia std::string `local_60` com `FUN_019236b4` (construtor de string vazia)
2. Concatena `"Metadata"` (literal `s_Metadata_00a99e33`) + `param_1` ("global-metadata.dat") via `FUN_01915d10`
3. Chama `FUN_0194339c(path_string, flags=3, mode=1, param=1, writable=0, &error_out)` → `uVar2` = file handle struct
4. Se erro == 0:
   - `uVar3 = FUN_0192ca00()` — cria um contexto/scope (provável RAII guard)
   - `FUN_019435dc(uVar2, &error_out)` — **lê e processa o conteúdo do arquivo** ← próximo alvo
   - Se sucesso: retorna `uVar3` (o contexto criado)
   - Se falha: `FUN_0192ca10(uVar3)` cancela o scope, retorna 0
5. Se erro != 0: loga `"ERROR: Could not open %s"` com o path

**Nota SSO (Small String Optimization):**
`local_60[0] & 1` é o flag de heap do `std::string` em Bionic/LLVM. Quando 1, `local_50` é o heap pointer e `thunk_EXT_FUN_770a3954cc` é `free()`.

**Próximo alvo:** `FUN_019435dc` — lê/mapeia o conteúdo do arquivo aberto.

---

### FUN_0194339c — File opener (wrapper sobre open64)

**Arquivo:** `FUN_0194339c`
**Offset Frida:** `0x194339c`
**Papel:** Abre um arquivo via `open64`, faz `fstat64`, verifica cache por dev+ino, e retorna um struct de file handle de 0x50 bytes.

**Funções identificadas dentro dela:**
| Ghidra ref | Função real |
|------------|-------------|
| `func_0x03db15a0` | `open64(path, flags, mode)` |
| `func_0x03db1290` | `__errno_location()` |
| `func_0x03db15e0` | `fstat64(fd, &stat)` |
| `func_0x03db0e20` | `malloc(0x50)` |
| `func_0x03db1560` | `strcpy` ou path copy helper |
| `func_0x03db1490` | `close(fd)` (chamado no path de erro) |
| `func_0x018d5124` | lock (mutex acquire) |
| `func_0x018d55c8` | unlock (mutex release) |

**Layout do struct retornado (0x50 bytes, int* piVar5):**
```
+0x00  fd             (int)    — file descriptor aberto
+0x04  file_type      (int)    — 1=regular, 2=?, 3=? (derivado de st_mode & 0xf000)
+0x08  path_copy             — cópia do path (func_0x03db1560)
+0x24  param_4        (int)
+0x28  param_3        (int)
+0x20  param_5        (uint)
+0x30  st_dev         (ulong)  — device ID do fstat (usado pelo cache check)
+0x38  st_ino         (ulong)  — inode number do fstat (usado pelo cache check)
+0x48  next           (ptr)    — próximo nó na linked list global
```

**Cache global:** `piRam0000000004277df0` / `piRam0000000004277f98` — head/tail da linked list de file handles abertos.

---

### FUN_019432e4 — Cache check por dev+ino

**Arquivo:** `FUN_019432e4`
**Offset Frida:** `0x19432e4`
**Papel:** Verifica se um arquivo (identificado por st_dev + st_ino do fstat) já está na linked list global. Retorna `true` se NÃO está no cache (= precisa ser carregado).

**Parâmetros:**
- `param_1` → ponteiro para `{st_dev, st_ino}` (primeiros 16 bytes da struct stat)
- `param_2` → flag de verificação de estado
- `param_3` → modo esperado (1 ou 2)

**Fluxo:**
1. Adquire mutex (`FUN_018d5124`)
2. Percorre linked list starting em `DAT_04277df0`
3. Para cada nó, compara `node+0x30` (st_dev) e `node+0x38` (st_ino)
4. Libera mutex
5. `lVar3 == 0` → arquivo não encontrado → retorna `true` (prosseguir com load)
6. `lVar3 != 0` → arquivo já em cache → retorna `false` ou verifica estado

---

## Próximos alvos

| Endereço | Papel provável | Status |
|----------|---------------|--------|
| `FUN_019435dc` | Lê/mapeia conteúdo do arquivo (HTPX decryption?) | **Não analisado — próximo** |
| `FUN_0192ca00` | Cria scope/contexto RAII antes do load | Não analisado |
| `FUN_0192ca10` | Cancela/libera o scope em caso de erro | Não analisado |
| `FUN_018ffd10` | il2cpp_metadata_cache_init (frame #04) | Não analisado |
| `FUN_0194bd60` | il2cpp_init_callee_top (frame #05) | Não analisado |

## Nota sobre o dump

O `libil2cpp_decrypted.so` capturado em runtime tem o ELF header corrompido
(anti-dump pelo SDK de proteção). O código nos segmentos está decriptado e analisável.
Para carregar no Ghidra: usar como **Raw Binary, base 0x0, AARCH64:LE:64:v8A**.
O `libil2cpp_fixed.so` tem o header reparado mas pode ter endereços deslocados dependendo
de como o Ghidra mapeia os segmentos ELF.
