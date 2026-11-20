# Lane R — Dumper v24 COMPLETO (campos, parâmetros, retornos + RVAs de método)

**Resultado:** artefato definitivo da 1.14.27 gerado (`dumpcs_114.cs`) e teste final de consistência contra o dump 1.9.5: **69.515 de 69.515 RVAs comparáveis idênticos (100,000 %)** entre o rebuild 1.9.5 (metadata+binário reconstruídos) e o dump de runtime antigo. Isso prova, em nível de binário, que (a) a metadata v24 reconstruída pela Lane K está correta na ordem/tokens dos métodos, e (b) o binário reconstruído tem a CodeGenModule/methodPointers certa.

## Artefatos
| arquivo | conteúdo |
|---|---|
| `/home/re/work/apk/dumpcs_114.cs` (18 MB, 271.908 linhas) | dump estilo dump.cs da **1.14.27**: 11.681 classes, 92.976 métodos (84.625 com RVA), campos, parâmetros, retornos |
| `/home/re/work/apk/dumpcs_195.cs` (17 MB, 253.500 linhas) | idem para a 1.9.5 (rebuild): 10.997 classes, 87.203 métodos (79.375 com RVA) |
| `/home/re/work/apk/il2cpp_full_{114,195}/NNN_*.json` | JSON por assembly (classes → fields{name,type,typeIndex,token}, methods{name,token,**rva**,flags,slot,ret,params}, `moduleBase`) |
| `/home/re/work/apk/kdump2.py` + `lib.py` | o dumper (`python3 kdump2.py 114|195`; precisa de `/tmp/meta_dec_VER.bin` do kdump.py) |
| cópia em `C:/Users/prs/work/laneR/artifacts/` | dumpcs_*.cs, il2cpp_full_*.tgz, kdump2.py, lib.py |
| `C:/Users/prs/work/laneR/consistency_195.txt`, `divergences_195.json` | tabela completa de consistência / divergências |

## 1. Tabelas da metadata (novos layouts resolvidos)
- **methods (36 B)**: `name, declaringType, returnType(typeIdx), returnParamToken(0x08000000), parameterStart, genericContainer, token, flags(u16), iflags(u16), slot(u16), paramCount(u16)` — corrige a leitura anterior: parameterStart está em +16, não +12.
- **fields (12 B)**: `nameIndex, typeIndex, token(0x04xxxxxx)`. Base achada por varredura de tokens: **195 @0x8133e8 (63.945 entradas = Σ fieldCount exato)**, **114 @0x8b8fa0 (70.043)**. Os pares do cabeçalho não servem (offsets/sizes tortos); o fieldStart do typeDef é `t[8]`, fieldCount = low16 de `t[17]`.
- **parameters (12 B)**: `nameIndex, token(0x08…), typeIndex`. Base **195 @0x6ec7d0 (100.610 entradas)**, **114 @0x780ff4 (106.489)**; validação: 300 métodos amostrados, 0 inválidos.
- typeDef: `t[2]` = byvalTypeIndex (índice de tipo no espaço da metadata), `t[7]` flags, `t[8]` fieldStart, `t[9]` methodStart, `t[16]` = methodCount|propCount<<16, `t[17]` = fieldCount|eventCount<<16.

## 2. RVAs de método — como funciona neste binário
1. **Mapeamento do binário (verificado):** os ponteiros de `methodPointers` na tabela RW **já são RVAs** (valor = RVA do dump antigo, sem −0x4000). Para 195 e 114 a seção RW tem file-offset == vaddr (o `_full.so` e o `img195_vaddr.so` são idênticos na RW). O "−0x4000" só afeta onde o *código* cai no arquivo, não os ponteiros. (Observação de residual: o conteúdo de código em si não passa num teste simples de prólogo/`ret` em nenhum deslocamento constante — não necessário para RVAs, mas quer dizer que o RX reconstruído não deve ser usado como oráculo de início de função sem checar mais.)
2. **Estrutura:** v27+-like `Il2CppCodeGenModule` por assembly: `{name*, count, methodPointers*, adjustorThunkCount, adjustorThunks*, invokerIndices*, …}`; `methodPointers[rid-1]` com `rid = token & 0xFFFFFF` (rid reinicia por imagem). Arrays consecutivos, seguidos pelos adjustorThunks (pares de 16 B → gap = nMétodos + 2·adj).
   - 195: regiões `0x40813a0` (48.391 slots) e `0x4208710` (45.227). 114: `0x43f9298` e `0x459c8d8`.
   - Os campos *count* dos structs estão zerados no RW (perdidos na reconstrução) → bases achadas pelos structs (qword que aponta pro array, precedido de zero e do ponteiro de nome).
3. **Identificação módulo→imagem:**
   - **114:** o ponteiro de nome + **0x238** (tamanho do header-wrapper) aponta para a string `"X.dll"` → mapeamento direto, 78/81 imagens com métodos (0 inconsistências gap≥count; faltam só `DesperateDevs.Utils`, `Unity.Profiling.Core`, `__Generated`: 3 métodos cada, sem array próprio).
   - **195:** ponteiros de nome apontam para região diferente do pool; usei alinhamento monotônico (DP) ordem-de-ponteiro × ordem-no-pool-de-strings com restrição gap ≥ count. Validado por votação independente (RVA do dump antigo ⇒ base) — 100 % de acordo. 72 módulos atribuídos.
   - Ordem de módulos no binário ≈ nome sem `.dll`, lowercase, com prefixo mais curto vindo *depois* (`System.Core < System.IO.* < System.Numerics < System`).
4. **Entradas nulas** (≈8,4 k em 114, 7,8 k em 195): métodos abstratos/genéricos compartilhados (o dump de runtime antigo mostra RVA compartilhado tipo 0x187ad5c para `ETCSingleton\`1`, `LTDescr`…, que não está em methodPointers) e ~400 placeholders de token `0x06xxxxxx` na região 114 (valor-token no lugar de ponteiro; tratados como "n/a").

## 3. Validação 195 vs dump antigo (RVA)
- `NetEase.NetSecProtect.initDecrypt` (Assembly-CSharp-firstpass) → **0x19e1c2c** ✔ (igual ao dump.cs linha 239784)
- `UnityEngine.UI.ButtonEx.OnPointerClick` → **0x23bed78** ✔
- Total: 69.515/69.515 RVAs iguais; **0 divergências**.

**Equivalentes na 1.14.27 (novo artefato):**
- `NetEase.NetSecProtect.initDecrypt(String)` token 0x600003b → **RVA 0x1b0d950** (era 0x19e1c2c)
- `UnityEngine.UI.ButtonEx.OnPointerClick(PointerEventData)` token 0x6006bfb → **RVA 0x26de58c** (era 0x23bed78)
- `BaseFinger.GetGesture` 0x1b151d0 (era 0x19e94a8)

## 4. Tabela final de consistência (rebuild 195 × dump 1.9.5)
Escopo: todas as 77 assemblies presentes nos dois lados (o dump.cs antigo lista 79 assemblies; as 6 maiores abaixo). Comparação por `fullName` de classe único em ambos.

| assembly | classes (rebuild / casadas) | lista de campos idêntica | lista de métodos idêntica (nomes+nº params) | RVAs iguais / comparáveis |
|---|---|---|---|---|
| Assembly-CSharp | 3513 / 2420 | 100,0 % | 99,9 % | 27.413 / 27.413 |
| mscorlib | 1283 / 971 | 99,9 % | 100 % | 7.497 / 7.497 |
| com.Tivadar.Best.HTTP | 1235 / 961 | 100 % | 100 % | 7.676 / 7.676 |
| UnityEngine.UIElementsModule | 1092 / 692 | 100 % | 100 % | 5.057 / 5.057 |
| UnityEngine.CoreModule | 782 / 561 | 99,8 % | 100 % | 4.923 / 4.923 |
| System | 507 / 346 | 100 % | 100 % | 2.371 / 2.371 |
| **TOTAL (77 assemblies)** | 10.992 / 7.737 | **99,95 %** (7.733/7.737) | **99,97 %** (7.735/7.737) | **69.515 / 69.515 = 100,000 %** |

**Divergências (todas):** 6 classes, nenhuma em RVA:
- `Assembly-CSharp: Entitas.TDGameEntity` (métodos 869 vs 512), `IFix.ILFixDynamicMethodWrapper` (1511 vs 512), `IFix.IDMAP0` (campos 20.758 vs 256), `mscorlib: System.TermInfoStrings` (396 vs 256), `UnityEngine.KeyCode` (338 vs 256), `Mono.Security…CipherSuiteCode` (267 vs 256) — o dump de runtime antigo **trunca em 256/512 itens**; a metadata reconstruída tem a lista completa (são exatamente as 2 classes que a Lane K já tinha apontado como "divergentes").
- Classes não casadas (3.255): são nomes que não casam 1:1 por `fullName` (duplicatas/nomes de genéricos/aninhadas) — não são conflitos de conteúdo; refinar o casamento é trabalho pendente e não afeta os 100 % acima.
- RVA "faltando no rebuild" mas presente no dump antigo: 5.902 métodos — todos de tipos genéricos compartilhados (ponteiro 0 em methodPointers), mais 6 métodos de módulos sem array (`DesperateDevs.Utils`, `Unity.Profiling.Core`).

## 5. Nomes de tipo (limitação conhecida)
- A metadata v24 aqui usa um espaço de `typeIndex` **próprio**: as entradas do array `types` do binário (114: 0x42cb168, 34.397 ptrs → objetos 16 B `{bits:u32(attrs|type<<16), pad, data:u64}`) **não** batem 1:1 com os índices da metadata (offset deriva suavemente entre ≈3.100 e ≈9.800; existem variantes por `attrs`). Portanto não resolvi tipos pelo binário. No 195 o `.data` desses objetos está zerado no rebuild.
- Nomes de tipo no dump.cs vêm de: (1) typeDef.byval → nome da classe (11.681 / 10.997 índices, determinístico); (2) votação a partir do dump 1.9.5 (campos/retornos/params de classes com lista de campos/métodos idêntica) e, para a 114, também a partir do 195 já resolvido. O que não resolve fica como `T#<índice>` (≈32,7 mil linhas na 114, ≈26,9 mil na 195 — principalmente tipos genéricos instanciados, arrays e variantes enum/static). **Os índices cruzam versões consistentemente** (mesmo tipo = mesmo índice dentro de uma versão), então `typeIndex` no JSON permite refinar depois.
- Campos sem flags de acesso (a tabela de 12 B não tem `attrs`; ficam no `Il2CppType`), por isso o dump mostra `Tipo nome; // token` sem modificador.
- Cabeçalho da classe: visibilidade/abstract/sealed/interface do `flags`; sem base-class/interfaces (parent também é typeIndex).

## 6. Riscos residuais
- Os 3 módulos de 3 métodos (+`__Generated`) sem RVA; ~400 placeholders `0x06…` na 114 tratados como n/a (podem ser métodos com stub do packer — vale conferir em runtime).
- Atribuição módulo→imagem da 195 depende do DP (validado por votos); da 114 depende do ponteiro-de-nome+0x238 (49→71 structs, todos com `.dll` válido e gap ≥ count). Sem oráculo de RVA para a 114: só a consistência estrutural (gap−count pequeno = pares de adjustor) e a analogia 1:1 com a 195.
- RX reconstruído não serve (ainda) para checar "início de função" — não validei RVAs da 114 por prólogo.
- Casamento por `fullName` cobre 70 % das classes; os 100 % valem para os 69.515 pares comparáveis.
