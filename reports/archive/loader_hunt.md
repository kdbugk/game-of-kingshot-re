# Lane D — Caça ao loader customizado de bundles (1.9.5 dump.cs → 1.14.27 libil2cpp)

Escopo: somente leitura (dump.cs, il2cpp_dump/*.json, partA_195.bin, partA_inflated.bin, APK extraído). Nada foi tocado no celular nem no repo.
Scripts/saídas em `C:/Users/prs/work/laneD/` (`names.py`, `disfn.py`, `cmp.py`, `loc2.py`, `loc3.py`, `callers.py`, `prol.py`, `libscan.py`, `loc_core.out`, `loc3.out`).

## 0. Resumo executivo (TL;DR)

1. **O carregamento de bundles do jogo NÃO é customizado no lado C#.** Existe um único caminho: `BundleLoader::Load` (e `::ReportCorruptAsset`) → `AssetBundle.LoadFromFile(Async)(path, crc=0, offset=AssetDataInfo.BundleEncryptOffset)` — a API **padrão** do Unity, com o parâmetro `offset` (byte) alimentado por `AssetDataInfo.get_BundleEncryptOffset()`.
2. `get_BundleEncryptOffset` (byte, 0..255) é um **stub de hot-fix IFix**: no código nativo ele só retorna `0` (`mov w0,wzr`) a menos que `WrappersManagerImpl.IsPatched(id)` seja verdadeiro, i.e. exista patch IFix carregado. Mesma forma em 1.9.5 (id 0x4f12) e 1.14.27 (id 0x5b0a). Pistas pra lane: o "offset de criptografia" é só um *prefixo de bytes antes de `UnityFS`*; os bundles que o time parseou começam em `UnityFS` no offset 0 (parser em `laneC/collect.py` assume isso), logo offset efetivo = 0.
3. **Nenhum código toca a constante do prólogo `16 00 01 00 …`** em: RX 1.9.5, RX 1.14.27, libunity 1.14 desempacotado (`unity_image.bin`), libsigner, libnesec, libtolua, libmain, lib_burst_generated, libNetHTProtect (empacotado). As ocorrências brutas dos 4 bytes são tabelas de dados coincidentes (§4). Zero pares MOVZ/MOVK que montem 0x00010016 ou 0x000a/b161x.
4. Conclusão: a lógica que lida com o prólogo do bloco 0 **não está no C# do jogo nem em libsigner/libnesec**. Resta (a) o próprio libunity (parser UnityFS/ArchiveStorage — já fracassou via xrefs de string, mas o código pode ser *inline* sem string), ou (b) o prólogo é dado de formato (ex.: header de compressão/criptografia no bloco) lido por código genérico, não por comparação com constante. Ver §6 para próximos passos.

## 1. Correção importante do mapeamento RVA → offset (1.9.5)

O briefing dizia "offset em partA = RVA − 0x238". **Para os RVAs do dump 1.9.5 isso é falso.** Evidência:
- Com `idx = RVA − 0x238` o disassembly cai no meio de funções (ex.: `BundleLoader::Load` começava em `cmp w11,w10`).
- Calibração por histograma de alvos de `BL`: para os alvos de BL em partA_195, a diferença `RVA_do_dump − offset_de_arquivo` que casa com RVAs de métodos do dump é **+0x4000** (767 de 1479 métodos amostrados caem exatamente em alvo de BL; o próximo melhor shift tem 14). Com `idx = RVA − 0x4000` as funções começam em prólogos reais (`str x30,[sp,#-0x30]!` em `BundleLoader::Load`) e os BL resolvem para nomes do dump (IFix, AssetBundle::LoadFromFile etc.).
- Todos os offsets abaixo, para 1.9.5, usam `file_off = RVA − 0x4000`. Para 1.14.27 não há dump de RVAs (`il2cpp_dump_114` está vazio), então reporto **file_off em partA_inflated.bin**; RVA_114 ≈ file_off + 0x4000 *se* o mesmo layout valer (suposição, não verificada).

## 2. Mapa da superfície de carregamento (C#, 1.9.5, RVAs do dump)

### 2.1 Cadeia principal (confirmada por disassembly)
`AssetBundleMgr.Load/LoadInner` → `LoaderGroup` → `BundleLoader.Load(async)`:
```
AssetModule.SearchAsset(abName, out AssetDataInfo)        0x250a5d8
AssetDataInfo.GetFullPath()                               0x24d1df0   (persistent vs streaming, flag em +0x41)
AssetDataInfo.get_BundleEncryptOffset()  -> byte          0x24d1e4c   (stub IFix, devolve 0 sem patch)
AssetBundle.LoadFromFileAsync(path,0,offset) / LoadFromFile(path,0,offset)   0x3b02d18 / 0x3b02e4c
  -> AsyncOperation.add_completed(OnRequestOperationCompleted)  /  BundleLoader.OnAssetBundleLoadCompleted
```
`BundleLoader.ReportCorruptAsset` (0x252b58c) repete LoadFromFile(path, 0, get_BundleEncryptOffset) com log em StringBuilder (re-tentativa/diagnóstico de bundle corrompido).

Callers de `get_BundleEncryptOffset` em TODO o RX 1.9.5 (varredura de todos os BL): somente `BundleLoader::Load` e `BundleLoader::ReportCorruptAsset`.
Callers de `AssetBundle::LoadFromFile`: `BundleLoader::Load`, `BundleLoader::ReportCorruptAsset`, `UnityEngine_AssetBundleWrap` (binding Lua). `LoadFromFileAsync`: `BundleLoader::Load`, wrap Lua. `LoadFromMemory(Async)`: só `CriWare.CriFsLoadAssetBundleRequest::Update`, `WWW::get_assetBundle` e wrap Lua. `LoadFromStream*`: só wrap Lua.
→ Não há `CreateFromMemory`/decrypt-buffer em C# do jogo no caminho dos bundles de jogo.

### 2.2 Classes/métodos (1.9.5, RVA)
**CenturyGame.GameFramework.AssetBundleMgr** (singleton): Init 0x25274bc · Start 0x2527784 · Update 0x25278a4 · Load 0x252808c · LoadInner 0x2528214 · LoadAsset 0x2528638 · LoadAssetInner 0x252872c · LoadScene 0x2528930 · OnAssetBundleLoadCompleted 0x2529148 · GetLoaderGroup 0x2528e04 · CreateCache 0x2527d84 · LoadShader 0x25277cc · OnShaderBundleLoadCompleted 0x25299d4 · GetDependencies 0x2527ea8 · FindAssetBundleNameFromAssetPath 0x2527be4 · …
**Loader / BundleLoader / BundleAssetLoader / AssetLoader / StreamLoader / SceneLoader / ResourceLoader**: BundleLoader::Load 0x252b15c · OnAssetBundleLoadCompleted 0x252b330 · CancelLoad 0x252b3e8 · ImmediateFinish 0x252b44c · OnRequestOperationCompleted 0x252b4a4 · ReportCorruptAsset 0x252b58c · BundleAssetLoader::Load 0x252acc8 · Loader::Load 0x252a790 · Loader::OnLoadCompleted 0x252a80c · StreamLoader::Load 0x252c57c (UnityWebRequest).
**AssetDataInfo**: GetFullPath 0x24d1df0 · get_BundleEncryptOffset 0x24d1e4c · GetPersistentDataPath 0x24d1738 · GetStreamingAssetsPath 0x24d1d58 · CheckFlag 0x24d1564 · GetUrl 0x24d1b6c.
**AssetBundleHelper**: GetAssetBundleSuffix 0x24d775c · ToRealPath 0x24d77f4 · GetAssetBundleNameWith(out)Extension 0x24d78a0/0x24d79cc · UnloadAssetBundle 0x24d7aac. `AssetBundleDownloadHandler` (SupportFileSystem, UnloadAssetBundle 0x24d76f0).
**AssetBundleContentData / AssetBundleData / AssetBundleMapping** (manifest ab↔asset): Init 0x252f1cc · OnAssetBundleMappingLoadCompleted 0x252f910 · OnMonoScriptsLoadCompleted 0x252feac.
**AssetModule** (download/versão/SearchAsset 0x250a5d8, DownloadAssetBundle 0x250b558, DownloadPatch 0x250b27c), **DownloadPatchTask**, **AssemblyPatch** (Apply 0x24fe20c / ApplyInner 0x24fe254 / ApplyPatch 0x24fe48c → `IFix.Core.PatchManager.Load` 0x370da08/0x370dbb8).
**LuaLoader** (lua em bundles): Init 0x2532990 · AddLuaBundle 0x2532b1c · ReadZipFile 0x2532c18 · GetLuaFromBundle 0x2532f64 (TextAsset.bytes — sem decrypt) · ReadFile 0x25330cc. **LuaModule** abre libs (OpenCrypt 0x25345b0 = lua `crypt` lib, é libtolua, não bundles).
**Binding Lua**: UnityEngine_AssetBundleWrap::LoadFromFile 0x1e4bb78 etc.
Não existe nenhuma classe `ABLoader/XAsset/ResourceManager`-estilo com decrypt; as únicas `Decrypt*` do dump são TLS (BestHTTP/BouncyCastle/Burst GCM).

### 2.3 Padrão IFix (importante para quem interpretar o disassembly)
Quase todo método do Assembly-CSharp começa com `mov w0,#id ; bl IsPatched ; … bl GetPatch ; b __Gen_Wrap_N`. IDs mudam entre versões (ex.: BundleLoader::Load 0x5238 → 0x5faa). Por isso o matcher mascara `movz w0,#imm`.

## 3. Onde estão as mesmas funções em 1.14.27 (partA_inflated.bin)

Método de localização e disciplina de falso-positivo:
- Janela = os primeiros N≤64 instruções (N=comprimento até o primeiro `ret`, máx. 256 B); busca deslizante dentro de ±0x30000 B do delta local corrente (delta é "re-ancorado" somente com strict ≥85 % **e** 2º melhor <80 %; primeiro item de cada grupo: busca em ±0x1800000).
- **strict** = comparação por palavra de instrução com `BL`, `ADRP` e `movz w0/1/2,#imm` mascarados (imediatos de endereço/ID mudam entre builds); **loose** = strict + mascara offsets imm de LDR/STR/ADD (offsets de campos estáticos/literais); **raw** = igualdade byte a byte pura (o critério ≥95 % do briefing). 
- **Aviso:** o raw ≥95 % NÃO é atingível para funções com BL/ADRP (os imediatos sempre diferem entre builds); ex. `LoadAsset` tem raw 95,0 %, mas só porque é quase só ALU. Eu **não aceitei** nada por loose/raw sozinho: aceitei com (a) strict ≥95 % em janela ≥12 instr **e** 2º melhor ≪ melhor, ou (b) validação cruzada por grafo de chamadas (o alvo de um BL dentro de uma função já localizada cai na função candidata, e o disassembly lado a lado é idêntico exceto imediatos).
- Funções <12 instr (getters triviais) casam com dezenas de clones — **ambíguas, não reportadas como localizadas**.
- Falsos positivos observados na 1ª passada (matcher de chave de 8 palavras e busca ±0x10000 com delta mal ancorado): `AssetBundleMgr::Contains` 53 %, `Update` 75 % (n=16) etc. caíam em funções aleatórias; o 1º script re-ancorou o delta com 50 % e contaminou o resto. Corrigido com os limiares acima.

Delta observado (file_off_114 − file_off_195): região do carregador **−0x9c79bc…−0x9c7ae0** (código movido ~10 MB p/ trás); AssetDataInfo/AssetBundleHelper/AssetModule/AssemblyPatch **+0x395ed8…+0x39fd78**; UnityEngine.AssetBundle (extern) **+0x350954**; PatchManager **+0x33ccb0**.

### 3.1 Tabela — funções localizadas em 1.14.27
`janela` = nº de instruções (×4 B); `strict` = % palavras iguais com máscara (BL/ADRP/IDs); `2º` = melhor candidato alternativo (unicidade). file_off em partA_inflated.bin (hex).

| 1.9.5 função (RVA) | file_off 1.14 | janela | strict | loose | raw | 2º | veredito |
|---|---|---|---|---|---|---|---|
| AssetBundleMgr::LoadAsset (0x2528638) | 0x1b5cb58 | 60 (240 B) | 100,0 % | 100,0 | 95,0 | 18 % | **confiável** |
| AssetBundleMgr::UnloadAsset (0x25288a0) | 0x1b5cdc0 | 35 (140 B) | 100,0 % | 100,0 | 90,7 | 31 % | **confiável** |
| AssetBundleMgr::UnloadScene (0x2528c98) | 0x1b5d288 | 30 (120 B) | 100,0 % | 100,0 | 90,0 | 40 % | **confiável** |
| AssetBundleMgr::CreateCache (0x2527d84) | 0x1b5c1f0 | 64 (256 B) | 93,8 % | 96,9 | 84,8 | 34 % | provável (<95 strict, único) |
| AssetBundleMgr::LoadAssetInner (0x252872c) | 0x1b5cc4c | 49 | 93,9 % | 95,9 | 86,7 | 26 % | provável |
| AssetBundleMgr::Load (0x252808c) | 0x1b5c584 | 64 (256 B) | 89,1 % | 95,3 | 77,3 | 41 % | provável (delta coerente −0x9c7b08) |
| AssetBundleMgr::LoadInner (0x2528214) | 0x1b5c70c | 64 | 70,3 % | 71,9 | 67,2 | 33 % | só por posição/delta (corpo diverge) |
| AssetBundleMgr::OnAssetBundleLoadCompleted (0x2529148) | 0x1b5d738 | 64 | 84,4 % | 93,8 | 71,1 | 31 % | provável (posição+único) |
| AssetBundleMgr::LoadShader (0x25277cc) | 0x1b5baa4 | 64 | 87,5 % | 93,8 | 72,3 | 41 % | provável |
| **BundleLoader::Load (0x252b15c)** | **0x1b5f7a0** | 64 (256 B) | 90,6 % | **96,9** | 77,3 | 36 % | **confirmado** — disassembly completo lado a lado: *idêntico* a 1.9.5 exceto imediatos/IDs IFix/offsets de campo; alvos dos BL: SearchAsset→0x28a6294, GetFullPath→0x2863cc8, get_BundleEncryptOffset→0x2863d24, LoadFromFileAsync→0x3e4f66c, LoadFromFile→0x3e4f7a0 |
| BundleLoader::OnAssetBundleLoadCompleted (0x252b330) | 0x1b5f974 | 64 | 90,6 % | 93,8 | 78,1 | 39 % | confirmado (só diferem imediatos) |
| BundleLoader::.ctor / Reset | 0x1b5f740 / 0x1b5f748 | 64 | 89,1 % | 93,8 | 75,8 | 39 % | provável |
| BundleLoader::CancelLoad / ImmediateFinish / OnRequestOperationCompleted | **ambíguo** (clone de BundleAssetLoader: 2º=idêntico) | 24/21/49 | 95,8/95,2/89,8 | – | – | =melhor | ambíguo (resolver por posição: CancelLoad ≈ 0x1b5f59c é de BundleAssetLoader) |
| BundleLoader::ReportCorruptAsset (0x252b58c) | 0x1b5fbd0 | 64 | 65,6 % | 93,8 | 35,9 | 59 % | só posição; **cabeçalho casa, corpo ≥ palavra 65 diverge** (nº de inits estáticos diferente) — merece leitura manual |
| BundleAssetLoader::Load (0x252acc8) | 0x1b5f30c | 54 | 85,2 % | 94,4 | 70,4 | 44 % | provável |
| Loader::Load / OnLoadCompleted / AddCallback | 0x1b5edd4 / 0x1b5ee50 / 0x1b6023c | 64 | 90,6 / 89,1 / 93,8 | 95,3 / 95,3 / 96,9 | 79 / 80 / 84 | 45 / 44 / 36 | provável |
| **AssetDataInfo::get_BundleEncryptOffset (0x24d1e4c)** | **0x2863d24** | 17 (68 B) | 94,1 % | – | 76,5 | **88 % (ambíguo isolado)** | **confirmado por grafo de chamadas** (alvo do BL dentro de BundleLoader::Load 1.14) + 20-instr lado a lado idêntico: `mov w0,#0x5b0a; IsPatched; GetPatch; b __Gen_Wrap…; mov w0,wzr; ret` |
| AssetDataInfo::GetFullPath (0x24d1df0) | 0x2863cc8 | 40 | 92,5 % | 92,5 | 77,5 | 70 % | confirmado por grafo de chamadas |
| AssetDataInfo::.ctor (0x24d1468) | 0x2863310 | 60 | 96,7 % | 96,7 | 87,5 | 23 % | **confiável** |
| AssetDataInfo::GetStreamingAssetsPath / GetPersistentDataPath | 0x2863c30 / 0x28636cc | 64 | 87,5 / 84,4 | 90,6 / 89,1 | 75,8 / 73,8 | 48 | provável |
| AssetModule::SearchAsset (0x250a5d8) | 0x28a6294 | 63 | 92,1 % | 95,2 | 82,9 | 57 % | confirmado por grafo de chamadas |
| AssetBundleHelper::ToRealPath / GetAssetBundleSuffix | 0x2869720 / 0x2869688 | 64 / 37 | 79,7 / 81,1 | 90,6 / 91,9 | 66,8 / 71,6 | 45 / 57 | provável (posição coerente, delta +0x395f2c) |
| UnityEngine.AssetBundle::LoadFromFile(...) externs (0x3b02dc0/…/0x3b02e4c) | 0x3e4f714 / 0x3e4f758 / 0x3e4f7a0 | 64 | 82,8–84,4 % | **100,0** | 77–80 | 57–84 | wrappers de icall idênticos (loose 100 %); distinção entre sobrecargas só por posição/BL |
| UnityEngine.AssetBundle::LoadFromFileAsync (0x3b02d18) | 0x3e4f66c | 64 | 84,4 % | 100,0 | 80,5 | 68,8 | idem |
| LuaLoader::Init/AddLuaBundle/ReadZipFile/GetLuaFromBundle | 0x1b67090 / 0x1b6721c / 0x1b67318 / 0x1b67664 | 64 | 90,6 / 87,1 / 81,2 / 85,9 | 95–96 | 61–82 | 35–47 | provável (delta −0x9c7900 coerente) |
| AssemblyPatch::Apply / ApplyInner / ApplyPatch | 0x289720c / 0x2897254 / 0x2897488 | 64 | 81 / 72 / 86 | 95 / 92 / 95 | 56 / 52 / 71 | 47–55 | provável (delta +0x39d000 coerente) |
| IFix.Core.PatchManager::Load (path) | 0x3a466b8 | 63 | 90,5 % | 96,8 | 83,7 | 51 % | provável |

Saída completa: `loc_core.out` (loader/mgr) e `loc3.out` (restante, 219 linhas; linhas com strict <85 % ou "2º" próximo do melhor devem ser ignoradas — vários grupos AssetModule::* dessa saída são ruído).

### 3.2 Observação semântica 1.14 vs 1.9.5
O fluxo de `BundleLoader::Load` em 1.14.27 é **instrução por instrução o mesmo** de 1.9.5 (SearchAsset → GetFullPath → get_BundleEncryptOffset → LoadFromFile[Async](path, 0, offset)), inclusive o stub IFix de `get_BundleEncryptOffset`. A Rodada 1.9.5→1.14 não introduziu loader novo em C#. Isso indica que a mudança de formato do bundle (prólogo no bloco 0) tem de ser consumida pelo parser nativo do Unity (libunity) ou pelo próprio formato.

## 4. Constante do prólogo (`16 00 01 00 [15|16] 16 [0a|0b] 00`)

Varridos: partA_195.bin (69,5 MB), partA_inflated.bin (73,3 MB), unity_image.bin (libunity 1.14 desempacotado, 19,8 MB), libsigner.so, libnesec.so, libtolua.so, libmain.so, lib_burst_generated.so, libNetHTProtect.so (empacotado — ineficaz).
Buscas: (i) bytes `16 00 01 00` crus; (ii) palavra 2 `15|16 16 0a|0b 00` como u32 LE (0x000a1615/6, 0x000b1615/6) crua e em par com palavra 1 (8 B adjacentes); (iii) MOVZ/MOVK (qualquer ordem, janela de 4 instr., reg igual) montando 0x00010016 e as 4 variantes da palavra 2.
Resultados:
- (iii) **0 hits em tudo**. (ii) **0 hits** em tudo (nunca aparece o prólogo de 8 B).
- (i) hits crus: 4 em cada RX (1.9.5: 0xd45dec,0xd5e610,0xe01ca2,0xe342f8; 1.14: 0xded540,0xe07774,0xe751de,0xe915d0) e 2 em libunity (0x12d2a68, 0x12e752c). Verificados os 4 de 1.14: são **tabelas de dados** coincidentes (sequências 15 00 01 00 / 16 00 01 00 / 17 00 01 00 de contador+campos u32, e listas de u16), **não** código. Hits de libunity não inspecionados em detalhe (região de dados). Disciplina: contagem de 4/73 MB é o esperado do acaso (~4 B → 17 hits/73 MB aleatórios).
- libsigner/libnesec/libtolua/libmain/burst: 0 hits crus e 0 MOVZ/MOVK. Strings relevantes (`unityfs|assetbundle|bundle|loadfromfile|decrypt|archive`): **nenhuma** nessas libs.
- libunity (desempacotado) só tem strings de decrypt do **mbedtls** (TLS) — sem crypto de bundle. Possui proxies `::Scripting::UnityEngine::AssetBundleCreateRequestProxy`, `Archive*` etc. (Unity padrão).
Observação: `libsigner.so` não está em `xapk/native_extract` — extraída de `config.arm64_v8a.apk` (`lib/arm64-v8a/libsigner.so`, 983 864 B).

## 5. Limites / o que NÃO foi feito
- Sem dump de RVAs 1.14 → file_off, não RVA, para 1.14.
- Não foi feita análise de decomp (Ghidra) de libunity; não verifiquei se IFix de fato aplica patch em 1.14 (o repo afirma "inativo" em 1.9.5; offset de bundle = 0 é consistente com o `UnityFS` em offset 0 dos arquivos).
- `ReportCorruptAsset` em 1.14 diverge a partir da palavra 65 — não foi lido manualmente.
- Janelas de 256 B limitam a confiança a funções ≥12 instr.

## 6. Próximos passos sugeridos
1. Prólogo é dado de formato, não constante de código: verificar se `16 00 01 00 15|16 16 0a|0b 00` é o início do SerializedFile/ArchiveStorage block 0 *após* uma etapa de transformação; o consumidor é o código de `ArchiveStorageReader` em libunity → procurar nele **sem strings**: ancorar em `ArchiveStorageHeader` (leitura big-endian de size/csize/usize/flags em offset após "UnityFS\0"), i.e. instruções `REV` (byte-swap) em sequência de 3 loads u32/u64 consecutivos — o corpo do reader de header é achável por padrão (ver `collect.py:parse`), e os flags de compressão (`fl&0x3f`) levam ao despachante de descompressão; ali procurar um tipo de compressão extra (4+) ou transformação pré-LZ4 do bloco 0.
2. Confirmar em runtime (Frida, quando o celular estiver disponível): valor de retorno de `AssetDataInfo::get_BundleEncryptOffset` (1.14: file_off 0x2863d24 / RVA provável 0x2867d24) e se `IsPatched(0x5b0a)` é verdadeiro.
3. Ler manualmente `ReportCorruptAsset` 1.14 (0x1b5fbd0) por mudança de fluxo.
4. `AssemblyPatch::ApplyPatch` 1.14 (0x2897488) → ver de onde vem o arquivo de patch IFix e se existe patch que redefine `get_BundleEncryptOffset`.
