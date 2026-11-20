# Lane G — Payloads IFix (hot-update): inventário, superfície de carga, conclusão

Escopo: leitura apenas (APKs, dump.cs, partA_195.bin). Celular e repo intocados.
Artefatos: `laneG/scan.py` (varredura de bundles, blocos 1..N), `scan195.txt`, `scan1427.txt`, `lua.py`, `lua64.bin` (blocos ≥1 do luapackage_64 1.9.5), `inv.sh`.

## 0. TL;DR
1. **NENHUM payload IFix existe nos APKs** (1.9.5 e 1.14.27, os 3 splits cada). Nem por nome de arquivo, nem por conteúdo.
2. Patches IFix, se existirem, **chegam do CDN pelo sistema de manifesto de assets do jogo** (flag `patch`), caem em *persistentDataPath* e são aplicados por `AssemblyPatch.Apply`. Estado "sem patch" confirmado antes por Frida (ASSEMBLIES.md: "IFix.Core inativo em runtime — nenhum patch carregado").
3. **A teoria unificada (decryptor do bloco 0 = código IFix) fica enfraquecida**: `get_BundleEncryptOffset` tem como corpo ORIGINAL `return 0` (`mov w0,wzr; ret` depois do prólogo IFix padrão — que existe em *todo* método do Assembly-CSharp, não só neste). Além disso `offset` do `LoadFromFile` é só um prefixo de bytes antes de `UnityFS`, não tem relação com o bloco 0 interno. Mesmo um patch IFix que o redefina só poderia mudar esse prefixo.
4. IFix só consegue substituir **métodos C#** (VM interpretada). Ele não tocaria o parser UnityFS (nativo em libunity). Para o bloco 0 a pista continua sendo libunity / formato — não IFix.

## 1. Inventário (com caminhos)
Listagens: `unzip -Z1` de cada apk em `/home/re/work/apk/{xapk195,xapk}/` (resultados em /tmp/l_*.txt no distro).

| APK | entradas | achados por nome (`ifix|patch|hotfix|\.dll`) |
|---|---|---|
| xapk195/com.run.tower.defense.apk | 1449 | só `assets/bin/Data/Managed/Resources/{Entitas,mscorlib}.dll-resources.dat` (recursos .NET, nada de IFix) |
| xapk195/config.arm64_v8a.apk | 24 | nada (libs nativas) |
| xapk195/game_asset.apk | 6671 | nada (só `.unity3d`, `.acb/.awb`, `assets/world/*.bytes`) |
| xapk/(1.14.27) com.run.tower.defense.apk | 1504 | idem |
| xapk/config.arm64_v8a.apk | 24 | nada |
| xapk/game_asset.apk | 7330 | nada; extra `assets/config/{deqp,device_d,gpus_p,gpus_r}_*.bytes` |

- `assets/bin/Data/` (StreamingAssets/Unity): `Managed/Metadata/global-metadata.dat` (magic `HTPX`, 11.6 MB, cifrado → strings inacessíveis), `ScriptingAssemblies.json`, `RuntimeInitializeOnLoads.json`, `boot.config`, `level0-2`, `sharedassets*`, ~65 blobs `Data/<md5>` (assets de cena). Sem DLLs (il2cpp). **Nenhum arquivo `*.patch`/`*.ifix`/`*.bytes` de patch.**
- Não há IFix.Core.dll no APK em si (vem do metadata; 018_IFix.Core.dll.json = 41 classes do dump).
- **Varredura de conteúdo** (`scan.py`): 6632 bundles (1.9.5) + 7279 (1.14.27), 0 falhas de parse, blocos 1..N descomprimidos, regex `ifix|ILFix|hotfix|\.patch|PatchManager|AssemblyPatch|BundleEncryptOffset`; arquivos não-UnityFS também varridos. Resultado: **zero ocorrências de IFix/ILFix/PatchManager/AssemblyPatch/BundleEncryptOffset**. As únicas ocorrências de "hotfix" são em `luapackage_32/64_*.unity3d` (bytecode LuaJIT): lógica de *hot-update de recursos* em Lua — `HotFixConfig`, `GameUpdateHelper.HotfixNotify`, `IsNeedHotFixUpdate`, `resVersion`/`appVersion`/`hotFix` (campos da resposta do servidor), URLs `%s/api/maintain_data?kingdom=%s&language=%s` e `%s/api/kingdom/status?env=%s&language=%s`, `err_hotfix_helpe_data_error`. Isso é notificação de versão de recursos, não IFix. (1 falso positivo `ifiX` em dados binários de cena.)
- Limitação: o bloco 0 (primeiros ~128 KB de cada CAB) não foi lido; um patch de ≥128 KB ou um bundle pequeno inteiro dentro do bloco 0 não é visto — mas nenhum nome de bundle sugere patch (nem `patch`, `ifix`, `hotfix`).

## 2. Superfície de carga IFix (1.9.5, dump.cs + disassembly partA_195, file_off = RVA − 0x4000)

**IFix.Core** (dump.cs l.221600+): `PatchManager.Load(string filepath)` 0x370da08 · `Load(Stream, bool checkNew)` 0x370dbb8 · `readMethod` 0x3710610 · `readSlotInfo` 0x3711710 · `getRedirectField` · `Unload`; `VirtualMachine.InitializeGlobal(Stream)` 0x370d7c8 / `ReplaceGlobal(Stream)` 0x370d824 / `Execute` 0x3700e50; `IFix.Version.FILE_FORMAT` (string estática); `WrappersManagerImpl` (`IsPatched(id)` 0x262cde8, `GetPatch(id)` 0x262cd6c).

**Lado do jogo** (CenturyGame.GameFramework): `AssemblyPatch` (só 3 métodos):
- `Apply(bool isTempFile)` 0x24fe20c → `ApplyInner` 0x24fe254.
- `ApplyInner(isTemp)` (disasm confirmado): se `!isTemp` e uma condição de tipo (`Type.op_Equality` de 3 tokens de runtime — provavelmente plataforma/editor) não bate, **itera uma string[] estática** (campo estático da classe em GOT 0x3fdb000+0xf40), para cada nome faz `StringBuilder.AppendFormat(fmt, nome)` (fmt = literal do metadata, cifrado), chama `AssetModule.GetPatchInfo(nome, out AssetDataInfo)` (0x250a798, consulta `AssetModule.m_patches`), e se `AssetDataInfo.IsFileExist()` → `ApplyPatch(AssetDataInfo.GetPersistentDataPath())`.
- `ApplyPatch(string path)` 0x24fe48c: `new FileStream(path, Open(3), Read(1))` → `PatchManager.Load(stream, checkNew=true)` → `Dispose`. (Chamada 0x24fe558.)
- Origem dos bytes: **sempre arquivo no persistentDataPath**; nunca embutido no APK nem em StreamingAssets.

**Pipeline de download**: `AssetsChecker` (static `Manifests` string[], `FileInfo{path, code, bool patch}`) → `AssetDownloadMgr` (`m_assets`, **`m_patches`**, `CheckManifest`) → `DownloadPatchTask` (`Start`, `OnDownloadSplitManifest`, `OnDownloadPatchManifest`, `CheckAndDownload`) + `PatchSizeDownloader`/`SimpleDownloader.Start(pathSrc, pathDst)`; `AssetModule.m_patches` (preenchido ao ler a versão do asset: `OnAssetVersionLoadCompleted`). Ou seja, um patch é um item do manifesto marcado `patch=true`, com `code` (hash/md5 no nome), baixado para persistent.

## 3. CDN / URLs
Não recuperáveis estaticamente: o formato do manifesto e os hosts são literais no `global-metadata.dat` (cifrado HTPX) e no Lua só aparecem `HotFixConfig` + `%s/api/maintain_data…`/`/api/kingdom/status…` (API de manutenção/status, host injetado). Para obter: (a) captura MITM do primeiro run (captures/ tem só battle*.pcap, sem boot); (b) hook Frida em `AssemblyPatch.ApplyInner` + `AssetModule.GetPatchInfo` (os nomes da string[] e o fmt aparecem como argumentos) — as RVAs 1.9.5 são 0x24fe254 / 0x250a798; (c) `SimpleDownloader.Start(pathSrc,pathDst)` 0x2509bec dá a URL exata e o destino.

## 4. Decodificação
Sem payload → nada a decodificar. Formato IFix (referência, **não verificado online nesta lane, sem acesso a web garantido; de memória do repo Tencent/IFix**): arquivo `.patch` = BinaryReader sequencial: cabeçalho com `Version.FILE_FORMAT`, tabela de assemblies/tipos externos, tabela de métodos lida por `readMethod` (assinatura em string + regex de genéricos, vide `<readMethod>c__AnonStorey0.<>m__0(Match)`), `readSlotInfo` (vtable/slots de ITF), depois blob de instruções (`IFix.Core.Code` enum, `Instruction` 8 bytes) consumido por `VirtualMachine.Execute`. Quando houver um `.patch` real, o decodificador mais seguro é rodar a lib `IFix.Core.dll` (do metadata) ou portar `PatchManager.Load` — ver passos.

## 5. Próximos passos
1. **Não investir mais em IFix estático**: não há payload. Se quiser fechar a teoria, ler em runtime: Frida `AssemblyPatch.ApplyInner` (0x24fe254 em 1.9.5; em 1.14 achar por assinatura `mov w0,#imm; IsPatched`) + `PatchManager.Load` (`ifix_tracker.js` já tem). Se `ApplyPatch` nunca é chamado e `IsPatched(0x4f12)` = false → teoria refutada de vez.
2. Listar `persistentDataPath` no celular (usuário; não toquei) por arquivos com nome de patch — a string[] de `ApplyInner` aponta o nome. Se existir, é o payload.
3. Voltar ao bloco 0: alvo é libunity (ArchiveStorage/`ReadBlocksInfo`) ou transformação dentro do formato (lane C: XOR 0xA6 + chave por-bundle, só 4096 B). IFix não pode implementar isso (só substitui métodos C#, e `BundleLoader.Load` é idêntico entre versões).
4. Opcional: decifrar `global-metadata.dat` (HTPX) para recuperar literais (`fmt` e nomes dos patches, URLs de CDN) — já coberto pelos relatórios meta_recon.md/partb_format.md (libil2cpp_*_full.so tem a metadata-registration).
