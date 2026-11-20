# LANE LUAPKG — RELATÓRIO

## TL;DR
**luapackage achado, decifrado, extraído e validado.** Os schemas sproto **completos** (texto-fonte, com comentários em chinês) do gateway estão recuperados, e o decoder escrito sobre eles decodifica **312/312 frames** do `gw_transcript115.pkl` (1.14.27) campo a campo, incluindo as msgs 8501/3001/1029 e as camadas cifradas (`crypt_method=1`).

## 1. Onde estava
Não era o `cache_crypt_payload.bin` (esse é payload de metadata/il2cpp). Estava em `/home/re/work/apk/xapk/game_asset.apk` (1.14.27) e `xapk195/game_asset.apk` (1.9.5) (WSL `kingshot-re`):
- `assets/data/luapackage_64_74a1e4b6….unity3d` (40 MB) e `luapackage_32_77bcbf47….unity3d` (40 MB) — **1.14.27**
- `luapackage_64_1ebe3e56….` / `_32_93f769f3….` (28 MB) — 1.9.5
- `toluaout_64/32_*.unity3d` (~145 KB cada) — bundle pequeno (tolua; extraídos mas não analisados a fundo)
Cada bundle = UnityFS com 1 CAB, 772 blocos LZ4 (1.14.27) / 550 (1.9.5); descomprimido = SerializedFile v22 (Unity 2022.3.62f1) de ~101 MB (1.14.27) / 72 MB (1.9.5).

## 2. Método
1. `ext.py`: parse do header UnityFS (BlocksInfo) como `laneC/collect.py`; bloco 0 (primeiros 0x1000 B do stream) decifrado com `block0k/gen/emu_blk.py::run` (emulação de F_01412580); todos os blocos LZ4 (flag 3) descomprimidos e concatenados → `out/*.bin` (SerializedFile). **Funcionou de primeira nos 8 bundles** (versão `2022.3.62f1` visível no header).
2. `dump.py`: UnityPy 1.25.4 `SerializedFile(EndianBinaryReader(bytes))` lê direto o blob: 8334 objetos = **8333 TextAsset + 1 AssetBundle** (1.14.27); 6678 TextAssets em 1.9.5. Soma dos scripts = 99 652 904 B (1.14.27) ≈ os "100 MB".
3. Todo TextAsset é **bytecode LuaJIT 2.x (`1B 4C 4A 02`, flags 0x0A = stripped + FR2/GC64)** — 100% (8333/8333). Não há fonte Lua em claro, **mas strings (nomes de campos/constantes) ficam intactas**, o que basta para os schemas. (Sem `LuaQ`/PUC; `.sproto` não existe como arquivo, o schema é string-constante embutida.)
4. Schemas sproto: vivem como **uma única string-constante UTF-8 gigante** dentro do bytecode de `game_proto_game_proto_c2s` / `…_s2c` (e `game_config_default_game_proto_*`). Extração: KGC string = ULEB(len+5) + bytes no início da constants (`sp.py`).

## 3. Artefatos (tudo em `C:/Users/prs/work/luapkg/`)
| caminho | conteúdo |
|---|---|
| `out/1427_luapackage_64_74a1e4.bin` (+`_32_`, `195_*`, `*toluaout*`) | SerializedFile decifrado+descomprimido (~101 MB/72 MB). |
| `lua/1427_64/*.bin` (8333 arquivos), `lua/1427_32/`, `lua/195_64/` | cada TextAsset = 1 módulo Lua (bytecode LuaJIT). `_index.txt` = lista nome\ttamanho. Nome = caminho do módulo com `_` (ex. `game_module_login_NetMsg`). |
| **`lua/1427_64/game_proto_game_proto_c2s.sproto`** (828 KB), **`…_s2c.sproto`** (523 KB) | **schemas gateway 1.14.27**: c2s = 1261 tipos + **1888 protocolos** (`req_*`), s2c = 1082 tipos + **1005 notificações** (`notify_*`). |
| `lua/1427_64/game_config_default_game_proto_{c2s,s2c}.sproto` | variante "config default" (351/233 KB; subconjunto/versão antiga do schema — não usada na validação). |
| `lua/195_64/*.sproto` | mesmos schemas da 1.9.5 (c2s 980 tipos/1424 protos; s2c 841/795) — útil p/ diff de versões. |
| `proto_index_1427.tsv` | índice dir\tmsgId\tnome\tcomentário (2893 msgs). |
| `sproto_py.py` | parser de schema sproto-texto + 0-unpack + decoder (struct/array/map `*t(key)`/`*t()`, tipos aninhados). |
| `val.py` / `val_out.txt` | validação contra o transcript; saída completa decodificada (312 frames). |
| `ext.py`, `dump.py`, `sp.py` | extratores (rodar com `wsl -d kingshot-re -- python3 …`). |
(Obs.: `PORT_PY.md`, `dec_block0.py`, `pp/` na pasta são de outra lane, não meus.)

## 4. Inventário do luapackage 1.14.27 (8333 módulos)
`game_module_ui` 4121 (views/items/painéis) · `game_config` 1787 (tabelas de config, ex. `game_config_default_payment_config`, `…threedays_shop_item`, `…shop_menu_tab`, `…daily_specials_payment`) · `game_module_logic` 720 (Ctrl/Info de cada módulo: `…threedayshop_ThreeDayStoreCtrl`, `…froststarshop_*`) · `game_module_scene` 710 · `game_helper` 293 · `game_read` 206 (leitores de config: `ShopRead`…) · `game_define` 188 · `btree/hfsm` ~125 · `game_proto` 12 (c2s, s2c, sprotoloader, sproto_crypt, sproto_extend, errcode 110 KB, buffdef…) · `engine_proto_sproto`/`sprotoparser` · `game_module_login_NetMsg`/`ProtoHandler`.
Observação: as **tabelas de config do jogo (`game_config_default_*`, 1787) também estão aqui** (bytecode com constantes) — mina para espelhar dados de loja/pagamento no mock, mas exigem decompilador/leitor de constantes LuaJIT (próximos passos).
"conquest": só UI (`BestZoneConquestSubPanel`); nenhum msg de rede com "conquest" no nome — o equivalente provável é a família `supremacy_war_*`/`bestzone`/`kingdom` (grep no `proto_index_1427.tsv`). Pagamento: `req_recharge_by_voucher 6707`, `req_recharge_by_token 6708`, `req_recharge_get_first_reward 6705`, `notify_recharge_init 6701`, `req_webshop_login_license 6795`; loja: `req_shop_quick_buy 2001`, `req_shop_info 2002`, `req_shop_buy 2003`, `req_shop_refresh 2004`, `notify_shop_open 2051`, etc.

## 5. Formato do wire (confirmado)
- Frame = `sproto-pack(.package ++ body)`; `.package {type 0, session 1, ud 2 {crypt_method 0, crypt_length 1}}`. Req: `type`=msgId (tag do protocolo) + `session`; resposta: só `session` (sem type) → body = `response` do protocolo da sessão; push: só `type` → `request` do `notify_*` s2c. (Já bate com a hipótese de spec_server.md §1, agora com schemas.)
- **`ud.crypt_method=1`** (frames de 1029, 1023, 3001 e respostas): o body (após o header) é XOR com chave periódica de 4 B **`ec ba bc b9`** (nesta sessão cap115/1.14.27; `crypt_length` = tamanho do ciphertext do req; no resp o ciphertext é o restante do frame). Chave recuperada por texto-claro conhecido (zeros do sproto) e confirmada: plaintext fecha 100%. É o `bxor` de `game_proto_sproto_crypt` (strings: `key_default`, `key_rc4_enc/dec`, `bxor` — há também modo RC4 não visto no transcript). **Pendência**: a chave é por-sessão/handshake? (nas capturas anteriores `ef ba be b9`/`b9 24 5f bd` — mesma família "kind03"). Lua `sproto_crypt` é o lugar para ler a derivação (bytecode LuaJIT, 2.8 KB — pequeno).

## 6. Validação (critério do task)
`val.py` com schemas 1.14.27 × `gw_transcript115.pkl`: **312/312 frames** decodificados com consumo exato do buffer (≤7 B de padding do pack). Exemplos (ver `val_out.txt`):
- `req_trigger_opinion` **8501**: `{type:1, sid:221, is_anonymity:false, content_id:1001016}` → resp `{code:0}` (resp **8552** = `notify_opinion_update`).
- `req_players_base_info_with_permission` **1029** (cifrado): `{permission:1, uids:[34174824]}` → `{code:0, overload:0, result:[{lv:1,image:1009,kid:931,stove_lv:39,nickName:"幸運就是我7945",…}]}` (nome e uid 0x02097768 batem com kind03_codec.md §3.6).
- `req_save_client_data` **3001** (cifrado, 2522 B): `{data:{law_point:18580767, survivor:[{sid:1,res601:83.26…,res602:97.49…,…}×31…]}}` — o "snapshot de 31 registros × 5 doubles" do kind03 era `client_data.survivor[]` com `res601..607` (recursos/medidores por sobrevivente); resp `{code:0}`.
- `req_heartbeat` 22 → `{time:1795057419}`; `req_loaddata` 21; `req_loginauth` (type 1: account, sdkToken, version "1.14.27", device…) → `{code:0, serverid:931, uid:40444746, version_info…}`; push inicial ~50 `notify_*` (game_init, quests, alliance_init, base_info, backpack_init, hero_init, equipment_info, recharge_init…) todos com valores plausíveis (servertime 1795057408 etc.).
- **2803** (`req_survivor_update_cure_end_time`), **20463** (`req_climbtower_challenge`), 20466/20474 (`notify_climbtower_tower_update`/`currency_update`): presentes no schema (c2s l.23995 / l.14468; s2c l.10841/10848); o transcript cap115 (login+ocioso) não contém 2803/20463 — eles são do cap_combat2 (frames.pkl de kind03), **não decodificados por mim nesta lane** (o formato é o mesmo; basta rodar `val.py` apontando para os frames de `work/kind03/frames.pkl`).

## 7. Limites honestos
- Código Lua em si **não** está decompilado (LuaJIT bytecode stripped, sem nomes de locals/linhas). Só strings/constantes e schemas. Lógica de loja/validação requer decompilador (ljd/luajit-decomp); o schema sproto, que era o objetivo, está completo.
- 1.14.27 e 1.9.5 têm schemas diferentes (1888 vs 1424 protos c2s) — usar o da versão do cliente-alvo (1.14.27 ↔ transcript).
- O modo `crypt_method` ≠ 1 (RC4) e a origem da chave XOR por-sessão não foram resolvidos.
- Decoder trata `integer(2)` (decimal fixo) como int cru; sem falhas observadas no transcript.

## 8. Próximos passos
1. Servir esses schemas no `mock_gateway.py`: montar respostas **tipadas** (`loginauth`, `notify_game_init` e as ~50 `notify_*_init` do login, na ordem de `val_out.txt` 1.326–1.521 s) — provável causa do travamento em 99% do loading.
2. Implementar encoder sproto (inverso do `Dec`) + 0-pack + XOR `ec ba bc b9`; round-trip contra os 312 frames.
3. Decompilar `game_config_default_*` (payment_config, shop_*) com ljd para espelhar loja/pagamento.
4. Rodar `val.py` em `kind03/frames.pkl` (cap_combat2) para fechar 2803/20463/20466/20474.
5. Ler `game_proto_sproto_crypt` (derivação da chave) por disassembly LuaJIT.
