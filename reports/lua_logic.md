# LANE LUA-LOGIC — Relatório (client Lua do Kingshot 1.14.27, offline)

Fonte: `C:/Users/prs/work/luapkg/lua/1427_64/` (8333 módulos LuaJIT 2.1 stripped, FR2/GC64). Tudo abaixo vem de análise estática do bytecode; **nada foi escrito no repo**.

## TL;DR
- Escrevi um parser próprio de bytecode LuaJIT (`ljparse.py`, 8333/8333 módulos, 112 411 protos, opcodes **padrão** — sem permutação) + um "decompilador simbólico" linear (`ljdis.py`, pseudo-código com expressões rastreadas; **não** reconstrói if/loops, só sequência de instruções com `? cond` marcando comparações).
- Os módulos **não têm nomes de função** (stripped), mas os nomes **sobrevivem como chaves de tabela** (`t.GetPrice = <closure>`, `r0._boughtCount`), então a estrutura de classes/métodos é recuperável quase 1:1.
- **Mapa msgId → módulo → função handler: 2455 registros** (`HANDLERS.tsv`; 2404 casam com msgId do schema sproto, 51 são nomes que não existem no schema 1.14.27 = código morto/legado). Mais `MSGMAP.tsv` (2796 nomes de msg citados por módulos, 2728 casados com msgId).
- **1389 tabelas de config reais extraídas** (`cfg/*.json`, 30 MB): preços de loja, recompensas de pass, custos de refresh, requisitos etc. — via mini-VM (`cfgvm.py`). Também `errcodes.json` (3045 códigos de erro nome→número).
- Achado central: o cliente é **fino**: ele só envia `req_*` com ids/contagem e **não calcula preço/validade autoritativamente** (ver §3). A lógica que importa para um servidor emulado é: (a) config (`cfg/`), (b) schema sproto, (c) máquina de estados/fases e `err_*` que o cliente espera.

## 1. Censo (nomes de módulos)
Prefixos: `game_module_ui_*` 4121 (views/itens), `game_config_default_*` 1396 (tabelas), `game_module_logic_module_*` 708 (Ctrl/Info por domínio; ~190 domínios), `game_module_scene_*` 710, `game_helper_*` 293, `game_read_*` 206 (acessores de config), `game_define_*` 188 (enums/constantes), `game_module_btree/hfsm_*` (IA de tutorial/guide, ~125), `game_languages_*` (textos por idioma), `game_proto_*` (schemas + `sproto_extend`, `sprotoloader`, `errcode`, `buffdef`...).

| domínio (regex no nome; um módulo pode cair em vários) | logic | ui | config | read | helper | scene | define |
|---|---|---|---|---|---|---|---|
| TOTAL | 708 | 4121 | 1396 | 206 | 293 | 710 | 188 |
| shop/store/pay/gift/vip/fund | 61 | 289 | 108 | 25 | 26 | 6 | 16 |
| conquest/stage/war/battle/boss/march | 208 | 1241 | 326 | 31 | 54 | 384 | 33 |
| pass/season/sign/festival | 48 | 219 | 34 | 22 | 22 | 0 | 4 |
| hero/skill/equip/soldier/pet/science | 72 | 541 | 99 | 24 | 30 | 64 | 15 |
| mail/chat/friend | 15 | 244 | 13 | 4 | 5 | 0 | 3 |
| alliance | 59 | 350 | 57 | 10 | 13 | 56 | 9 |
| rank/arena/league | 47 | 442 | 77 | 9 | 11 | 1 | 8 |
| quest/task/mission/activity/minigames | 231 | 677 | 367 | 28 | 29 | 76 | 15 |

Domínios lógicos (sufixo `logic_module_<dom>`), amostra: store, pay, payback, recharge, vip, supervip, battlepasscheck/festivalpasscheck/monthweekpasscheck/…passcheck (9 variantes), supremacywar(+activity,+pre), trianglewar(+activity), arsenalwar/arsenalleague, brawlwar, minewar, bestzone, crescent, alliance(+science, +development, +mobilization), hero/herodevelopment/heroictrials, equip, soldier/conscript/hospital, science/firecrystalscience, mail, chat, rank, arena/slg3arena/slg3league, mission/task/todo, world/worldboss/city/cityfield, garden, fishing, monopoly, towerdefence/tdevent/tdbox, etc. Lista completa em `MSGMAP.tsv`/`mod_msgcount.tsv`.
Observação: **não existe módulo chamado "conquest"**; o equivalente de "conquista/estágio" é a família `supremacywar*` / `trianglewar*` / `arsenalwar*` (guerras de aliança com fases) e `find_stage`/`stage_*` configs (§4).

Módulos que mais falam com o servidor (nº de msgs distintas): SupremacyWarMapCtrl 79, AllianceCtrl 63, CheatCtrl 62 (**debug/cheat do próprio cliente — lista de comandos GM!**), ArsenalLeagueWarMapCtrl 61, ChatCtrl 59, FindingGameCtrl 58, WorldMapCapitalCtrl 57, GardenCtrl 46, LinkageMonopolyCtrl 40, PlayerCtrl 34 … (`mod_msgcount.tsv`).

## 2. Mecanismo de despacho de mensagens (o "handler sproto")
Não há um módulo central msgId→função. O padrão é **registro por Ctrl**:
```
Ctrl.Init():  Proxy.Register('req_shop_buy', self, self.ShopBuyRsp)   -- 1877× "UV.Register", 190× NetMsg.Register
Ctrl.ReqX():  NetMsg.SendMsg('req_shop_buy', {shop_id=..,goods_id=..,count=..})
```
Evidência (`dis/game_module_logic_proxy_ProxyBase.txt`, `dis/game_module_login_NetMsg.txt`, `dis/game_module_login_ProtoHandler.txt`):
- `ProxyBase.Register(msgName,target,cb)` guarda `m_listeners[msg]={target,callback}`; `SendMsg` chama `handler(...)`; resposta: se `callback` presente → `callback(target, rsp)`; `rsp.code` default `ErrCodeDef.err_success`, `rsp.request_data = <request original>`.
- `NetMsg.HandleMsg(session, resp, 'RESPONSE'|'REQUEST')`: casa `session` com a tabela de pendentes (guarda `subname/msgid/msgdata`), injeta `request_data`, ignora `req_heartbeat`/`req_spectator_agent_heartbeat` no log, chama `CheckErrorTip` (mapeia `code`→toast), mede 20 ms por handler (`'----处理消息时间超过20ms'`), e despacha pelo `msgid`. `CheckFastTrack` pula fila para certas msgs.
- `ProtoHandler` (login): `Pack(name,args,session)` → `crypt_method = MsgMethod[name]` (só marca msgs cifradas); `Encrypt/Decrypt` com `_secretKeyDic` (`SetSecretKey` → `CreateSecretKey`), `Decode = sproto.pdecode`, `host.dispatch`. Usa `game.proto.sproto_extend` (`client`, `server`, `clientRequest`, `s2c`).
- `ServerProxy` tem FSM de conexão: `start:none→idle`, `login:{idle,berejected,bedisconnected}→loginserver`, `entergame:loginserver→gaming`, `maintenance/rejected/disconnected/logout`. Pack de frame: `bit32.extract(len,8)` + `len,0` = **prefixo de 2 bytes big-endian com comprimento**.
- **Convenção de nome do handler**: `req_x_y` → `XYRsp`/`OnReqXYCallback`; `notify_*` → `OnNotify…Callback`.

**Mapa gerado**: `HANDLERS.tsv` (msgId, msg, módulo, registrador, função), exemplo:
```
2001 req_shop_quick_buy  store_StoreCtrl  BuyRsp
2002 req_shop_info       store_StoreCtrl  ShopInfoRsp
2003 req_shop_buy        store_StoreCtrl  ShopBuyRsp
2004 req_shop_refresh    store_StoreCtrl  ShopRefreshRsp
2005 req_shop_info_array store_StoreCtrl  ShopInfoArrayRsp
16521 req_alliance_supremacy_war_sign_up  supremacywaractivity_SupremacyWarActivityCtrl  OnReqSupremacyWarSignUpCallback
```
Heurística: "primeiro argumento string `req_*`/`notify_*` de chamada `.Register/.AddMsg`" — chamadas dentro de laços/tabelas dinâmicas (msg em variável) não entram; cobre 2455 de ~2893 msgs.

## 3. Loja (store) — preço e limite
Módulos: `logic_module_store_{StoreCtrl,StoreInfo,StoreGoodsInfo}`, `helper_StoreHelper`, `define_moduleDefine_StoreDefine`, `read_StoreRead`, configs `store_conf`, `store_base_conf`, `fixed_store`, `store_grid_lock`, `store_item_sp_conf`, `store_quick_buy_config`, `shop_menu_tab` (+ `threedays_shop_*`, `frost_star_shop*`, `garden_shop`, `lord_skin_shop_conf`...).

**Protocolo (c2s, `game_proto_game_proto_c2s.sproto`)**: `req_shop_buy{shop_id,goods_id,count}→{code,goods}`, `req_shop_refresh{shop_id}→{code,info:shop}`, `req_shop_info{shop_id}`, `req_shop_info_array{arr_id}`, `req_shop_quick_buy{id,count,use,extra}`. **O cliente nunca envia preço.** O servidor devolve `shop{id, goods[{id,grid_id,conf_id,buy_count,tag}], last_refresh_ts, refresh_times}`.

**Lógica client (StoreGoodsInfo/StoreInfo/Helper)** — evidência `dis/*Store*.txt`:
- Cada bem = `conf_id` → linha de `fixed_store` (campos: `store_type,item_id,count,currency,price,original_price,limit_num,limit_number,discount,discount_stamp,lock_condition,limit_condition,order,display_type`) — **o preço vem da config local** (`InitBaseValue: _price = cfg.price`, `_currency`, `_limitCount = floor(limit_num × buff)`). Há exceção: `limit_num` do item `half_exchange_gold_limit_add_buff_good_id` é aumentado por buff de ciência (`FirecrystalScienceHelper.GetBuffAdditionDataByBuffId`).
- `IsFree = price <= 0`; limite: `limitCount<=0` ⇒ tipo `FIXED_LIMITDD(1)`, senão mapeia o `reset_type` do servidor via `STORE_BUY_LIMIT_TYPE_CONFIG_MAP`.
  `UpdateBoughtCount`: boughtCount += n. Sold-out = `boughtCount >= limitCount` (inferido; `IsSoldOut` não inspecionado).
- Enums (`StoreDefine`): `STORE_RESET_TYPE {DAY=1,WEEK=2,MONTH=3,PERIOD=4,NEVER=0xFFFFFFFF}`, `STORE_BUY_LIMIT_TYPE {FIXED_LIMITDD=1,DAY=2,WEEK=3,MONTH=4,PERIOD=5,LIFE=6,UNLIMITED=7}`, `STORE_ID_DEFINE` (DAY_DISCOUNT=101, BIOTIC=201, ARENA=301, ALLIANCE_DAY=401, MYSTERIOUS=601, VIP=701, VENDOR=801, ARSENALWAR=1001, CrystalTranslation=1101, PLAYER_EQUIP_MAT=1301, CRESCENT=1401, TRIANGLE_WAR=1701, SUPREMACY_WAR=1801, SUPREMACY_WAR_GUESS=1901, TOWER_OF_TRIAL=2001, BRAWL_WAR=2401, SLG3_LEAGUE=2601, LORD_SKIN=2801 …).
- **Reset/próximo refresh** (`StoreHelper` p9–p13): DAY→`GetServerNextZeroTime`, WEEK→`NextMondayZeroTime`, MONTH→`NextMonthZeroTimeUtc`, PERIOD→`start + ceil((now−start)/period)·period`. `CalculateNextRefreshDurationWithResetType = max(next − serverTime, 0)`. Também há `CalculateBuyLimitWithStoreId` por loja (lookup por STORE_ID).
- **Custo de refresh** (`GetRefreshGoodsPrice`): `reset_cost` é lista plana `[currency,amount, currency,amount,…]`; usa o par de índice `refresh_times+1` e **trava no último par**. Ex. real (`cfg/store_base_conf.json`, loja 601 "Misterioso"): `reset_cost = 101×0, 101×100, 101×200 … 101×2000` (moeda 101 = gemas provável, +100 por refresh, 21 níveis); `reset_cost_clear_type=1` (zera por dia), `reset_time=NEVER`.
- Abertura: `store_conf[id].open_condition` = lista `[tipo,valor,…]` consumida por `LockConditionHelper.IsConditionCompleted` (ex. loja Arena 301: `{5,326,1}`; Vendor 801: `{1,12}`; Misteriosa 601: `{1,15}`; tipo 1 provavelmente = nível — **inferência**, não verificado).
- Pagamento real (IAP): `pay_PayCtrl` (`req_webshop_login_license` etc.) — não aprofundado.

**Para um servidor**: validar `shop_id/goods_id` contra `fixed_store`/`store_base_conf`, debitar `price×count` da `currency`, respeitar `limit_num`+tipo de reset, devolver `goods{buy_count}` (o cliente só soma `count` localmente e, se vier `new_goods`, troca o item). Erros esperados: `ErrCodeDef.err_*` (`errcodes.json`).

## 4. Pass / fases ("conquest")
**Battle pass / "PassCheck"** (`battlepasscheck_BattlePassCheckCtrl`, `helper_BattlePassCheckHelper`, `read_BattlePassCheckRead`; configs `battle_pass`, `month_integral_battle_pass`, `fes_battlepass_*`, `bp_versions`):
- Msgs: `req_battle_pass_collect_reward / collect_all_reward / buy_score / choose_item`; notifies `OnBattlePassInfo/Purchase/Prepared/ScoreChange`.
- Estado no cliente: `IsBuy` (premium), `IsRewardGet(index,…)`, `GetScore`, `GetSerialNo`, `GetVersionIndex`, `GetChooseItemId`.
- **Nível é por pontos, calculado no cliente só para UI**: `GetLevel` percorre `battle_pass` (linhas `{group,integral,rewards01,rewards02,choose_rewards}`) e acha o maior `integral <= score`; `IsMaxLevel = último.integral <= score`; recompensa livre = `rewards01`, premium = `rewards02` (listas planas `[item,qtd,…]`), liberada só se `IsBuy`. O servidor é quem aceita/nega o `collect`. Exemplo `cfg/battle_pass.json`: grupo 1, níveis em 0,70,140,…; nível 2 → rewards01 `{100113×250}`, rewards02 `{101×100, 500210×2}`.
- `bp_versions[ver].group` liga a versão ativa ao grupo de linhas.

**Fases de guerras** (família "conquista"): `SupremacyWarActivityDefine.ActivityServerStatus = {Nothing=0, Predicted=1, SignUp=2, Dispatched=3, Publicity=4, Fighting=5, Restored=6}`, `FightingStep {Nothing,Preparations=1,Fighting=2,Settlement=3}`, `GoalType {kill_solider=2, loss_solider=3, collect_resource=4, kill_monster=5}`, `AdmittanceCondition {BeOut,Reinforcements,WoundedSoldier,Rampart,Hunting,Confrontation}`. O `SupremacyWarActivityCtrl` (~420 métodos) usa timer (`TimerModule.StartStamp`) que recalcula a fase a partir de `duration[]` por status e do tempo do servidor (`end − duration[Restored-1] − duration[Fighting-1]` → janelas calculadas de trás pra frente): **a fase é derivada de timestamps do `notify_supremacy_war_info`, não de comando** (inferência do pseudo-código). Configs: `supremacy_war_pre_stage`, `war_stage_goal`, `*_stage_goal_reward`, `*_stage_rank_reward`, `alliance_duel_stage_*`, `stage_final_reward`.
Padrão análogo em `trianglewar*`, `arsenalwar*`, `brawlwar*`, `bestzone`, `crescent`.
`find_stage` / `find_chapter` / `chapter_task` / `chapter_quest_conf` = estágios do mini-game FindingGame e capítulos de missão.

## 5. Outros domínios (resumo)
- **Hero/skill**: `hero_HeroCtrl/HeroData`, `herodevelopment_HeroDevelopmentFundCtrl`, configs `hero_develop_*`; defines `HeroDefine/HeroEquipDefine`. Não aprofundado.
- **Mail/chat**: `mail`, `chat_ChatCtrl` (59 msgs). **Alliance**: `alliance_AllianceCtrl` (63 msgs), `alliancescience`, `alliancedevelopment`, `AllianceMobilizationCtrl`, `AllianceWarCtrl`.
- **Rank/arena**: `arena`, `slg3arena/slg3league`, `arsenalleague` (27 msgs), `rank`.
- **Quests**: `mission`, `todo`, `commonsevendays`, `sevensign/fourteensign/twentyonesign`, `kingdomcard`.
- **CheatCtrl/SimulationNetMsg**: 62 msgs de debug presentes no client (indica quais `req_*` são GM/teste).

## 6. Artefatos nesta pasta
| arquivo | o que é |
|---|---|
| `ljparse.py` | parser LuaJIT 2.1 stripped (protos, KGC strings/tabelas, KNUM, bytecode) |
| `ljdis.py` | pseudo-decompilador simbólico (FR2: args em A+2); `python3 ljdis.py <modulo> [linhas]` |
| `raw.py` | dump cru de opcodes de um proto |
| `cfgvm.py`, `dumpcfg.py` | mini-VM linear p/ módulos de config → `cfg/*.json` (1389 tabelas) |
| `handlers.py` → `HANDLERS.tsv` | msgId→módulo→função handler (2455) |
| `msgmap.py` → `MSGMAP.tsv`, `msg_to_modules.json`, `mod_msgcount.tsv` | todo módulo que cita cada `req_/notify_` |
| `census.py` → `CENSUS.md` | censo por domínio |
| `errs.py` → `errcodes.json` | 3045 `err_*` nome→código |
| `dis/` | pseudo-código dos módulos analisados |
Rodar: `MSYS_NO_PATHCONV=1 wsl.exe -d kingshot-re -u re -- sh /mnt/c/Users/prs/work/lua-logic/rr.sh <script.py>` (scripts usam caminhos /mnt/c).

## 7. Limites / o que é inferência
- Pseudo-código sem estrutura de controle: `? cond` indica comparação cujo desvio não é mostrado; `tNN` são temporários. Leituras de lógica (sold-out, "tipo 1 = nível") são **inferência** a partir de constantes/ordem.
- Nome do handler vem do `Register`; chamadas com msg em variável escapam; 51 registros apontam msgs fora do schema 1.14.27.
- Mini-VM de config ignora metatables/defaults (linhas trazem só campos que diferem do template; o template default não foi mesclado).
- Não analisado a fundo: hero/skill/fórmulas de batalha (`scene_battle_logic_*`: `BLLogicCenter`, `BLBuff` — próximo alvo natural), pay/IAP, mail, chat, rank, `LockConditionHelper` (tipos de condição), `IsSoldOut`.
- Budget ~40 min; parado deliberadamente.
