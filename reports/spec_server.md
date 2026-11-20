# RELATÓRIO — LANE SPEC-SERVER (blueprint de backend a partir do cliente Kingshot 1.14.x)

Análise 100% offline/estática. Fontes: `dumpcs_114.cs` (271 908 linhas, WSL `kingshot-re`), `il2cpp_dump_114/`, `reports/capture_combat.md`, `reports/kind03_codec.md`, `laneQ/protocol_walkthrough.md` e os pcaps próprios (`battle.pcap`, `battle2.pcap`, `cap_combat2.pcap`). Nada foi escrito no repositório. Scripts de apoio nesta pasta: `ex.py`/`blk.py` (extrair classes do dump), `sp.py`/`sp2.py`/`sp3.py`/`chk.py` (decoder de wire, ver §1).

---

## 0. Limites que mudam o que este relatório pode afirmar (leia primeiro)

1. **O dump só tem assinaturas, não corpos de método.** `dumpcs_114.cs` lista campos/métodos/RVAs; não há IL nem pseudocódigo. Logo "validação client-side" só pode ser **inferida** de nomes (`Check*System`, `CanXxx`, campos `Cost`/`Max`) e de configs — nunca lida como `if (qty > cap)`. Onde digo "achado" para validação local, é por assinatura/config, não por corpo.
2. **A lógica de meta-jogo (loja interna, inventário, conquista/mapa, conta de jogo, mail, aliança) NÃO está no C# do dump.** O `Assembly-CSharp` (3 998 classes) é: engine/UI, SDK Century Games (`centurygame.*`), chat RTM (`com.fpnn.*`), **o minigame Tower Defense em Entitas (`CenturyGame.TowerDefense.*`, 659 classes)** e bindings tolua. O resto roda em **Lua** (`LuaModule`, `luapackage` ≈ 100 MB cifrado, não temos). O termo "conquest" **não aparece nenhuma vez** no dump (0 ocorrências). Os equivalentes visíveis: `FightPassNewData.PassID` (fase/"pass" do TD), `WarZoneMapController`, `TriangleWarMapController`, `TerritoryBuilding`/`TerritoryStronghold`, `WorldMapController`, `March*Mover` (só rendering).
3. Resolução de tipos do dump é parcial: `T#nnnn` = tipo não resolvido; `EasyTouchTrigger/ETTParameter` aparece no lugar de `int` (colisão de nome do voter) — leia como `int`.
4. Decodificação do protocolo (§1) é **minha, nova, validada estruturalmente** (1 771/1 771 frames fecham exatamente), mas **sem schema** (.sproto está no luapackage cifrado): sei a estrutura, não os nomes de campos.

Consequência honesta: o blueprint abaixo é sólido para **transporte, sessão, pagamento, battle-TD e arquitetura**; para loja/inventário/conquista é **inferência por padrão de mercado + o catálogo de IDs de mensagem observados**, a confirmar com Lua ou captura dirigida.

---

## 1. DESCOBERTA PRINCIPAL: o wire é **sproto (skynet) com 0-pack** — não "opcode+kind"

Evidência no código: `LuaModule` (tolua) abre, nesta ordem, `OpenLuaSocket` (`LuaOpen_Socket_Core`, `LuaOpen_Mime_Core`), `OpenCJson`, **`OpenSproto`**, **`OpenCrypt`**, `OpenBit32`, `OpenSqlite3`, **`OpenCmsgpack`**, `OpenMathS`. Ou seja: o gateway TCP :30101 é cliente luasocket + **sproto** (serialização do ecossistema skynet) + `crypt` (HMAC/DH/XOR do skynet) + `cmsgpack`. `HttpNetWork`/BestHTTP é só HTTP auxiliar (assets, Post/PostJson), `ChatProxy` é outro canal (RTM/FPNN).

Validação: apliquei o **desempacotador "0-pack" do sproto** (bitmap de 8 bits por grupo de 8 bytes; `0xFF` = N grupos literais) a todos os frames `uint16_BE(len)+corpo`:

| pcap | frames | desempacota e consome exatamente | header sproto parseia |
|---|---|---|---|
| battle.pcap (1.9.5) | 505 | 505 | 505 |
| battle2.pcap (1.9.5) | 608 | 608 | 608 |
| cap_combat2.pcap (1.14.27) | 658 | 658 | 658 |

O que isso **explica** (e corrige) nos relatórios anteriores:
- O "opcode" `byte0` (`15`,`1d`,`55`,`5d`,`7d`…) **não é opcode**: é o **byte de bitmap do primeiro grupo de 8 bytes** do sproto empacotado. Muda quando bytes do primeiro grupo mudam de zero/não-zero ⇒ explica o "bit 0x20" de `15→35`, `1d→3d`, `55→75`, `5d→7d` (é o byte do *session id* ficar não-zero/maior, não um modo).
- O "byte1 = 01/02/03 (kind)" é o **número de campos (`fc`) do 1º struct sproto** (o header do pacote): `01` = só 1 campo (push do servidor, sem sessão), `02` = 2 campos (req/resp com `session`), `03` = 3 campos (header estendido, ex. `ud`/`extra`).
- Os "bytes de controle intercalados" (`ff 00`, `1f`, `fc`, `f1 09`, `3f`) **são os bitmaps do 0-pack**, não escape/XOR. O "msgpack" visto (`a8 "atk_uids"`) é `cmsgpack` embutido em campo `string` de sproto (Lua `cmsgpack` está aberta) — hipótese consistente, não testada.
- Contadores "pares, passo 2" = sproto codifica inteiros inline como `(v+1)*2`; ou seja, **session = 1,2,3… sequencial**.
- Handshake desempacotado: `02 00 | 04 00 | 04 00 | …` ⇒ header `{type=1, session=1}`; strings viram `u32 len + bytes` (token 48 chars, user_id `384601255`, `1.9.5`, device, `android`, `BR`, `pt`, 2 ids hex de 32). (Observação: o token aparece com 2 chars à frente, `1W…` — a confirmar.)
- ATENÇÃO: o XOR de chave de 4 B (`b9 24 5f bd`) do canal "kind 03" (`kind03_codec.md`) **continua sendo uma camada real** sobre corpos grandes (provável `crypt`/NHP — `GameConfig.Enable_Encrypt_NHP` + `libNetHTProtect`/`NetEase.NetSecProtect`); só que a moldura externa é sproto.

### 1.1 Header sproto (estrutura inferida, schema-less)
```
struct Header { type?: integer (tag0), session: integer (tag1), ud/extra (tag2, kind 03) }
C→S req :  fc=2  tag0=<msgId>  tag1=<session>
S→C resp:  tag0 omitido (slot ímpar=skip)  tag1=<session eco>      -> "pareado por id"
S→C push:  fc=1  tag0=<eventId>, sem session
```
Corpo = 2º struct sproto (por msg).

### 1.2 Catálogo de IDs de mensagem observados (tag0), cap_combat2.pcap + battle2.pcap
Numeração por **módulo×100 + índice** (padrão de projeto de jogo chinês: 28xx, 85xx, 11xx…). Tag de 2 B do relatório anterior (`6c 42`, `e0 9f`, `f2 15`, `e8 15`, `4e 0d`…) = **o próprio msgId inline codificado** (`(id+1)*2`): `6c42→8501`, `e815→2803`, `f015/f215→2807/2808`, `e09f→20463`, `0c08→1029`, `7417→3001`.

| msgId (C→S) | n (combate) | len B | Observação | leitura provável |
|---|---|---|---|---|
| 1 | 1 (handshake 1.9.5) | 204 | token+uid+versão+device+país+lang+2 ids | **login/auth no gateway** |
| 21 / 22 | 1 / 105 | 4–5 | `22` a cada ~3–4 s; resposta c/ relógio do servidor | **heartbeat** (21=1º, 22=seguintes), resposta traz `server_time` |
| 8501 | 40 | 18–19 | resposta push 8552 (+51 no id) | comando leve periódico (sync/poll) |
| 2803 | 41 | 16 | | comando leve c/ timestamp (poll de estado) |
| 20463 | 22 | 51 | cada um → push 20466 (25 B) e 20474 (7 B) 0,2–0,6 s depois; contador `+1` por ação | **ação de combate repetida** (seq de ação) |
| 20461/20462 | 1/3 | 6–10 | mesma família 204xx | início/fim/arma combate |
| 2807 | 21 (fc=3) | 16 | resposta 27 B só com `server_time` | consulta de entidade |
| 2808/2809/2802/2804 | 2/6/1/1 | 9–44 | `2808` = pares `22 xx yy` (lista de ids) | família 28xx = batalha/marcha (módulo) |
| **3001** | 7 (fc=3) | **2462** | snapshot periódico C→S; resposta 16 B = ACK | **cliente envia estado de combate ao servidor** (31 entidades × 5 doubles ∈[0,100]) |
| 1029 | 1 (fc=3) | 30 | resp 264 B c/ perfil (nome, idioma, uid, timestamps) | **get_profile(uid)** |
| 1702/1703 | 2/2 | 57/9 | | módulo 17xx |
| 4405, 2005 | 1/1 | 17/67 | 2005 = tamanho idêntico ao "trio de entrada de cena" | cena/entrada de mundo |
| 1501–1504, 1811, 1103, 1023, 5601, 3801/2/7, 3201, 2251, 10161… | (só 1.9.5) | 5–296 | | módulos 11/15/18/23/32/38/56 |

Pushes S→C (tag0 sem session): `1102`, `1302`, `1902` (estado de mundo; 16–373 B), `1011` (82 B, 1×/sessão burst), `8552`, `8652`, `20466`, `20474`, `2752`, `5176` (48 B), `3351`, `4203`, `9676`, `10852`, … Rajada inicial pós-login ≈ 50 frames em 35 ms (snapshot do jogador: 1º push 2 721 B + dezenas de pushes de módulo).

---

## 2. DOMÍNIO: CONTA / SESSÃO

### 2.1 Classes-chave (assembly `Unity.dd.sdk.scripts.account`, ns `centurygame`)
- `CGAccount` (singleton `get_Instance()`): `Login()`, `Login(CGAccountType)`, `LoginWithPGSPrior()`, `CreateNewExpressAccount()`, `Logout()`, `IsUserLoggedIn()`, `CanSilentSignIn()`, `RegisterWithEmail(email,password)`, `LoginWithEmail`, `LoginWithMobile(mobile,csc,password)`, `BindAccount(type)`, `BindWithEmail`, `BindOrLogin(type)`, `BindOrLoginWithAgainConfirmLogin`, `AgainConfirmLogin(bool)`, `ResetPassword(email)`, `SendSmsWithMobile(mobile,csc,type)`, `RequestLoginEmailVerificationCode(email,codeLength)`, `LoginWithEmailCode(email,code)`, `GetBindInfo()`, `GetAccountInfo()`, `ShowClearLoginStatusAllDevices()`, `VerifyLoginAccountSocialBindingPGS()`, `AuthorizeVipMallUser(AuthorizeVipMallUserBean)`, `ShowUserCenter()`.
- `CGAccount.IDelegate` (callbacks): `OnLoginSuccess(CGSession)`, `OnLoginError(CGError)`, `OnBindAccountSuccess(CGSession)`, `OnBindOrLoginSuccess(bool isBind, CGSession)`, `OnBindOrLoginWithAgainConfirm(string fpid)`, `OnGetBindInfoSuccess(string uid, List<CGSocialInfo>, string email)`, `OnSwitchPGSAccountStatus(CGSwitchAccountStatus, CGAccountType, bool needLogOut, string currentFpid, string toFpid)`, `OnLogout()`.
- **`CGSession`**: `AccountType`, `Fpid`, `SessionKey`, `Email`, `Mobile`, `SnsPlatform`, `SnsId`, `SnsAccessToken`, `SnsName`, **`ExpireOn` (long)**; `FromMessage(string)`.
- `CGAccountType` (26 valores): Express, Email, Facebook, VK, Wechat, GooglePlus, GameCenter, Mobile, Naver, Google, Cache, Apple, Twitter, Platform, Huawei, Cgid, **GooglePgs**, QQ, TapTap, CnMedia, Douyin, Alipay, EmailSocial, CGSID.
- `CGAccountInfo{Fpid,Email,Mobile,SocialDetail[],DeleteInfo,Compliance}`; `DeleteInfo{Code,CodeGeneral,DelayTime,SurplusTime,ApplicationTime,DeleteTime}` (exclusão de conta com período de espera); `Compliance{AgePhase,ConsentStatus,AdultTag,AAStatus}`; `CGSwitchAccountStatus{NEED_SHOW_LOGIN_UI,USER_CHOOSE_SWITCH_PGS,SHOULD_LOGIN_CACHE,PCG_CONFLICT_SHOULD_LOGIN_CACHE}`.
- `core`: `CGSdk` (`Install()`, `GameId`, `GameKey`, `LogUserLogin/LogNewUser/LogUserLogout(uid)`, `LogUserInfoUpdate(serverId,userId,userName,userLevel,userVipLevel,isPaidUser)`, `SetGameUserData(GameUserData{zoneName,balance,partyName,exchangeRate,currencyName})`, `LogPayment(productId,throughCargo,purchaseData)`), helper HTTP interno `PostRequest/PostCgidRequest/GetRequest` com `DictionarySort` (assinatura de parâmetros ordenados — padrão "sign").
- Assembly-CSharp: `GameConfig` (`Kingdom`, `Language`, `CountryCode`, `AppStoreCountryCode`, `DeviceID`, `DeviceModel`, `SystemVersion`, `UserId`, `Enable_Encrypt_NHP`), `LoginData(long pid,long uid,bool authStatus,int errorCode)` e `ChatProxy.Login(endpoint, endpoint_bak, long pid, long uid, string token, bool waitConnectingCannelled, int timeOut)` (login do chat RTM por token).
- Anti-cheat/integridade: `NetEase.NetSecProtect`, `NetSecHTPCallback{onReceive,onResult(AntiCheatResult)}`, `NetSecGetCollectDataHelper.GetData(timeout, businessId, onCompleted)`/`GetDataByMsg` — o cliente coleta dados do dispositivo e os anexa ao tráfego (NetEase HTProtect/YiDun) → **servidor valida blob anti-cheat**.

### 2.2 Local vs servidor
| Item | Cliente | Servidor |
|---|---|---|
| Credenciais e-mail/telefone/social | só coleta/UI; `codeLength` do código de verificação é pedido pelo cliente | valida, emite `CGSession` (`Fpid`+`SessionKey`+`ExpireOn`) — **backend de identidade é o da Century/FunPlus ("CGID")**, separado do gateway |
| `IsUserLoggedIn`/`CanSilentSignIn` | decide com cache local (`SessionKey`,`ExpireOn`) | revalida `SessionKey` no handshake do gateway |
| Bind/troca de conta (PGS conflito) | mostra diálogos (`CGSwitchAccountStatus`) | decide conflito `fpid`↔conta de jogo; retorna `toFpid` |
| Idade/consentimento (`Compliance`) | exibe | fonte da verdade |
| Exclusão de conta | exibe `SurplusTime` | mantém janela de espera (`DelayTime`) e estado |
| Dispositivo (`DeviceID`,`DeviceModel`,país,lang) | envia no handshake `msgId=1` | registra; anti-multi-conta |

### 2.3 Cruzamento com o protocolo
`msgId=1` (204 B) = `{token (48 chars), user_id 384601255 (9 díg.), version "1.9.5", device "motorola moto g(8)", os "android", país "BR", lang "pt", 2×hex32 (sdk_id + 1 id)}`; resposta 63 B ecoa versão e `827` (versão de protocolo/ID) mais tempos do servidor. O token e uid **eram idênticos entre 3 conexões** ⇒ **token de sessão de longa duração e sem nonce/timestamp** no handshake: replay trivial → no backend novo: nonce+timestamp+HMAC (o `59/02` com HMAC base64 de 27 B visto em 1.9.5 sugere que o próprio jogo já tem uma etapa challenge/HMAC pós-login — padrão skynet `crypt.hmac64`).

---

## 3. DOMÍNIO: LOJA / PAGAMENTO (SDK) — o mais completo no dump

### 3.1 Classes-chave (assembly `Unity.dd.sdk.scripts.payment`, 42 classes)
- **`CGPayment`** (singleton): `SetDelegate(IDelegate)`, `StartHelper(string[] productIds)`, `SetNonConsumptionProductIds(string[])`, `CanMakePurchases()`, **`Buy(string productId, string throughCargo)`**, **`Buy(string productId, string serverId, string throughCargo)`**, `SetThroughCargoForOngoingPurchases(productId, serverId, throughCargo)`, **`paymentServerApi(string purchaseDataJson)`**, `checkOngoingSubscriptOrders()`, **`TryCompleteUnPayOrder()`** (reentrega de pedido pago não consumido), `GetSupportCurrencyList()`, `RequestProductDetailsWithCurrency(currency)`, **`RequestGetThroughCargoWithProviderOrderId(orderId)`**, `FetchStoreCountryCode()`, `EnableOfferCodeOrderHandling`, `PresentOfferCodeRedemptionUI`, `SetAndroidCnMediaPayOrderParam(CGCnMediaOrderParam)`.
- **`CGPayment.IDelegate`**: `OnInitializeSuccess(List<CGProduct>)`, `OnInitializeError(CGError)`, `OnPurchaseSuccess(productId, throughCargo)`, `OnPurchaseSuccessWithOrderId(productId, orderId)`, `OnCreateOrderIdComplete(productId, orderId, throughCargo)`, `OnPurchaseError(CGError)`, `OnCheckOngoingSubscriptOrders(List<CGSubscriptProduct>)`, `OnGetThroughCargoWithProviderIdSuccess(throughCargo, productId)`, `OnCommonCallBack(string)`.
- `CGProduct{ProductId,Title,Description,PriceCurrencyCode,FormattedPrice,long Price,Icon,currencyLable}` com parsers por loja: `FromGoogleIabMessage`, `FromAdyenPayMessage`, `FromAmazonIapMessage`, `FromAppleIapMessage`, `FromMiniGameMessage`. `CGSubscriptProduct{productId,createTs}`. `CGUnFetchedProduct{ProductId,StatusCode}`. `CGPaymentError{ErrorProductId,ErrorThroughCargo,ErrorNotMatchUid}`.
- Backends Android (todos com a mesma interface `BasePaymentWrapper`): `CGGoogleIabAndroid`, `CGAdyenPayAndroid`, `CGAmazonIapAndroid`, `CGHuaweiIapAndroid`, `CGMycardIabAndroid`, `CGOnestoreIabAndroid`, `CGXsollaPayAndroid`, `CGPaymentCNAndroid`. Web shop externa: `CGWebShop` + `CGExternalContentLinks` (`ConnectionBilling`, `IsBillingProgramAvailableAsync`, `CreateBillingProgramReportingDetailsAsync`→token, `RequestWebShopLink(data)`, `LaunchExternalLink`) = Google "External Offers / alternative billing".
- Telemetria de compra: `CGSdk.LogPayment(productId, throughCargo, purchaseData)`; `GameData.PayEnable` (flag de build/região).
- `CurrencyHelper.GetPriceByCurrencyCode(long price, string currencyCode, out string formatPrice)` — só formatação.

### 3.2 O desenho (fluxo implícito pela API)
`throughCargo` = **payload opaco do jogo que atravessa a loja e volta ao servidor** (padrão "developerPayload"; carrega uid/serverId/sku/pedido interno). Fluxo:
1. cliente → (Lua) pede ao **servidor do jogo** criar pedido → `OnCreateOrderIdComplete(productId, orderId, throughCargo)`;
2. `Buy(productId, serverId, throughCargo)` → fluxo nativo da loja;
3. SDK Java faz `PaymentServerApi(purchaseDataJson)` → **servidor de pagamento da Century (CG Payment) valida o recibo com a loja** e **entrega o item ao servidor do jogo por callback server-to-server**, usando `throughCargo`. O cliente recebe só `OnPurchaseSuccess(Id, throughCargo)`; `ErrorNotMatchUid` indica que o servidor compara o uid do pedido com o uid logado;
4. pedidos pendentes: `TryCompleteUnPayOrder`, `SetThroughCargoForOngoingPurchases`, `RequestGetThroughCargoWithProviderOrderId` (reconcilia por orderId da loja).

### 3.3 Local vs servidor (pagamento)
| Verificação | Cliente | Servidor |
|---|---|---|
| `CanMakePurchases()` (billing disponível) | local (BillingClient) | — |
| Catálogo/preço exibido (`CGProduct.Price`, `FormattedPrice`, moeda por país) | vem **da loja** (Google/Apple), formatação local | preço **lógico** (SKU→itens entregues) é do servidor; cliente nunca decide valor |
| Limite de compra/dia, 1ª compra bônus, VIP lvl, regional (`PayEnable`, `GetSupportCurrencyList`) | **nenhuma validação visível no C#** (pode haver na Lua — UI só esconde/desabilita) | **tudo**: limite por SKU/conta/janela, elegibilidade, pacote one-time |
| Recibo/assinatura | repassa JSON (`purchaseDataJson`) | valida na loja (Google Play Developer API/Apple), idempotência por `orderId` |
| Consumir/acknowledge | `CompleteUnFinishPay`/consumo no SDK Java **após** entrega confirmada | decide quando é "entregue"; retry |
| Assinaturas | `checkOngoingSubscriptOrders` | estado/renovação/expiração (`createTs`) |

---

## 4. DOMÍNIO: FASES / "CONQUEST" (o que existe de fato = Tower Defense "FightPass")

### 4.1 Classes-chave (ns `CenturyGame.TowerDefense`; ECS Entitas — simulação **local**)
- **Estágio/fase**: `FightPassNewData{PassID, Name, Type, ActivityPass, PrepareTime, Time, Scene, PassDataName, DayOrNight, BoxDropRadius, ResCount, CityPass, CollectResType, UnlockUnit, UnlockSkill, MonsterFactor, ResHpFactor}`; `FightPassNewConfig.Get(PassID)` (tabela carregada de arquivo); `WaveData{ID,GroupID,StartTime,Queue,ConditionType,ConditionParam,PassID,BornPoint,RandomBornRadius,CallQueueGetRes}`; `TD_ACTIVITY_PASS_TYPE{NONE,ACTIVITY,SINGLE_TD}`; `TDBattleStage{None,Prepare,Battle,BeClosing}`; `E_BATTLE_RESULT{eSuc,eFail,eExit}`.
- **Economia intra-batalha ("coin")**: `CoinData{PassID, CoinID, Lv, CostType, Cost(short), SelectUnit, UnitLv, UnitRes, UnlockFunction, CanRebuild, ...}`; `CoinConfig.Get(passId,coinId,lv)`; `UnitLevelNewData{ID,Level,HP,Atk,Def,AtkInterval,AtkDistance,Speed,DieDrop,...}`; `OutPutData{UnitID,UnitLv,OutType,ProCount,ProSpeed,OverlayCount,ProMax}` (produção de recurso com **`ProMax` = cap de produção**); `TDGlobalNewData{ID,Value,Param}`.
- **Recompensa (server-driven)**: `ServerRewardBoxInfo.serverBoxInfo : Dictionary<int boxId, Dictionary<int itemId, int count>>`; `RewardBoxCmd` (mesmo tipo); `TDMainPanel/BaseTDGameMainLoop`: `AddServerRewardBoxInfo`, `ReplaceServerRewardBoxInfo`, `AddRewardBoxCmd`, `ReplaceRewardBoxCmd`; `TDBoxRewardController.GetServerBoxReward()`, `ImportOneBoxReward(boxId,itemId,itemCount)`, `OpenBox(boxId):bool`, `DropBox(boxId, Vector3)`; `DieDropRewardBox{orderId,boxId}`; `TDLogicEventHandler.ImportServerBoxReward()/DropBoxReward(boxId,pos)`.
- **Ponte C#→Lua→servidor**: `TDToLuaEventType`: `GameEnd`, `CanEnterTDFight`, **`C2SDropBox`**, **`C2SOpenBox`**, `GetServerBoxReward`, `FlyReward`, `NotifyFightPassType`, `NotifyGameRunState`, `UnlockNewUnit`, `NotifyGameEndShowSeignioryOpenBox`, `StartupFailed`, `ExitTD`, `AcitiyRemainTime`, `ResidentDie`, `QueryLog`. Chegam em Lua via `LuaEventMgr.CallFunc(LuaEventDefine.TOWERDEFENCE_EVENT_CSHARPE_TO_LUA, …)`; Lua faz o envio (os nomes `C2S*` são a convenção skynet de mensagem cliente→servidor).
- `TDBattleDataRecorder` (estado enviável: `m_listDieResident`, `m_dictPickUpResCount`, `m_mainBuildingLv`, `m_setUnlockUnit`, `RecordActivityRemainTime`); `TDBattleLogService.CacheBattleLog(List<string>)` (log de batalha textual **guardável/consultável** — `QueryBattleLog`: candidato a prova de verificação).
- Sistemas de **validação local** (nomes): `CheckGameEndSystem` → `BattleEnd(E_BATTLE_RESULT)`; `CheckWaveConditionSystem/CheckWaveStartSystem/CheckWaveDoneSystem`; `CheckCoinLevelUpSystem` (usa `CoinData.Cost/CostType/Lv`, `UnLockOtherCoinShow`); `CheckCoinObjectInPutCdSystem` (cooldown de input); `CheckUnitLvUpSystem`; `CheckSkillCanDoSystem`/`CheckSkillObjCanDoSystem` (energia/CD de skill: `SkillEnergyInfo`, `ViewSkillEnergySystem`); `CheckUnitCreateBlockOtherSystem`, `CheckUnitAtInvalidCellSystem` (posição); `CheckProjectileCloseTargetSystem`.
- `LaunchTDBattleScene` (`WaitData`, `FailStartup`, `m_startupStageTimeoutSeconds`) — espera dados do Lua/servidor antes de iniciar; `isCanEnterTDFight` (flag vinda do servidor/Lua).
- "Estrelas / tentativas": **não existem no C#** (nem campos `Star`, `Attempt`, `Stamina`, `Energy` de conta). Só aparecem como `E_BATTLE_RESULT` (3 estados). Qualquer nota de estrela/limite de tentativas é da Lua/servidor.

### 4.2 Local vs servidor
| Aspecto | Cliente | Servidor |
|---|---|---|
| Simulação da batalha TD (waves, HP, dano, fórmulas) | **100% local, determinística-ish (ECS)** com tabelas `*Config` embutidas | **não simula** (só vê resultado/snapshots) → **trust-the-client por padrão** |
| Condição de fim (`CheckGameEnd`) | local → `GameEnd` → Lua | aceita/recusa recompensa |
| Custo de coin/level-up de unidade em batalha | local (`CoinData.Cost`) | irrelevante p/ economia persistente (moeda de round) |
| **Quais caixas/itens caem** | cliente só **importa** o que o servidor mandou (`ImportOneBoxReward`) e **pede** `C2SDropBox/C2SOpenBox` | **servidor decide conteúdo** (`serverBoxInfo[boxId][itemId]=n`), estado "caixa aberta?", anti-dup |
| Entrada na fase (`CanEnterTDFight`, `PassType`, tempo restante da atividade) | recebe | **servidor autoriza** (desbloqueio, atividade ativa, tentativas) |
| Verificação de resultado | snapshots 3001 (2 462 B, 31 entidades×5 percentuais) + ações 20463 com contador | recomenda-se heurística/plausibilidade; hoje parece apenas receber |

---

## 5. DOMÍNIO: INVENTÁRIO / ITENS / MOEDAS

**Não há classes de inventário/itens de conta no C# do dump.** O que existe:
- `ItemData`/`ClipData`/`NodeData` = animação (não inventário); `PackItem`/`UnpackItem` = msgpack do FPNN; `ItemInfo`/`EffectItemInfo` = UI hierarchy; `CurrencyHelper` = formatação de preço; `ResourceType` = tipo de asset.
- Recursos de round (TD): `UnitCreateSourceType`, `AddRes(resType,cnt)`, `GetResCnt`, `DieDropRes.dictDropTypCounts`, `TDBattleDataRecorder.m_dictPickUpResCount` — **só dentro da batalha**.
- Moeda real: `CGSdk.SetGameUserData(GameUserData{balance, currencyName, exchangeRate, zoneName, partyName})` — o jogo **informa o saldo ao SDK** (para fins de tela de pagamento/telemetria), o que prova que **saldo vive no servidor/Lua** e o SDK só o recebe.
- Sinais no protocolo: módulos de mensagem 1x/2x/3x/5x… (ex.: `1501–1504` com 28–296 B, `1811`, `5601`) e o push de 2 721 B pós-login (estado completo do jogador) — **o inventário viaja nos snapshots pós-login e em pushes de módulo**, não via HTTP. Decodificar exige o `.sproto`.

Conclusão: **para inventário/cap de compra o cliente C# não prova nada**; assuma servidor-autoritativo (padrão) e confirme extraindo `luapackage` (cifrado, ver `block0_*`/`UPDATE_NOTES_v1.14.md`).

### Tabela implícita de responsabilidade (inventário/compra interna) — **inferência, nível de confiança médio/baixo**
| Regra | Cliente | Servidor |
|---|---|---|
| Quantidade máxima (cap de estoque/compra/produção) | exibe, desabilita botão | **valida e rejeita** (cliente adulterado ignora) |
| Cooldown/regeneração (energia, produção `ProMax`/`ProSpeed`) | exibe timers (lê `server_time` das respostas hb/2807) | calcula pelo relógio do servidor |
| Débito de moeda | otimista na UI | transação atômica |
| Uso de item / abrir caixa | `C2SOpenBox` | resolve, remove, credita |

---

## 6. CANAIS E TRANSPORTES (visão completa do cliente)

| Canal | Cliente | Protocolo | Uso |
|---|---|---|---|
| **Gateway de jogo** `:30101` TCP | Lua (luasocket) | `uint16_BE len` + **sproto 0-pack**; header `{type,session,ud}`; corpos `cmsgpack`/binário + XOR (NHP) | todo o jogo (login msg 1, heartbeat 21/22, ações, snapshots, pushes) |
| **Chat/RTM** | C# `ChatProxy` → `com.fpnn.rtm.RTMClient` (FPNN, `msgpack`) endpoint `*-rtm-intl-frontgate.ilivedata.com` | FPNN/msgpack, autenticação `pid/uid/token` | chat P2P/sala/grupo, `GetHistory`, `Translate`, `EnterRoom(s)`, push; **serviço terceirizado (iLiveData)** |
| **HTTP** | `HttpNetWork`, `HttpRequestWork`, BestHTTP, `CGSdk` PostRequest | REST + assinatura | assets/hotfix (`CheckAppVersion`, `CheckHotFix`, `VersionManifestChecker`, `DownloadPatchTask`), SDK de conta/pagamento/analytics |
| **Loja** | Google Play Billing via `CGGoogleIabAndroid` | AIDL/Java | compra; recibo vai ao **servidor de pagamento da Century**, não ao gateway de jogo |
| **Anti-cheat** | NetEase HTProtect (`libNetHTProtect.so`, `libnesec.so`) | binário | blob de dispositivo/ações |

---

## 7. CONCLUSÃO ARQUITETURAL — o backend que o desenho implica

### 7.1 Serviços lógicos
1. **Identity (CGID)** — contas, vínculo social, e-mail/SMS, exclusão com janela, compliance de idade. Emite `Fpid`+`SessionKey`+`ExpireOn`. (Pode ser terceiro; no seu jogo: JWT/refresh + tabela `identities`.)
2. **Gateway (TCP persistente)** — auth por `{token, uid, versão, device, país, lang, ids}`; heartbeat (21/22) que devolve `server_time`; roteamento `type→handler`; **pushes** sem session; resposta = mesmo `session`. Versão do cliente/protocolo checada no login.
3. **Game logic (autoritativo)** — contas de jogo/reinos (`Kingdom`), inventário, moedas, mail, aliança, mundo/marchas, relatórios de batalha (`atk_uid`,`def_uid`,`battle_type`,`result`…, já vistos em 1d/01), perfil (`1029`).
4. **Battle TD** — modelo **client-simulated, server-recorded**: servidor entrega `PassID`+seed/`ServerRewardBoxInfo`, cliente roda, reporta resultado + snapshots (3001) + ações (20463). Decidir se você vai: (a) confiar (barato, vulnerável) ou (b) re-simular no servidor (tabelas `FightPassNewData/WaveData/CoinData/UnitLevelNewData` são dados estáticos → portáveis p/ headless).
5. **Payment** — criar pedido (gera `orderId` + `throughCargo`), receber recibo, validar com Google/Apple, idempotência, entregar, reconciliar (`RequestGetThroughCargoWithProviderOrderId`, `TryCompleteUnPayOrder`), assinaturas.
6. **Chat** — pode ser serviço separado (hoje RTM de terceiros).
7. **Asset/versão (HTTP)** — manifestos, hotfix Lua, patches.

### 7.2 Endpoints lógicos mínimos (nome sugerido ← evidência)
| Endpoint | Direção | Evidência |
|---|---|---|
| `auth.login(token,uid,version,device,os,country,lang,sdkId,…)→{serverTime,protoVer}` | C→S msg 1 | pcap |
| `sys.ping(seq)→{serverTime}` | msg 21/22 | pcap |
| `player.get_profile(uid)` | msg 1029 | pcap |
| `player.state` (push inicial grande) | S→C 1011/1102/1302/1902 + 2 721 B | pcap |
| `battle.report_snapshot(entities[31×5])→ack` | msg 3001 | pcap |
| `battle.action(seq,…)→ack` + push de confirmação | msg 20461–20463 → 20466/20474 | pcap |
| `td.enter(passId)`, `td.end(result)`, `td.open_box(boxId)`, `td.drop_box(boxId)`, `td.get_server_box_reward()` | `C2SOpenBox`, `C2SDropBox`, `GetServerBoxReward`, `GameEnd`, `CanEnterTDFight` | dump |
| `shop.create_order(sku)→{orderId, throughCargo}`; `shop.verify(purchaseJson)`; `shop.reconcile(orderId)` | `OnCreateOrderIdComplete`, `paymentServerApi`, `RequestGetThroughCargoWithProviderOrderId` | dump |
| `chat.*` | `ChatProxy.*` | dump |

### 7.3 Validações server-side que o desenho EXIGE (porque o cliente não as pode impor)
1. **Cap de compra/quantidade**: nunca confiar no cliente; checar em transação (`SELECT … FOR UPDATE`/contador atômico) por (conta,SKU,janela). O cliente só vê `CGProduct.Price` da loja — **o servidor precisa do mapa SKU→itens/limites**.
2. **Compra real**: validar recibo na loja + **idempotência** por `orderId`/`purchaseToken`; comparar `uid` do pedido com o logado (`ErrorNotMatchUid`); consumir só após entrega; fila de reentrega.
3. **Recompensa de fase**: decidir conteúdo de caixa no servidor; marcar `boxId` como aberta (1×); rejeitar `C2SOpenBox` duplicado; limitar `OpenBox` por tentativa autorizada em `td.enter`.
4. **Resultado de batalha**: (a) token de tentativa (criado em `td.enter`, consumido em `td.end`); (b) limite de duração (`FightPassNewData.Time` + `PrepareTime`), (c) coerência de snapshot (doubles ∈[0,100], 31 entidades, ids pares conhecidos), (d) taxa de ações (contador 20463 +1/ação, ~3,5 s entre ações no capturado) — se não for re-simular, ao menos rate-limit.
5. **Relógio**: tempo é do servidor (todo heartbeat devolve `server_time`; cooldowns/regeneração calculados daí).
6. **Sessão**: `session` sproto estritamente crescente por conexão (rejeitar reuso → anti-replay básico); handshake sem nonce no original é fraqueza que você deve corrigir.
7. **Versão/hotfix**: `CheckAppVersion`/`CheckHotFix` indicam gate de versão no servidor (bloqueia clientes antigos).
8. **Anti-cheat**: validar blob `NetSecGetCollectDataHelper` se for usar NetEase; senão, no mínimo, device-binding.

### 7.4 O que precisa ser **transacional**
- débito de moeda + crédito de item (compra interna);
- entrega de compra paga + marcação de pedido `delivered` + ack à loja (outbox/idempotency key);
- abrir caixa: remover da `serverBoxInfo` + creditar itens + registrar;
- fim de batalha: consumir tentativa + creditar recompensa + atualizar progresso (`PassID` desbloqueado/estrelas).
Tudo o mais (estado de mundo, snapshots, heartbeat) é eventual/derivado.

---

## 8. Próximos passos recomendados (para fechar as lacunas)
1. **Extrair o `.sproto` / Lua** (`luapackage`, cifrado — `UPDATE_NOTES_v1.14.md` §Bloco 0) → traria nomes de campos, regras de cap/cooldown e todos os msgIds. Prioridade máxima: é o que falta para um blueprint "de verdade" de loja/inventário.
2. Sem Lua: **captura dirigida** (comprar item interno, abrir caixa, entrar/sair de fase) e correlacionar msgId novo por ação — o decoder deste relatório (`sp3.py`) já tabula `msgId`, tamanho e pares req/resp.
3. Testar a hipótese "cmsgpack dentro de string sproto" extraindo os campos `string` do body (já temos o parser de struct em `sp2.py`).
4. Verificar o prefixo `1W` do token e o `59/02` (provável challenge/HMAC skynet).
5. Confirmar `type` vs `session` (tag0/tag1) com o `.sproto` real.

## 9. Resumo de confiança
| Afirmação | Confiança |
|---|---|
| Wire = sproto 0-pack, `fc` do header = "kind" | **Alta** (1 771/1 771 frames fecham; explica "bit 0x20" e "controles") |
| msgId = tag0; tag de 2 B anterior = msgId inline | **Alta** (8501/2803/20463/3001/2807/1029 batem com tags já tabelados) |
| Significado de cada msgId | Baixa/média (inferido de tamanho/tempo/contexto) |
| Pagamento: servidor-a-servidor via `throughCargo` | Média-alta (API do SDK) |
| TD client-simulated | Alta (ECS completo no cliente, `CheckGameEnd`, `BattleEnd`) |
| Loja/inventário/conquista: validações locais | **Não observável** (Lua) |
