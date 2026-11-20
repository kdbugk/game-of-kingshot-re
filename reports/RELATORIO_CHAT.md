# RELATÓRIO — LANE CHAT-RTM (análise estática offline)

## 1. Cadeia do endpoint (evidência)

**O endpoint NÃO vem de config HTTP do CGSdk nem é hardcoded. Vem do push `notify_chat_init` (id 3401, s2c), enviado pelo gateway.**

| Elo | Evidência |
|---|---|
| Assinatura C# | dump.cs:14787 `ChatProxy.Login(String endpoint, String endpoint_bak, Int64 pid, Int64 uid, String token, Boolean waitConnectingCannelled, Int32 timeOut)` (estático, campo `RTMClient s_client`; também `SetBackupEndpoint`, `OnLogin(pid,uid,authStatus,errorCode)`) |
| Quem chama | Lua `game/module/logic/module/chat/ChatProxyCtrl` (strings: `Login`, `ChatProxy`, `Is_Y25_M6_CSharpCode`, `ClearFuncData`, `InitData`, fila `m_firstFuncList/m_norFuncList/m_btnFuncList/m_hisFuncList` com timer) — a chamada vem de `ChatCtrl` via `SDKLogin` (campos `endpoint_bak`, `token`, `m_token`, `pid`, `m_pid`, `endpoint_2_7_0`, `m_endpoint` aparecem juntos, logo após `OnNotifyInit`) |
| Origem dos campos | `proto/game_proto_s2c.sproto:10613` `notify_chat_init 3401 { endpoint 0 (<sdk 2.7.0), pid 1, token 2, endpoint_2_7_0 8 (>=2.7.0), endpoint_bak 16, kingdom_rid 4, alliance_rid 5, broadcast_local_kin_gid 6, cross_capital_war_rid 7, blocklist 3, expression_map 9, reddot_ts 11, ... }` ; handler `HANDLERS.tsv:261 3401 notify_chat_init → ChatCtrl.OnNotifyInit` |
| O `uid` | do próprio PlayerCtrl (não vem no push) |
| Token refresh | `req_chat_get_token 3405` (c2s sproto:8177) resp `{code, rtmcode, token}` → `ChatCtrl.OnGetTokenRes`; **a resposta NÃO traz endpoint** (só rtmcode+token). Quem dispara: `ChatCtrl.NetGetToken` (strings `m_tokenWaitTime`, `m_isWaiting`, `m_token`, e `ChatProxyCtrl.IsLoginSucc` logo ao lado) |
| Classes C# de config | `com.fpnn.rtm.RTMConfig` (dump:88233) só tem timeouts/`reloginWithIP`/RegressiveStrategy — **nenhum host**. Não achei ChatConfig/IMConfig. |

**Fixture capturada (real)** em `fixture_v4.json`, `notify_chat_init`:
`endpoint = endpoint_2_7_0 = "c02-rtm-intl-frontgate.ilivedata.com:13321"`, `endpoint_bak = "ga-c02-rtm-intl-frontgate.ilivedata.com:13321"`, `pid=80000717`, `token="03D79E93…"` (token real expirado, de outra conta).
→ O mock já reenvia esse `notify_chat_init` no burst. Portanto o cliente **tenta logar no RTM real (LiveData/FPNN, TCP 13321)** com token velho/de outra conta → auth falha → `IsLoginSucc` permanece falso → `ChatCtrl` re-pede `req_chat_get_token` em polling (timer `m_tokenWaitTime`). Nossas respostas (`rtmcode 0/1`) não mudam nada porque: (i) resposta sem endpoint não troca o host; (ii) `mock-…` não é token válido para o RTM real; (iii) `rtmcode:1` é tratado como erro transitório → retry (comportamento observado).

> Limite da análise: dump.cs só tem assinaturas e os .bin Lua são bytecode LuaJIT (sem decompilador disponível aqui). A lógica exata do loop (condição/intervalo/teto de retries) está **inferida** por nomes de strings, não lida de código. Para confirmar: frida em `ChatProxy.Login` / `ChatCtrl.OnGetTokenRes` (RVA Login 0x1c97a80).

## 2. Opções para o mock

### (a) Servidor RTM/FPNN próprio + `notify_chat_init` apontando para ele
- Mudar no `notify_chat_init` do mock: `endpoint`, `endpoint_2_7_0`, `endpoint_bak` = `IP_do_mock:PORTA`, `pid`/`token` próprios (token qualquer — nós validamos). Isso é toda a "config"; sem DNS/HTTP extra.
- Cliente: `RTMClient` → `TCPClient rtmGate` FPNN (dump `com.fpnn.*`). FPNN = TCP, frames com magic `FPNN`, corpo msgpack; pode haver handshake de criptografia (ECDH/AES) opcional — **o dump não documenta o protocolo** (só assinaturas). Seria preciso: capturar tráfego real (pcap do cliente → LiveData; é TLS-less FPNN mas possivelmente cifrado) ou inspecionar `com.fpnn.TCPClient`/`ClientEngine` via frida. Depois implementar: (1) aceitar conexão (+ handshake de chave se o cliente exigir), (2) responder a `auth` (pid, uid, token) com ok, (3) `ping`, (4) responder vazio a `getunread`, `enterroom(s)`, `getgroupchat`, `dataget`, etc. (as chamadas de `ChatProxy`).
- Prós: chat real funcional (inclusive mensagens locais); elimina o polling na raiz.
- Contras: maior esforço e risco (protocolo não documentado, possível cifragem); ~1 dia.

### (b) Fazer o cliente desistir
- Nada encontrado no dump/Lua que desabilite o chat: não há flag óbvia `chat_enable` em GameConfig (não achei; busca limitada, o grep no dump estourou timeout por lentidão do WSL). Em `ChatCtrl` só há `isDontSend`, `GetGlobalConfig`/`SystemConfigRead` de limites de chat, e códigos `err_chat_enter_room_rtm_fail`. `rtmcode` é lido em 3 pontos da ChatCtrl (OnGetTokenRes/envio), mas nada indica "rtmcode X = desistir"; `reloginStopCodes` (HashSet em `RTMClient`) existe no SDK C# — códigos de erro RTM que param auto-relogin — mas é lado do SDK, não controlável via get_token.
- Variante prática: **`notify_chat_init` com `endpoint` apontando para porta que recusa a conexão** (ex.: `127.0.0.1:1`/porta fechada no IP do PC) em vez do host ilivedata real: evita bater no serviço real (e queimar rate-limit/ban com pid/token falsos) mas continua o polling.
- Prós: barato. Contras: sem garantia; precisa de teste empírico (testar `rtmcode` = 0 com token longo, e também outros valores como 3/-1; e `code!=0` com err conhecido). Experimento recomendado de 10 min.

### (c) Aceitar o polling
- Custo no servidor: 1 req pequena a cada `m_tokenWaitTime` (provavelmente dezenas de segundos). Já em `AUTO_SKIP`. Inofensivo para estabilidade; polui log. O chat fica indisponível (UI de chat vazia/"conectando").
- Risco: o cliente continua tentando conectar ao RTM **real** (ilivedata) com `pid`/token do fixture — tráfego externo inútil e potencialmente sinalizável. Mitigar trocando o endpoint (ver acima).

## 3. Recomendação
1. **Já, trivial (5 min):** no `notify_chat_init` do mock, substituir os 3 hosts (`endpoint`, `endpoint_2_7_0`, `endpoint_bak`) por um endpoint local (IP do mock:porta fechada, depois porta aberta de teste) e `token`/`pid` próprios. Medir se o polling muda (observar tempo entre `req_chat_get_token`). Responder `get_token` com `rtmcode:0` + token estável. Isso é a opção (c) segura.
2. **Se o polling incomodar:** subir um listener TCP na porta do endpoint para observar o primeiro frame do cliente (hex dump). Isso dá de graça o formato do handshake FPNN e decide se (a) é viável (se o frame inicial for `FPNN` plano + msgpack, implementar auth/ping mínimo → login RTM ok → `IsLoginSucc`=true → polling cessa). Esse é o caminho (a), em etapa incremental barata antes de investir.
3. Frida em `ChatCtrl.OnGetTokenRes`/`ChatProxy.OnLogin` (errorCode) para ver o erro real do RTM e fechar a dúvida da lógica do loop.

## 4. Bônus — `req_dun163_risk_check` (13823)
- sproto: request `{token: string}`, response `{code, sdk_resp_data: string}` ("易盾风险检测" = NetEase Yidun/Dun163 anti-fraude).
- Cliente: `CGSdk.InitNetSecProtect(productId, serverType, channel, gameKey, extraData, host)`, `NetSecGetToken(timeout, businessId)`/`NetSecGetTokenAsync` (dump:16761–16766) gera o token (`NetEase.AntiCheatResult`); o servidor do jogo valida o token na API NetEase e devolve `sdk_resp_data`, que o cliente repassa para `NetSecSetResponseData(sdkRespData)` (dump:16768; ver `game_module_SDKModule.bin`).
- Servidor-lab **não precisa validar**: basta `{code:0, sdk_resp_data:""}` (ou eco). Risco baixo: se o SDK exigir dado válido em `NetSecSetResponseData`, no pior caso a proteção ignora/loga erro; não bloqueia gameplay (é telemetria de risco). Verificar apenas se algum fluxo faz `NetSecSetResponseData("")` com erro visível.

## Pendências de verificação
- Confirmar a lógica do polling (intervalo, tetos) com frida ou desassembly LuaJIT (`ljd`/`luajit -bl` não disponíveis no WSL).
- Procurar flag de desabilitar chat na config server-side (ex.: `notify_*` de config / `GetGlobalConfig` keys `chat_*` em `cfg/`) — não concluído.
