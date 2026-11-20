# BLUEPRINT DE CONSTRUÇÃO — backend para um jogo "tipo Kingshot" (LANE SPEC-BLUEPRINT)

Análise 100% offline, dados próprios (schemas `.sproto` extraídos do `luapackage`, transcript `gw_transcript115.pkl` com 312 frames, relatórios `spec_server.md` v1 / `capture_combat.md` / `kind03_codec.md`). Nada foi escrito no repositório. Entregáveis nesta pasta:

| Arquivo | O que é |
|---|---|
| `RELATORIO.md` | este blueprint |
| `ref_server.py` | servidor de referência (asyncio, stdlib, 253 linhas) — **validado contra o transcript** (§6) |
| `tabela_grupos.md` | 50 grupos × mensagens reais (id, direção, campos req/resp, o que validar) — gerada por `gen_groups.py` direto dos schemas |
| `indice_grupos.md` | índice compacto dos 50 grupos (§3) |
| `rt_test.py`, `run_output.txt`, `rt_output.txt` | prova: round-trip enc/dec de 312 corpos e saída do self-test |
| `t1.py`/`t1.out` | dump decodificado campo-a-campo dos 312 frames (com nomes de mensagem/campo) |

---

## 0. Correções ao v1 (o schema real mudou várias conclusões — leia primeiro)

O v1 inferia por tamanho/tempo. Com os schemas reais:

| v1 dizia | Real (schema + transcript) |
|---|---|
| header sproto `{type,session,ud}` "inferido" | **Confirmado**: `.package{type 0, session 1, ud 2{crypt_method 0, crypt_length 1}}` (tags 0/1/2) |
| msg 1 = "login/auth" | `loginauth` — 22 campos no pedido (`sdkToken, account, serverid, version, uid, is_create, group, device, device_os, ip, country_code, distinct_id, lan, device_id, inner_permission_account/token, …`) |
| 20463 = "ação de combate repetida" | **`req_climbtower_challenge`** (Torre/PvE em fases; 20466=`notify_climbtower_tower_update`, 20474=`notify_climbtower_currency_update`) — a "repetição" é o jogador desafiando fases, não um tick de combate |
| 8501 = "comando leve/sync" | `req_trigger_opinion{type,sid,content_id,choice_id,is_anonymity}` → push `notify_opinion_update`(8552): **cartas/opiniões dos sobreviventes** (satisfação) |
| 2803 = "poll de estado" | `req_survivor_update_cure_end_time` (cliente informa fim de cura) |
| 2807/2808 = "consulta de entidade" | `req_survivor_work_start` / `req_survivor_work_pause` |
| 3001 = "cliente envia estado de combate (31×5 doubles)" | **`req_save_client_data{data:client_data{law_point, survivor[]:{sid,res601,res602,res603,res604,res607}}}`** — atributos de sobreviventes **calculados no cliente** (comentário do schema: "在客户端计算的属性"). Os 31×5 doubles são recursos de sobrevivente, não combate |
| 1029 = "get_profile" | `req_players_base_info_with_permission{permission, uids[]}` |
| 21 = 1º heartbeat / 22 = demais | **21 = `req_loaddata`** (cliente pede "carregar dados" → dispara a rajada de `notify_*_init`); **22 = `req_heartbeat`** (resp `{time}`) |
| cifra = "XOR 4 B (NHP)" com chave de origem desconhecida | `loginauth.response` traz **`secret_key`(binary,tag 17) + `crypt_method`(tag 18: nil=sem cifra, 1=XOR, 2=RC4)**. Na captura: `secret_key = ec ba bc b9`, `crypt_method=1`. **A chave viaja em claro na resposta de login** (TCP :30101 sem TLS) → é ofuscação, não confidencialidade |
| "tokens de 2 B em claro" no corpo (kind03) | Hipótese (não testada): são bytes de controle do 0-pack (`ff 00` = run de grupo cheio) — consistente com `ff 00` ser o marcador de run do sproto-pack |
| mensagens com ids "módulo×100" | ids são **por direção**: `c2s` e `s2c` têm espaços separados e **colidem** (ex. 1103 = `req_use_item` em c2s e `notify_backpack_auto_use` em s2c; 1301/2005…). Dispatcher = tabela por direção |

Novos achados de segurança do schema (afetam o clone): (a) **287 mensagens `req_cheat_*` (ids 1201–14xxx) no schema de produção** (add/reduce item, `req_cheat_change_sys_time`, `req_cheat_recharge`, set hero level…); (b) `loginauth` aceita `group 0=debug` e `inner_permission_account/token`; (c) não existe `req_verify_receipt` no gateway — compra é por SDK→servidor de pagamento (server-to-server); mas há `req_recharge_by_voucher`/`by_token` (resgate); (d) `req_battle_adventure_battle_result_error` mostra que o original **já recompara cliente×servidor** (`client_enddata` vs `server_enddata`, `err_type` 1=HP difere, 2=resultado difere) — há simulação no servidor para a aventura PVE.

Limites honestos: (1) o transcript é um login+idle (61 pedidos/251 respostas+pushes), então **só login/heartbeat/loaddata/snapshot/perfil foram observados em fluxo real**; os outros 48 grupos têm **schema real mas comportamento inferido** (padrão do gênero). (2) A regra de cifra das respostas (ver §2.3) é inferida de 4 pares. (3) Não vimos o "blob anti-abuse anexado" no nível sproto: o que existe no schema é `req_dun163_risk_check{token}` (Yidun/NetEase) e `req_report_userkey` — o blob de HTProtect anexado ao tráfego, se existir, não é visível aqui (o 0-pack não mostra campo extra). (4) Pagamento: sem captura de compra; vale o v1 §3.

---

## 1. Arquitetura de referência

```
 cliente ──TCP──►  GATEWAY (L4 LB, TLS na frente)         ┌───────────────────────────┐
  Lua+sproto        │ framing u16BE | unpack 0-pack      │  SERVIÇOS DE JOGO         │
                    │ header{type,session,ud}            │  (stateless, por módulo)  │
                    │ decrypt(ud) → dispatcher por       │  player/economy/mail/     │
                    │ msgId(direção c2s) → handler       ├─► alliance/world/battle/  │
                    │ pareamento session, rate-limit     │  rank/shop/quest…         │
                    │ push bus (notify_*)  ◄─────────────┤                           │
                    └──────┬──────────────────────────────┴────────────┬──────────────┘
                           │ sessão (Redis: uid, key, last_session)    │ eventos
                    ┌──────▼─────┐  ┌───────────┐  ┌─────────────┐  ┌──▼──────────────┐
                    │ IdP (token)│  │ Pagamento │  │ DB (txn)    │  │ Jobs: ranking,  │
                    │ sdkToken   │  │ recibo+   │  │ contas,     │  │ filas/timers,   │
                    └────────────┘  │ idempot.  │  │ inventário  │  │ guerra, mail    │
                                    └───────────┘  └─────────────┘  └─────────────────┘
```

### 1.1 Moldura e protocolo
- TCP persistente; frame = `u16 BE len` + `0-pack( header ++ body )`. **Header = struct sproto `package{type,session,ud}`**, **body = struct sproto do `request`/`response`/`notify_*`** concatenado logo após o header (o decoder devolve o offset do fim do header).
- Três formas de frame (observado nos 312):
  - **Pedido C→S**: `{type=msgId, session=N}` (+`ud` se cifrado).
  - **Resposta S→C**: `{session=N}` **sem `type`** (tag 0 pulada) — o cliente casa pelo `session`; o tipo da resposta é o do pedido pendente.
  - **Push S→C**: `{type=notifyId}` **sem `session`**; corpo = `notify_*` (campo `request` no schema s2c).
- **Mensagem sem bloco `response` no schema = sem resposta** (o servidor não deve responder; o `ref_server` segue isso).
- Dispatcher: `msgId → nome → (schema request, schema response)`, **tabela por direção** (c2s ≠ s2c).

### 1.2 Modelo de sessão
- `session` **sequencial, estritamente crescente por conexão** no cliente (1,2,3… observado; heartbeat = 1 pedido a cada ~3,5–4,5 s). Servidor: rejeitar `session <= last` (anti-replay básico) — `ref_server` conta `stats['replay']`.
- Pareamento: 1 resposta por pedido com `response`, mesma `session`; latência observada mediana ~0,2–0,3 s (servidor real). Reordenação possível; o cliente só usa o `session`.
- Estado de sessão no servidor: `{uid, authed, secret_key, crypt_method, last_session, last_seen}`. Tudo exceto `loginauth` exige `authed`.
- Heartbeat 22 → `{time}` (relógio do servidor). Ociosidade > ~30 s ⇒ derrubar (original: heartbeat ~4 s). `req_loaddata`(21) é chamado **uma vez após o login** e dispara os ~50 `notify_*_init`.
- Reconexão: cliente refaz `loginauth`(novo token/nonce) + `loaddata`; servidor reenvia snapshot completo, **sem replay de deltas**.

### 1.3 Camadas de cifra (observadas) — e o que fazer
1. **Nível 0 — 0-pack** do sproto (compressão de zeros, não é cifra).
2. **Nível 1 — corpo XOR `crypt_method=1`**: o cliente decide por mensagem (só perfil/snapshot foram cifrados: 1029, 1023, 3001) marcando `ud{crypt_method=1, crypt_length=N}`; `body[:N] ^= secret_key` (periódica, 4 B). Na **resposta** o corpo inteiro vem XOR (o `crypt_length` do header é só o eco do pedido). A cifra é aplicada **antes** do 0-pack — por isso aparecem os blocos periódicos `b9 24 5f bd` (zeros XOR chave não são zero).
3. **Chave**: entregue na resposta do login (`secret_key`), 4 B, **sem derivação/KDF e sem TLS** ⇒ capturável por qualquer MitM; XOR de 4 B é recuperável por known-plaintext (já recuperado por crib).
4. `crypt_method=2` (RC4) está previsto no schema; não observado.
5. **Anti-abuse**: `req_dun163_risk_check{token}` → `{code, sdk_resp_data}` (Yidun) e `req_report_userkey` → `{userkey, gen_ts}` (assinatura base64 de 27 chars). O servidor valida o token do SDK de risco server-to-server.

**No seu jogo**: TLS (ou Noise/AEAD) no transporte; `secret_key` por sessão de 16–32 B via CSPRNG; `crypt_method` extra só para compatibilidade com o cliente-modelo. Se mantiver XOR/RC4, trate como ofuscação e **não** coloque segurança nela.

### 1.4 Cliente-autoritativo vs servidor-validador
| Dado | Hoje (observado/schema) | No seu jogo |
|---|---|---|
| Resultado de PVE da aventura | cliente simula, servidor re-simula e compara (`battle_result_error`, `err_type`) | **manter**: simular no servidor, divergência = flag/ban, seed do servidor |
| Torre `climbtower_challenge` | servidor responde, push de update (`20466/20474`) | servidor decide o resultado; `sweep` só em fase vencida |
| Arena | `arena_fight` (servidor escolhe oponente) | simular no servidor |
| TD (`td_event_start/settle_stage`) | cliente roda a fase (ECS local), servidor recebe settle | token de tentativa + duração plausível + re-simulação se barato |
| **Snapshot 3001** (`survivor[].res601..607`) | **cliente calcula e envia** a cada ~30 s; servidor só ACK `{code:0}` | tratar como *hint*: clamp [0,100], taxa de variação ≤ f(tempo), nunca creditar; ideal: cálculo no servidor |
| Relógio / cooldowns / filas | servidor (`time` no heartbeat, `endtime` nas filas) | idem; jamais timestamp do cliente |
| Compras | SDK de pagamento → server-to-server (`throughCargo`) | pedido no servidor + validação de recibo + idempotência |

### 1.5 Pushes (`notify_*`)
1005 tipos. Ordem pós-login observada: `notify_game_init`(33) → `notify_quests`(4303) → … → `notify_base_info`(1010), `notify_resource_init`(1301), `notify_backpack_init`(1101), … (~50 em ~35 ms). Depois: deltas (`*_update`) e eventos (`notify_queue_timeout`, `notify_world_march_*`, `notify_opinion_update` (resposta ao 8501), `notify_climbtower_*`). Regra: push só ao dono/assinante; fila por conexão com limite (backpressure); nunca bloquear handler de pedido por causa de push.

---

## 2. Fluxo de login/handshake (observado, frame a frame)

1. C→S `loginauth`(1, session=1): `sdkToken` (48 c.), `account`, `serverid`, `version "1.14.27"`, `uid`, `group=1`, device ("motorola moto g(8)"), `device_os "android"`, `country_code "BR"`, `lan "pt"`, `distinct_id`, `device_id`…
2. S→C resposta (session=1): `code=0, serverid=931, uid, is_new=false, server_ts, version_info{appVersion,resVersion}, age_flag, secret_key=ecbabcb9, crypt_method=1, …`.
3. C→S `req_loaddata`(21) → resposta `{code}` + rajada de pushes.
4. C→S pedidos de UI (ranking 3201, mail 2514/2501, shop 2005…), `req_report_userkey`, `req_settings_set_device`, `req_dun163_risk_check`; depois heartbeat 22 a cada ~4 s e `trigger_opinion` 8501.
5. Pedidos cifrados (`ud.crypt_method=1`): 1029, 1023, 3001.

## 3. Os 50 grupos de protocolo (índice; detalhe com campos e validações em `tabela_grupos.md`)
| # | Grupo | Domínio | Mensagens-chave (id nome) |
|---|---|---|---|
| G01 | Login / autenticação | gateway | 1 loginauth; 21 loaddata; 33 ↓game_init |
| G02 | Heartbeat / relógio | gateway | 22 heartbeat; 8504 update_4_new_day |
| G03 | Cifra de sessão | gateway | 1 loginauth; 30841 report_userkey |
| G04 | Anti-abuse / risco | gateway | 13823 dun163_risk_check; 3613 settings_set_device; 30841 report_userkey |
| G05 | Conta: exclusão / reinos | conta | 23 del_account_pre_review; 24 del_account; 25 del_account_cancel_pre_review; 3601 server_list |
| G06 | Perfil do jogador | jogador | 1029 players_base_info_with_permission; 1023 players_base_info; 1021 player_detail_info; 1003 player_modify_name |
| G07 | Estado inicial (push pós-login) | gateway | 33 ↓game_init; 1301 ↓resource_init; 1101 ↓backpack_init; 1801 ↓hero_init |
| G08 | Recursos / moedas | economia | 1301 ↓resource_init; 1302 ↓resource_update; 1901 ↓produced_resource_init; 1503 get_hang_up_reward |
| G09 | Inventário / itens | economia | 1101 ↓backpack_init; 1102 ↓backpack_update; 1103 use_item; 1103 ↓backpack_auto_use |
| G10 | Loja interna | economia | 2002 shop_info; 2003 shop_buy; 2001 shop_quick_buy; 2004 shop_refresh |
| G11 | Recarga / pagamento | pagamento | 6705 recharge_get_first_reward; 6706 recharge_collect_accumulative_reward; 6707 recharge_by_voucher; 6708 recharge_by_token |
| G12 | Passes (BP) / pacotes | pagamento | 9251 battle_pass_collect_reward; 9252 battle_pass_buy_score; 9253 battle_pass_collect_all_reward; 9270 ↓battle_pass_info |
| G13 | VIP | economia | 4651 vip_get_daily_exp; 4652 vip_get_daily_free_gift; 16172 vip_privilege_turntable_play; 4603 ↓vip_info |
| G14 | Mail | social | 2514 mail_type_info; 2501 mail_cover_list; 2508 mail_detail_info; 2510 mail_read |
| G15 | Chat (envio) | social | 3405 chat_get_token; 3402 chat_send_p2p; 3403 chat_send_kingdom; 3404 chat_send_alliance |
| G16 | Chat de grupo | social | 13551 chat_group_create; 13552 chat_group_add_member; 13553 chat_group_del_member; 13559 chat_group_change_group_owner |
| G17 | Amigos | social | 8102 friend_add; 8103 friend_accept; 8104 friend_refuse; 8105 friend_del |
| G18 | Aliança: criar / entrar | aliança | 5101 alliance_create; 5115 alliance_join; 5116 alliance_apply_join; 5121 alliance_quit |
| G19 | Aliança: gestão / cargos | aliança | 5104 alliance_modify_notice; 5105 alliance_modify_name; 5107 alliance_modify_flag; 5109 alliance_modify_recruit_type |
| G20 | Aliança: ciência / doação / ajuda | aliança | 5203 alliance_science_research; 5204 alliance_science_donate; 5205 alliance_science_diamond_donate; 5251 alliance_help_all |
| G21 | Ranking | competição | 3201 rank_info; 3202 rank_range; 5402 alliance_rank_data; 5403 alliance_rank_get_rewards |
| G22 | Arena (PvP assíncrono) | competição | 8453 arena_refresh_opponent; 8460 arena_get_opponent; 8452 arena_set_defence_heroes; 8454 arena_fight |
| G23 | Torre (PvE em fases) | fases | 20461 climbtower_info; 20462 climbtower_tower_info; 20463 climbtower_challenge; 20464 climbtower_quick_challenge |
| G24 | Aventura PVE / auto-batalha | fases | 2602 battle_adventure_battle_result_error; 1550 ↓adventure_pve_info; 1503 get_hang_up_reward; 10851 ↓battle_hero_arrange_data |
| G25 | Batalha: sincronização / reprodução | combate | 2603 battle_by_key; 2602 battle_adventure_battle_result_error; 10851 ↓battle_hero_arrange_data |
| G26 | TD (Tower Defense) | fases | 16351 td_event_start_stage; 16352 td_event_settle_stage; 16354 td_event_fast_challenge; 16353 td_event_get_survivor |
| G27 | Sobreviventes + snapshot do cliente | combate | 3001 save_client_data; 2807 survivor_work_start; 2808 survivor_work_pause; 2803 survivor_update_cure_end_time |
| G28 | Heróis | progressão | 1811 hero_upgrade; 1812 hero_promote_star; 1816 hero_upgrade_skill; 1814 hero_debris_exchange |
| G29 | Equipamento / skin | progressão | 8601 wear_equipment; 8608 equipment_strength_recast; 8611 equipment_break; 8612 equipment_temper |
| G30 | Pets | progressão | 15321 pet_upgrade; 15330 pet_get_upgrade_initial_item; 15351 ↓pet_info; 15352 ↓pet_update |
| G31 | Cidade / construção | cidade | 2702 upgrade_building; 2703 upgrade_furniture; 2708 upgrade_building_cancel; 2902 building_queue_speed |
| G32 | Filas / aceleração | cidade | 2901 purchase_queue_time; 2903 queue_ask_for_help; 2953 ↓queue_update; 2952 ↓queue_timeout |
| G33 | Tropas: treino / hospital | cidade | 2251 barrack_train_soldier; 2252 barrack_recruit_soldier; 2253 barrack_upgrade_soldier; 2254 barrack_speed_up |
| G34 | Pesquisa | cidade | 12701 spar_science_begin_research; 12702 spar_science_research_complete_immediately; 12704 spar_science_research_speed_up; 12731 ↓spar_science_all_research |
| G35 | Mundo / mapa | mundo | 5601 world_map_info; 5617 world_mapobj; 5615 world_map_search; 5604 world_move_city |
| G36 | Marchas | mundo | 5701 world_march; 5702 world_march_recall; 5703 world_march_speedup; 5709 world_march_detail |
| G37 | Missões / conquistas | progressão | 4303 ↓quests; 4501 get_growthquest_award; 4401 get_dailyquest_award; 4405 get_all_dailyquest_award |
| G38 | Check-in / recompensas periódicas | engajamento | 15301 sign_21day_get_reward; 15302 sign_21day_get_all_reward; 16132 sign_draw_lottery; 9101 receive_online_reward |
| G39 | Eventos de atividade | engajamento | 11401 get_active_recharge_quest_reward; 12921 daily_task_activity_get_task_reward; 9952 continuous_recharge_reward; 15531 ↓personal_7days_init |
| G40 | Gacha / roleta | engajamento | 4701 hero_search_times; 10351 hero_turntable_play; 16172 vip_privilege_turntable_play; 16132 sign_draw_lottery |
| G41 | Guerra de aliança (arsenal/supremacy/triangle) | guerra | 11103 arsenal_war_march; 17303 arsenal_league_march; 15985 triangle_war_march_move; 16001 triangle_war_heartbeat |
| G42 | Espectador / heartbeat de instância | guerra | 51 spectator_agent_heartbeat; 52 spectator_agent_auth; 16001 triangle_war_heartbeat |
| G43 | Red packet | social | 20511 red_packet_send; 20513 red_packet_get; 20515 red_packet_get_detail; 20517 red_packet_exist |
| G44 | Upload de imagem / UGC | social | 8326 upload_image_erase; 8327 get_hd_image; 1014 ↓player_upload_image; 8301 ↓upload_image_init |
| G45 | Setup / tutorial / questionário | engajamento | 8001 guide_set_step; 3604 update_setting_info; 9201 questionnaire_writed; 9202 questionnaire_get_reward |
| G46 | Polling leve (client-driven) | gateway | 8501 trigger_opinion; 2518 update_read_time; 20959 update_find_goods_server_time; 2810 survivor_update_riot_detect_time |
| G47 | Push genérico notify_* (S→C sem session) | gateway | 1102 ↓backpack_update; 1302 ↓resource_update; 2953 ↓queue_update; 2560 ↓mail_type_info_syn |
| G48 | Notificações de compra/BP | pagamento | 9271 ↓battle_pass_purchase; 15482 ↓general_bp_purchase; 30832 ↓hero_growth_bp_purchase; 15312 ↓sign_21day_purchase |
| G49 | Cheat / GM (OBRIGATÓRIO desabilitar) | segurança | 1201 cheat_add; 1202 cheat_reduce; 1211 cheat_recharge; 1223 cheat_change_sys_time |
| G50 | Config / versão / módulos | gateway | 1 loginauth; 3601 server_list; 3653 ↓setting_gm_mark; 3607 ↓unlock_module_info |

> Cada grupo em `tabela_grupos.md` traz, para cada mensagem: id real, direção, **campos do request e response (nomes sproto reais)** e a linha **"Servidor PRECISA validar"**. Os 50 grupos resumem os 1888 req + 1005 notify; os ~100 prefixos restantes (eventos sazonais: `thanksgiving`, `brawl`, `frostfire`, `supremacy`…) repetem os mesmos padrões (G38 check-in, G39 eventos, G40 gacha, G43 guerra) e não pedem desenho próprio.

### 3.1 Padrões transversais de validação (todos os grupos)
1. **Autenticação por mensagem**: `authed` + `module_unlocked` + versão mínima.
2. **Idempotência**: `session` crescente + chave de idempotência por operação de recompensa/compra.
3. **Transação**: débito+crédito+marca de "já resgatado" numa transação (§5.3).
4. **Dono do recurso**: todo id vindo do cliente (`uids[]`, `mailid`, `qid`, `sid`, `aid`) é verificado contra o uid da sessão/relacionamento.
5. **Limites de lote**: arrays do request com teto (ex. `uids[]`≤50, `range`≤100).
6. **Relógio do servidor**: jamais confiar em `ts`/`endtime` do cliente.
7. **`code`**: respostas devolvem `code` (0=ok) com códigos de erro estáveis — nunca exceção ao cliente.

## 4. Servidor de referência (`ref_server.py`, 253 linhas)
1. **sproto**: `parse` (schema → tipos/protos), `unpack`/`pack` (0-pack; grupo cheio → `ff 00`+8 B), `Codec.dec/enc` (inteiros inline ou `data` de 4/8 B, strings/structs com `u32 len`, arrays de int/bool/double/struct, `double`, `binary`, structs aninhados `.nome`).
2. **Schema**: carrega os dois `.sproto`; `req_by_id`/`push_by_id` (dispatcher **por direção**).
3. **Gateway**: `Session`, `handle(ss, raw)` = unpack → header → decifra (`ud`) → checa `session` crescente → exige login → decodifica request → handler → monta response (mesmo `session`, sem `type`) → pushes pendentes. Handlers reais: `loginauth` (devolve `secret_key`/`crypt_method`), `req_heartbeat` (`time`), `req_loaddata` (+push `notify_game_init`), `req_save_client_data` (clamp [0,100]). **Todo o resto = stub** `{code:0}` ou `{}`; `req_cheat_*` → `code=-1` e contagem `denied`.
4. **TCP asyncio** (`conn`): `u16 BE len`, timeout de ociosidade (`IDLE`), uma sessão por conexão.
5. **Self-test**: `decode_all` (312 frames, ambos os lados, aprendendo a chave do login rsp) + `loopback` (servidor real em 127.0.0.1, cliente reproduz os 61 pedidos C→S do transcript e confere respostas/session).

Estender: `gw.H['req_shop_buy'] = fn(ss, req) -> dict` (a resposta é codificada pelo schema; campos ausentes são omitidos). Push: `gw.push('notify_xxx', {...})`. Subir de verdade: `python3 ref_server.py --proto <protocols/> --serve 30101`.

## 5. Checklists

### 5.1 Fazer IGUAL (compatível com o cliente-modelo e bom desenho)
- sproto + 0-pack; header `package{type,session,ud}`; resposta sem `type`; push sem `session`.
- `session` sequencial por conexão; heartbeat curto (3–4 s) com `{time}` do servidor.
- `loaddata` → rajada de `notify_*_init`; deltas `notify_*_update`.
- Filas (`qid,status,endtime`) como entidade do servidor com `notify_queue_*`.
- `code` em toda resposta; re-simulação + `err_type` em `battle_result_error`.
- Banco transacional; pedido de pagamento com `throughCargo` (payload opaco do jogo atravessando a loja).
- Recompensas "1×" por flag server-side.

### 5.2 Fazer DIFERENTE (segurança)
1. **Sem `req_cheat_*` em produção** (287 no original); ACL por flag de build; nunca `group=debug`/`inner_permission_*` no login público.
2. **Transporte com TLS/AEAD**; `secret_key` nunca em claro; chave por sessão ≥16 B; rotação.
3. **Login com nonce+timestamp+HMAC** (o original reaproveita `sdkToken`/uid entre conexões, sem nonce — replay trivial); validar `sdkToken` no IdP; limites por IP/dispositivo.
4. **Server-authoritative onde der**: PVE/arena/torre/TD simulados no servidor (seed do servidor); snapshot 3001 = *hint*; nunca creditar recurso do cliente.
5. **Recibo na loja**: `orderId` criado no servidor; validar com Google Play Developer API/App Store Server API; idempotência por `purchaseToken`/`orderId`; comparar uid do pedido×sessão; entregar → ack → consumir; reconciliação periódica; `by_voucher`/`by_token`: código de uso único + anti-brute-force.
6. **Rate-limit** (token bucket por uid+msg): heartbeat ≥1 s; chat/mail/friend add; `range`/`search`/`players_base_info` (uids≤50); polling 8501.
7. **Limites de lote** e paginação em tudo que lista (anti-scraping de jogadores/mapa).
8. **Visibilidade**: mapa/marchas só do que o jogador vê; `permission` verificada em `players_base_info_with_permission`.
9. **Filtros de conteúdo** (nome, chat, alias, UGC, nome de aliança) e moderação de imagem.
10. **Auditoria**: log de todo débito/crédito/compra/ação de cargo; divergência cliente×servidor (como `err_type`) contada com ban progressivo.
11. **Hardening do parser**: frame ≤65535 (u16); validar `u32 len` de campos contra o tamanho restante e limitar profundidade/tamanho de arrays (o decoder de referência confia no `len`; em produção valide).

### 5.3 Transações obrigatórias
- compra interna: débito de moeda + item + contador de limite;
- pagamento: pedido `created→paid→delivered` + crédito + ack à loja (outbox);
- recompensa (mail/quest/caixa/ranking/check-in): marcar "recebido" + creditar atomicamente;
- fim de batalha/torre: consumir tentativa + recompensa + progresso;
- construção/pesquisa/tropas: recursos + fila + `endtime`;
- doação/ajuda de aliança: débito + contagem diária + efeito.

## 6. Validação do esqueleto (executado)
Comando (WSL `kingshot-re`, Python 3, só stdlib):
```
python3 ref_server.py --proto <protocols/> --replay /home/re/work/apk/gw_transcript115.pkl
```
Saída real (`run_output.txt`):
```
schema: 1888 req/resp c2s, 1005 notify s2c
DECODIFICADOS: 312/312 frames (C>S=61, S>C=251); chave de sessão aprendida do login rsp = ecbabcb9
tipos distintos: 222 | top: [('req_heartbeat', 27), ('req_heartbeat.rsp', 27), ('req_trigger_opinion', 9), ('notify_opinion_update', 9), ('req_trigger_opinion.rsp', 9), ('notify_card_bp_info', 4)]
LOOPBACK TCP: enviados 61 pedidos C>S | respostas 61 | session ecoada correta 61 | heartbeat(21/22) respondidos 28 | login(1) 1 | pushes recebidos 1
stats gateway: {'req': 61, 'resp': 61, 'push': 1, 'unknown': 0, 'replay': 0, 'denied': 0}
```
- **312/312 frames decodificados campo-a-campo** com nomes reais de mensagem/campo (222 tipos distintos), inclusive os cifrados (1029/1023/3001 e respostas) com a chave `ecbabcb9` aprendida do próprio login rsp.
- **Loopback TCP real** (asyncio): **61/61** pedidos respondidos com a `session` ecoada (61/61): 1 login (msgId 1), 1 `req_loaddata` (21, dispara o push `notify_game_init`), 27 heartbeats (22) — "28" na saída = 21+22 pelo critério `type in (21,22)`.
- **Round-trip do encoder** (`rt_test.py`, `rt_output.txt`): re-codificar e re-decodificar os 312 corpos → **312/312 idênticos** (arrays de inteiros 8 B, structs aninhados, doubles, binary).
- Heartbeat do servidor vs original: header idêntico (`55 02 01 …`), diferem só no valor de `time` (relógio ≠). Login rsp **não** comparado byte-a-byte (o stub não preenche campos opcionais do original: `age_flag`, `show_privacy_policy`…).

## 7. Próximos passos
1. Codegen de handlers a partir do schema: um stub por `req_*` com validação declarativa (tetos, posse).
2. Config estática do servidor (preços, custos, tempos): sem as tabelas Lua originais, refaça com as do seu jogo.
3. Captura dirigida (compra, abrir mail, torre, aliança) para validar G09–G45; o `ref_server`/`t1.py` já servem de dissector.
4. Pagamento real (recibo) e IdP fora do gateway.
5. Decidir RC4 (`crypt_method=2`) vs TLS; recomendado TLS e manter `ud` só por compatibilidade.

## 8. Confiança
| Afirmação | Confiança |
|---|---|
| Moldura/header/formas de frame; schema como fonte de nomes e campos | **Alta** (312/312 + round-trip) |
| `secret_key`+`crypt_method` no login rsp; cifra do req = `crypt_length`; da resp = corpo todo | Alta (req) / **Média** (resp: 4 pares) |
| 3001 = atributos de sobreviventes calculados no cliente | Alta (schema+decode) |
| Existência de 287 `req_cheat_*` no schema | Alta; **se o servidor de produção os aceita: desconhecido** |
| Validações por grupo (G05–G50) | Média/baixa: padrão do gênero + schema, sem comportamento observado |
| Hipótese "tokens de 2 B" = marcadores do pack | Baixa (não testada) |
