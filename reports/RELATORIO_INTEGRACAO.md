# RELATÓRIO — LANE INTEGRATE (mock_v4 + server_state / server_rules / server_timers)

Entregas: `mock_v4.py` (integrado), `test_integrate.py` (40/40), este relatório. Mexi também em `work/server/server_rules.py` (+1 campo `item_id` em GOODS, p/ a loja creditar o item). Nada escrito no repo.

## Validação
| Suíte | Resultado |
|---|---|
| `server/test_state.py` | 31/31 |
| `server/test_rules.py` | 6/6 |
| `server/test_timers.py` | 12/12 |
| `mockserver/test_integrate.py` (NOVO; mock real via subprocess na 30102, restart de verdade) | **40/40** |
| legado `test_handlers_v4` / `test_handlers_l3` / `test_v4_client` | 31/31, 14/14, 11/11 (modo sem integração, inalterado) |

`test_integrate.py` cobre: shop_info antes do loaddata → 2 · acção antes do loaddata → 2 · heartbeat liberado · login→loaddata (snapshot ≥20 notifies) · climbtower 2× → 16807 (outro nível ok) · shop_buy ok / até o limite / além → 702 / slot inexistente → 701 / sem saldo → 51 / count 0 → 2 / com preço debita 109 e push `resource_update del` · hang-up 2× → 4004 · online 2× → 6151 · daily 2× → 905 · mail_receive 2× → 1202 · td_settle 2× → 6158 · save_client_data · upgrade_building com `total_time == build_time(302,24)` (45270 s) + fila ocupada → 73 · **restart (kill + novo processo)**: law_point, recurso 102, gasto da loja (109), climbtower 16807, contador da loja → 702, daily 905, fila de obra (end_time futuro) e fila ocupada → 73 · conclusão de obra por timer (`--build-time-scale 0`) → `notify_building_upgrade_finish` e nível 24 no snapshot do login seguinte.

## O que ficou LIGADO
Uso: `python mock_v4.py --port 30101 [--state PATH] [--no-sequencer] [--build-time-scale F] [--no-state]` (default state = `work/mockserver/account.json`; aceita `{uid}` no caminho). Integração só liga na CLI (ou `serve(integrate=True, state=...)`); `serve()` sem `integrate` = comportamento antigo (por isso os testes legados continuam intactos).

1. **Login** (`h_loginauth`): `Ctx.account(uid)` → `Account.load(state)` se existe, senão `from_seed(fixture)`; recompõe `ReplayRegistry` (persistido em `account.replay_done`, `reset_daily` na virada de dia local), `QueueManager` a partir de `account.queues`/`queue_tasks`; grava `meta.login_ts`/`last_login`; `seq.login_ok()`. Uma `Account` por uid compartilhada entre conexões, lock global (RLock) em volta de cada request.
2. **Dispatch** (`run`): `Session.check(nome)` antes do handler; código ≠ None → `reply({'code': cod})` e handler não roda. `loginauth` é tratado à parte (o sequencer só conhece `req_login`, que não existe neste protocolo). Handler que levanta exceção agora é logado (`[handler-err]`) sem derrubar a conexão.
3. **Handlers com estado**: `h_save` → `apply_client_save` + `save`; hangup, online, daily, td_start/settle, mail_receive, climbtower → anti-replay/cooldown ANTES de responder + `account.grant` (+ `save`); `h_shop_buy` (novo) → `check_shop_buy` (701/702/2) + `apply_cost` (51) + `spend` + `shop_buy` (contador no struct da loja da conta) + `grant(item_id×count)` + pushes; `shop_info/shop_info_array` leem da conta; `h_upgrade_building` → `QueueManager.start` com `build_time(bid, lv+1)` REAL (× `--build-time-scale`), `notify_queue_update` ocupada, timer daemon conclui (queue 2 → `building_upgrade_finish` → queue 1 → `shelter_info`) e aplica `set_building_lv`; obras que terminam com o cliente offline são liquidadas no próximo `loaddata`.
4. **Persistência**: `account.save()` (escrita atômica) a cada save do cliente e a cada mutação (grant/spend/loja/fila/replay).
5. **loaddata**: `snapshot_notifies()` substitui o burst cru. `burst_tpl`/`burst_idx` (usados por push_shelter, push_survivor_info, produced, auto-notify) também passam a ler o snapshot vivo → o fallback não re-empurra estado velho do fixture.

## O que ficou de FALLBACK (comportamento antigo)
- Auto-notify (`REQ_NOTIFY`) segue ativo, agora com templates vindos do snapshot da conta.
- Handlers sintéticos sem modelo na conta: `h_recruit`, `h_train` (instantâneo), `h_mail_onekey`, `h_mail_cover_list` (mails sintéticos, não entram em `account.mails`), `h_rank_info`, `h_arena_report`, `h_upgrade_furniture` (nível só na sessão), `survivor_work_*`, `hunting_tool_obtain`, `dorm_bed_obtain`, `schedule_info`, `h_cheat_*` (GM só inventário de sessão), `h_default` (template/`code 0`).
- Sem integração (`--no-state` ou sem módulos em `../server`): mock idêntico ao anterior.

## Decisões / desvios do pedido
- **hang_up**: o errcodes real não tem `*_already_get` para hang-up. Usei cooldown de 60 s (`HANG_MIN_INTERVAL`) com `err_hang_up_reward_interval_not_enough` = **4004** (semanticamente o mais próximo). Não passa por `check_and_mark`.
- **online reward**: cooldown de 3600 s → `err_online_reward_not_exist` (6151).
- **td_settle**: 1 settle por `start_stage` (`reward_generic`, chave `td:<start_ts>`); settle sem start prévio é livre (sandbox).
- **Loja**: o contador de compras vive em `account.shops[..].goods[].buy_count` (persistido) e uso `R.check_shop_buy` direto com ele, em vez de `ShopState` (em memória, não persiste). `goods_id` = slot (`goods.id`) ou `conf_id` de algum slot; senão 701. Loja que ainda não existe na conta é criada via `mk_shop` (conf_ids sintéticos → 701).
- `req_shop_buy` não tinha handler (caía em `h_default`/template); agora tem.

## Gaps / riscos
1. **Obra a duração REAL** pode ser de horas/dias (302 lv24 = 12 h 34). Não há speedup/ajuda/gema ligados: para uso prático rodar com `--build-time-scale 0` (instantâneo, mas com ciclo completo de notifies) ou um valor pequeno. Obras sem `costTime` na cfg → 1 s. Custo de recursos (`costRes`) e pré-requisitos de obra **não** são cobrados/validados. Pesquisa/treino/cura não integrados às filas.
2. **Moeda desconhecida**: ofertas com `price` mas sem `currency` (ex. loja 701) saem de graça (sem moeda p/ debitar). Ciclos de reset de loja (DAY/WEEK) não aplicados (só o `reset_daily` do replay); `refresh` de loja não tem handler.
3. **Offline**: `notify_offline_info` do snapshot é o do seed (estático); `offline_gain` / `SurvivorWork` / `Station` do server_timers **não** foram ligados ao login/handlers de sobreviventes.
4. **Sequencer**: um request pré-loaddata que o cliente real envie e que não esteja na lista liberada (`PRE_LOADDATA_OK/IDS`) recebe `code 2`. Se o cliente real engasgar, subir com `--no-sequencer`. Respostas sem campo `code` no schema saem vazias.
5. **Replay**: `mail_onekey`, `mail_cover_list` e hunting/dorm ainda não validam repetição (re-farm possível). Mail ids sintéticos de `mk_mail` mudam por sessão, então o "já recebido" de um mail sintético é por id de sessão.
6. `account.json` único por padrão: o servidor mistura qualquer login nele (uid vem do fixture). Para estado limpo, apagar o arquivo ou usar `--state` novo.
7. Código de `climbtower`: marcação é por id de nível; `his_passed_level` etc. vêm de `tower_pass(4, id+1)`, enquanto o push `notify_climbtower_tower_update` continua com `total_passed_cnt: 200` fixo.
