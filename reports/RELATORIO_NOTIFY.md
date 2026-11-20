# Relatório — LANE NOTIFY-AUTO (auto-reflection de pushes no mock_v4)

## O que foi feito
1. **Tabela req→notify** (`MAPEAMENTO_REQ_NOTIFY.tsv`, gerada por `gen_req_notify.py`): chave = módulo Lua. MSGMAP.tsv tem exatamente 1 módulo por msg; HANDLERS.tsv (nome normalizado `game_module_logic_module_X` → `X`) reforça. Para cada req_ do módulo M, listam-se todos os notify_ citados por M. Colunas: `req, module, notify, template_burst(0/1), source`.
   Totais: 12 028 linhas, 376 módulos, 1 646 reqs com ≥1 notify no módulo, 1 027 reqs com ≥1 notify que tem template no burst (1 515 linhas com template).
2. **mock_v4.py**: `Session.auto_reflect(req)` é chamado após **todo** handler (inclusive `h_default`/templates). Re-pusha os notify_* do módulo usando o payload do `burst` da fixture (cópia profunda). Sem template → pula (contador `auto_notpl`).
   - Flags: `--auto-notify on|off` (padrão on), `--auto-window S` (dedup por notify, padrão 5 s), `--auto-max N` (teto de notifies por req, padrão 8).
   - Dedup: `Session.push` registra `last_push[notify]` — vale também para pushes explícitos dos handlers (ex.: `notify_survivor_info` do `push_survivor_info` não é duplicado) e para o burst do loaddata.
   - Fora (`AUTO_SKIP`): heartbeat, save_client_data, chat_get_token, cheat_*, trigger_opinion, loaddata, players_base_info, dun163_*.
   - Stats por sessão no log `[end]`: `auto`, `auto_dedup`, `auto_cap`, `auto_notpl`, `push`.
   - Tabela carregada de `MAPEAMENTO_REQ_NOTIFY.tsv` ao lado do script (se faltar, auto-notify vira no-op).
3. **Teste** `test_notify_v4.py [on|off|nowin]`: sobe na 30102, loga com a transcrição, reenvia 1 payload real por tipo de req do mock_live.log (24 tipos), lê respostas e pushes que seguem, decodifica tudo via sproto_py.

## Resultados (offline)
| modo | reqs | respostas | pushes totais | decode falhas |
|---|---|---|---|---|
| off | 24 | 24 | 179 (176 burst + 3 explícitos) | 0 |
| on (janela 5 s) | 24 | 24 | 197 | 0 |
| nowin (janela 0) | 24 | 24 | 209 | 0 |

Reflexo observado (modo on/nowin), req → notifies automáticos:
- `req_survivor_work_start/pause`, `req_hunting_tool_obtain`, `req_schedule_info` → `notify_survivor_info`, `notify_clientsave_data`, `notify_schedule_update` (módulo city_SurvivorCtrl; **o conjunto que faltava pro modo caça/agenda**).
- `req_dorm_bed_obtain` (city_CityCtrl) → `notify_offline_info`, `notify_shelter_info` (+`upgrade_building` idem).
- `req_td_event_start/settle_stage` → `notify_td_event_info`.
- `req_get_all_dailyquest_award` → chapterquests/dailyquests/growthquests; `req_mail_cover_list`/`mail_type_info` → `notify_mail_type_info_syn`; `req_arena_report` → `notify_arena_init`; `req_report_userkey` → 4 notify de chat; `req_update_setting_info` → setting_info/gm_mark; `req_skin_get_condition_activity_skin` → `notify_skin_info`.
- `req_rank_info`, `req_shop_info_array`, `req_players_base_info...`: sem módulo Lua mapeado no MSGMAP (0 pushes — não há o que refletir).
- Com janela 5 s logo após o login, vários reflexos são suprimidos (o burst acabou de entregar o estado) — comportamento intencional.

## Sem template (limitações)
Dos 959 notify distintos da tabela, só 155 têm template no burst (167 tipos no burst; alguns fora dos módulos mapeados). Ficam sem push (pulados): `notify_building_upgrade_finish`, `notify_stove_info`, `notify_survivor_alloc_num_update` (city_CityCtrl; o `upgrade_building` continua sintetizando o finish explicitamente), `notify_survivor_add/del/riot_end/td_dead`, `notify_temp_survivor(_quest)`, `notify_law_point_add` (SurvivorCtrl), `notify_td_event_over/quest_update/trigger`, `notify_arena_report`. Lista completa: linhas `template_burst=0` do TSV. Próximo passo possível: sintetizar à mão esses (ex.: `notify_stove_info`, `notify_survivor_alloc_num_update`) ou obter de capturas.

## Riscos / observações
- Mapeamento por módulo é grosso: reqs de módulos grandes re-pusham estado (estático, do login) — pode regredir estado que o mock mudou (ex.: `notify_survivor_info` estático vs. `surv_work`; já tratado por push_survivor_info + dedup). Notifies de "init" reenviados podem resetar telas; mitigação: `--auto-max`, `--auto-window`, `--auto-notify off`.
- Não validado com o cliente real (só offline). Reqs sem resposta no schema também refletem.
