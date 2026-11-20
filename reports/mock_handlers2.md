# RELATORIO_HANDLERS — mock_v4.py lote 2 (sandbox generoso)

Handlers novos (dispatcher `H`), todos com `code:0`:

| Request | Resposta |
|---|---|
| req_survivor_work_start {sid} | `time`=now; sid entra em `surv_work` (estado de sessão) |
| req_survivor_work_pause {sid_list} | `code:0`; remove os sids de `surv_work` |
| req_hunting_tool_obtain {sid} | `work_endtime`=now+60 (permite caçar de novo em 1 min) |
| req_upgrade_building {bid,use_diamond,qid} | `{code,qid,expert_reduce_time:0}` + **3 pushes** (abaixo) |
| req_upgrade_furniture {bid,conf_fid,add_lv} | `lv` = nível rastreado por (bid,fid) + add_lv |
| req_td_event_start_stage | `start_stage_ts`=now, 3 `td_box` (cada com 50k de id 102), `td_survivor` tipo1 e tipo2 |
| req_td_event_settle_stage {is_win,td_survivor} | vitória: itens 101×500, 102×200k, 103×100k, 105×50k; derrota: 102×10k |
| req_skin_get_condition_activity_skin | listas vazias (sem skin em campanha) |
| req_mail_onekey_read {first_type} | `rewards` 101×100 + 102×50k, `readlist` vazio |
| req_barrack_train_soldier | `barrack` com soldier_id/num pedidos, `finish_ts`=now+1 (treino instantâneo) |
| req_mail_cover_list | `coverlist` vazio |
| req_receive_online_reward | já existia; conferido contra schema (code, online_reward, receive_start_time) OK |

Outros n≥2 no log: `req_produced_resource_need_update` (já coberto pelo default `{code:0}`), chat_token/heartbeat/opinion/save (já tratados).
n=1 (não tratados explicitamente, caem no default/template): receive_spec_reward, pet_break, begin_research, dorm_bed_obtain, recruitment_recruit_soldier, arena_report, schedule_info, rank_info, etc.

## Dependência de notify_* (upgrade_building)
O schema da resposta não traz nível/custo; a UI depende de pushes. Resolvido com `Session.push()` (mesmo mecanismo `L.build_push` + `send` do burst do loaddata), enviados logo após a resposta:
1. `notify_queue_update` (qid, status=2 ocupada, end_time=now+1, base.qtype=1)
2. `notify_building_upgrade_finish` {bid, lv, furniture_list:[], mode:0}
3. `notify_queue_update` (status=1 livre, como no burst real)
Obra "instantânea" no sandbox. Nível: `bld_lv[bid]` inicia em `stove_lv` do player_base (39) para bid 301, senão 1 — **o mock não conhece os níveis reais do save do cliente**, então lv pode divergir do exibido; ajustar via estado/GM se necessário. O significado de `status=2` é suposição (só se viu status=1 no burst).

## Testes
`test_handlers_v4.py`: sobe o mock em 127.0.0.1:30102 (fixture_v4.json), faz login real do transcript e reenvia os payloads REAIS extraídos do mock_live.log (+1 sintético p/ upgrade_furniture, sem amostra no log). Valida decodificação, `code==0` e campos obrigatórios (listas vazias omitidas no sproto são aceitas).
Resultado: **44 OK, 0 FAIL** (py_compile OK). Os 3 pushes do upgrade_building foram recebidos e decodificados.
Ressalvas: o teste não prova que a UI do jogo reage como esperado; o log trunca payloads em 100 chars (sid_list do pause reconstruído dos números visíveis).
