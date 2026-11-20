# RELATORIO — LANE RECIPES (modelos de resposta reais)

## O que foi feito
- `extract.py` decodifica as 2 capturas REAIS (login `gw_transcript115.pkl` + combate `kind03/frames.pkl`; mock_live.log NÃO usado), e para cada C→S pega a janela [t_req, próximo C→S]: resposta + pushes em ordem → `recipes.json`.
- Campos por comando: `response`, `pushes [[nome,obj]]` (só os "estáveis": presentes em ≥50% das ocorrências, para não atribuir timers coincidentes de heartbeat), `n_ocorrencias`, `delta_medio_ms`, `fontes`, `push_freq`, `req_exemplo`, `_ref_time` (relógio do servidor na captura, derivado do heartbeat mais próximo), `_dynamic` (caminhos vivos; `[]` = qualquer elemento de lista), `_dynamic_pushes`, `_variacoes` (valores distintos dos campos dinâmicos quando há >1 ocorrência). Com várias ocorrências guarda a mais completa (resp+pushes).
- `mock_v4.py`: `h_default` agora PREFERE a receita (antes: template do fixture ou `{code:0}`): responde com a resposta real, transplanta epochs dinâmicos (`valor = now + (valor_capturado − _ref_time)`, s e ms) e emite os pushes estáveis. Handlers específicos não foram tocados; sequenciador/anti-replay continuam antes (o dispatch em `run()` não mudou). Arquivo configurável por `RECIPES_FILE`; sem o arquivo, cai no comportamento antigo.

## Cobertura
- 37 comandos C→S distintos observados nas 2 capturas; **27 com resposta real**; 10 sem resposta capturada na janela (ver abaixo).
- Dos 27: **13 passam pelo h_default** e ganharam receita real efetiva (alliance_arsenal_war_login_weekly, chat_set_recent_contact, climbtower_info, climbtower_tower_info, dun163_risk_check, friend_get_alias, kitchen_cook_finish, kitchen_eat_finish, players_base_info, red_packet_exist, survivor_cure_finish, survivor_sick, survivor_update_cure_end_time); os outros 14 já têm handler específico (receita fica como referência/validação). O pedido falava em 15 — só 13 estão no h_default na prática.
- O catálogo REQ→NOTIFY cobre 1888 req no schema; ~37 observados ≈ 2% — o resto continua sem modelo real (precisa de mais capturas).
- Sem receita (sem resp na janela): arena_report, mail_type_info, shop_info, report_userkey, settings_set_device, update_setting_info, alliance_arsenal_league_*, alliance_showdown_* (respostas vazias/ausentes ou chegaram fora da janela).

## Padrões dinâmicos achados
- Epoch s: `loginauth.underage_info.server_ts`, `heartbeat.time`, `hunting_tool_obtain.work_endtime`, `survivor_sick.cure_end_time`, `players_base_info[_with_permission].result[].appoint_time/offline_time/equipedskin[].expire_ts`, `mail_cover_list.coverlist[].send_time`, `shop_info_array.map_info[].first_refresh_time/last_refresh_ts`.
- Contadores/valores: `climbtower_challenge.battle_result.def_power`, `rank_info` valores de ranking.
- Detecção = (valor varia entre ocorrências) ∪ (inteiro em faixa de epoch) ∪ (nome time/server_time/ts). Limitação: com 1 ocorrência só a heurística de epoch/nome vale; contadores que não variaram numa única amostra aparecem como estáticos.
- Heartbeat: 132 ocorrências, único com `time` dinâmico; `notify_opinion_update` é periódico, não consequência.

## Validação
- test_integrate 40/40, test_handlers_v4 31/31, test_handlers_l3 14/14 (rodados após a edição).
- `test_recipes.py`: 28/28 checks nos 13 comandos (estáticos idênticos, epochs ≈ now+offset ±5s, pushes estáveis recebidos).

## Riscos / pendências
- Pushes de receita (ex.: `notify_produced_resource_update` do kitchen) carregam valores absolutos da conta capturada, podem divergir do estado vivo (`--state`); ideal ligar a handlers de estado depois.
- `_ref_time` de capturas de combate vem do heartbeat (ofset de segundos).
- Respostas de comandos sem `response` no schema continuam sem resposta (comportamento mantido).
