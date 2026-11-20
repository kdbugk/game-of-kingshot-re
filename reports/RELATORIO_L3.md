# RELATORIO_L3 — Lote 3 de handlers (mock_v4.py)

Resultado: **14 OK / 0 FAIL** (`test_handlers_l3.py`, porta 30102, offline) + regressão `test_handlers_v4.py` **31 OK / 0 FAIL**.
Entregue em `C:/Users/prs/work/mockserver/mock_v4.py` (copiado para `/home/re/work/apk/`; repo não tocado).

## Handlers (todos `code:0`, sandbox generoso)
| req | resposta | pushes (UI depende) |
|---|---|---|
| `req_dorm_bed_obtain` | `fid_work_end_time` = cada fid pedido → now+30s | `notify_resource_update` (add 101/102) + `notify_shelter_info` com `work_endtime` das camas atualizado (camas = furniture type 1 conf 101/102; é `work_endtime` que a UI usa p/ "coletável") |
| `req_schedule_info` | `{qtime_id, start_time, server_time}`; qtime avança 1/h do relógio sintético (base 21) | `notify_schedule_update` idêntico |
| `req_shop_info` | `info` = shop real do template do cap115 se existir; senão sintético (8 goods, `conf_id = shop*100000+10000+grid*100+1`, padrão observado) | — |
| `req_shop_info_array` | `map_info` 1 shop por id de `arr_id` (template real ou sintético); `buy_count=0` em tudo = sem limite consumido | — |
| `req_rank_info` | 1 `rank_info` por `list_type` (eco de type/ext; `self_rank=1`, `count=100`, `top` e `self_value` = [~1e9, ts]; nome mock via uid 40444746) | — |
| `req_arena_report` | 1 relatório (vitória, scores 1000→1030, poderes plausíveis) | — |
| `req_unlock_module`, `req_guide_set_step` | `{code:0}` (`h_ok`) | — |
| `req_produced_resource_need_update` | `{code:0}` | `notify_produced_resource_update` (102 +100000, 103 +50000, 195 +20000 sobre o base do burst, workstations preservadas; acumula na sessão) |
| `req_mail_type_info` | `{code:0}` (schema só tem code) | `notify_mail_type_info_syn` (burst, com `can_get_attach=1`, unread ≥2) — é por aí que vêm os dados |
| `req_mail_cover_list` | `coverlist` = 2 mails sintéticos (`attach_statue=1`, ids únicos, mailid_new string) + 1 real do template do mesmo `first_type` | — |
| **Caça** (`req_hunting_tool_obtain` reescrito) | `work_endtime=now+30` | `notify_resource_update` (101 +5000, 102 +20000), `notify_shelter_info` com `work_endtime` da ferramenta (furniture type 18, fid = `fid_work` do sobrevivente) setado p/ now+30, `notify_survivor_info` status 2 |

**Caça completa:** no schema NÃO existe `hunting_start`/`work_end`. O ciclo é só `req_hunting_tool_obtain` (comentário do schema: "work_endtime: antes disso não pode caçar de novo; cada work-periodo uma vez"). O que faltava era a UI saber do novo `work_endtime` — que vive em `furniture.work_endtime` dentro de `notify_shelter_info`; agora é reenviado com o valor novo (e cooldown curto de 30s, antes 60s sem atualizar o shelter → provável causa dos 6× obtain repetidos). Hipótese a confirmar ao vivo.

Auxiliares novos na Session: `burst_tpl`, `push_shelter` (aplica `fid_wet` + `bld_lv` do sandbox), `push_res_add`, `push_produced`, `mk_shop`, `mk_mail`; estado `fid_wet`, `prod_extra`, `mail_seq`.

## Testes (`test_handlers_l3.py`, 1+ por handler)
Payloads reais do `mock_live.log` (truncados em 100 chars → reparados por regex: fids, tipos de rank, arr_id de shop) marcados `[real]`; os sem amostra `[synt]` (unlock_module, guide_set_step, produced_need_update, shop_info). Cada teste valida code 0, campos obrigatórios, **pushes esperados presentes** (decodificados pelo schema) e uma checagem semântica (ex.: nº de fids = nº de entradas, buy_count=0, attach_statue=1, work_endtime>0). Hunting roda 2× (repetível). Execução: `cd /home/re/work/apk && python3 test_handlers_l3.py`.

## Atenção / riscos
- **Edição concorrente**: outra lane adicionou `auto_reflect/AUTO/REQ_NOTIFY` ao mesmo mock_v4.py durante o trabalho; os dois conjuntos de mudanças coexistem (verificado, 45 testes passam). Para evitar que o auto-reflect re-empurrasse templates *stale* (offline_info — popup de recompensa offline —, survivor_info, clientsave_data), adicionei `req_dorm_bed_obtain`, `req_schedule_info`, `req_mail_type_info` ao `AUTO_SKIP`. Outros handlers meus são cobertos pelo dedup (`last_push`, 5s).
- `notify_shelter_info` é reenviado inteiro (13 KB, estilo burst). Se o cliente substituir o estado de prédios, os níveis de `upgrade_building` são preservados via `bld_lv`, mas outras mudanças de furniture (upgrade_furniture `fur_lv`) não são reaplicadas — melhoria futura.
- Ids de recurso de recompensa (101/102/103/195) são palpites alinhados com o hangup/td; não confirmados qual é "carne crua" da caça.
- Mails: sem handler de `req_mail_read`/coleta de anexo (fora do lote) — abrir o mail cairá no template/default; `param` do mail sintético é `"80"` (mapa msgpack vazio).
- `req_rank_info` lista só o primeiro colocado (campo `top`); `req_rank_range` não implementado.
- Não validado ao vivo no cliente (só offline).
