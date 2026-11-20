# RELATÓRIO — LANE EXT-SOCIAL (aliança + chat)

Entregues em `C:/Users/prs/work/server/` (nada escrito no repo; `mock_v4.py` intocado):
`ext_alliance.py`, `ext_chat.py`, `_ext_common.py` (helpers), `test_ext_social.py`, este relatório.

**Validação: `python test_ext_social.py` → FIXTURES N_ok/N = 256/256 (205 alliance + 51 chat); CENÁRIOS 31/31.**
Cada handler é chamado com o payload de `fixtures_all.json` (valores aleatórios, ex. id=679507): sem exceção, 1 reply,
resposta SCHEMA-VÁLIDA (chaves ⊆ campos do response — recursivo, com tipos *scoped* como `req_x.response.rank_data` —
e round-trip `enc_struct → dec_struct` idêntico) e pushes idem (`build_push`). Cenários com payload válido verificam estado.

## Contrato / integração
`HANDLERS = {"req_x": fun(session, m)}`; `fun` retorna None e nunca lança (`safe` → `code:2` em exceção inesperada).
Usa `session.account` **ou** `session.acct` (o mock real usa `acct`), `session.reply/push/now`, `session.replay_err` (se existir).
**Para ligar no mock:** `HANDLERS.update(ext_alliance.HANDLERS); HANDLERS.update(ext_chat.HANDLERS)` (cobrem todos os
`req_alliance_*`/`req_chat_*` do c2s — nomes lidos do `game_proto_c2s.sproto` em import; msgs novas do schema viram stub code:0).
Estado social: `account.social` (dict JSON-safe, persiste via `Account.to_dict`); mutações da aliança são in-place no
passthrough `account.raw["notify_alliance_*"]` → o re-push/snapshot reflete. Env: `KS_SOCIAL_FREE=1` = doação/custos sem débito (sandbox).
Nota: no seed o jogador (uid 40444746) é **R1** (líder 34174824, R5) → ações de gestão devolvem 1508 (`err_alliance_have_not_permission`), como a produção.

## Handlers — ALIANÇA (205)
| Grupo | Msgs | Estado real (seed/conta) | Sintético / observação |
|---|---|---|---|
| Info/básico | init_data, detail_info, cover_info, members, setting, power, online_info, check_name/abbr, whitelist_get/add/del, check_whitelist_by_uid | aliança/player/membros do seed (`notify_alliance_init/member_init`); whitelist em `social` | alianças ≠ seed: determinísticas por aid (nome/abbr/poder); online = ⅓ dos membros |
| Busca | search_init, search_by_key, recommend_alliance, recommend_players, member_info_by_key | inclui a aliança do seed na busca | pool de 12 alianças sintéticas; jogadores sintéticos (nomes por uid) |
| Entrar/sair | create, join, fast_join, apply_join, cancel_apply, applys, deal_apply, deal_invite, invite_member, quit, dismiss | muda `left`, membros, `count`, player.rank; create cobra `systemconfig.alliance.create_cost` (400, item 101) via check_cost+spend; condição de entrada (level/power), lotação (member_max) | só existe UMA aliança real (a do seed): "entrar" reentra nela; apply_join a outras só registra o pedido |
| Gestão | change_rank, del_member, change_leader, replace_leader (custo 200), modify_name/abbr/flag/language/manifesto/notice/recruit_cond/recruit_type/rank_names | permissões por rank (R4+; líder p/ rank_names/dismiss/change_leader), escreve em `al` do seed | custos de renomear (`alliance_name_cost`) NÃO aplicados; só contadores `name_count/abbr_count` |
| Avisos | get_notice_history/star_history, like_notice, cur_notice_like_data, del/top/star/open_like_history, reserve_notice (CRUD + count, limite `notice_reserve_count`) | histórico acumulado em `social.notices` (semeado com o notice do seed) | sem agendamento: reserve não publica sozinho |
| **Doação / ciência** | science_donate, science_diamond_donate, science_research, science_recommend/cancel_recommend | **custo `alliance_science_detail.donate_cost` via `server_rules.check_cost` + `account.spend`** (51 se faltar), diamante = `systemconfig.alliance_science_conf.diamond_cost`; crit/multiplicador por `res_conf.rates/multiple`; credita `sciences[].donate`, `donate_day`, `player.donate`; recompensa pessoal `donate_reward` ×mult via `account.grant`; push `notify_alliance_science_exp_update`; research checa `need_donation_value`, pré-requisito e recursos da aliança (`cost_alliance_resource`) e sobe o lv | ganho de pontos por doação = contagem×mult (regra inferida); research conclui na hora (sem fila/cost_time); sem limite diário de doação (1528 não emitido); id da moeda premium ASSUMIDO = 101 |
| Baú | receive_chest, receive_chest_by_ids/by_type, chest_set_anonymity | baús de `notify_alliance_chest_init` (seed vem vazio): marca recebido + grant das rewards, 1540 se repetido | sem geração de baús |
| Dev/ajuda/recursos | dev_get_main/week/rank/daily, help_all, exchange_resource, bomb_use, war_mark_leader | `notify_alliance_dev_init`, `help_init` (glória por `help_reward`, teto diário), recursos da aliança (`resource`), bomba | dev_get_daily: recompensa sintética (101×50, 110×1000) + anti-replay `alliance_dev_daily` |
| Rankings | members_power_rank, members_kill_num_rank, rank_data, player_rank_data, rank_get_rewards, trap_score_rank | membros do seed | valores sintéticos por uid |
| Prédios | building_list(_exist), add, remove, hall_move | `notify_alliance_building_simple_info` mutado | sem custo/território/tempo de construção; building_list devolve só campos vazios |
| Votos | vote_add/records/record_detail/select/finish/delete_record/top/share_to_uids | CRUD completo em `social.votes`, limites de `systemconfig.alliance_vote` | — |
| Trap | trap_info, score_rank, get_mass_record, join_count, batch_get_personal_score_reward, buff_strengthen | `notify_alliance_trap_update` (donate/total_score) | sem mass real; buff_strengthen só soma doação (custo `alliance_trap_strengthen` não ligado) |
| Logs | activity_logs, activity_sub_logs, battle_logs | — | vazios code:0 |
| **STUBS code:0 (106)** | arsenal_* (30), triangle_war_* (19), showdown_* (20), supremacy_war_* (14), duel_* (14), activity_auto_join_* (3), honor/cross_capital history, trap_start/auto_reserve/get_personal_score_reward, members_cheat_login | — | responde só `code:0` (schema-válido; listas vazias/zeros). São módulos de guerra/evento = GAP principal |

## Handlers — CHAT (51)
| Grupo | Msgs | Observação |
|---|---|---|
| Token | get_token | `code 0, rtmcode 0, token "mock-rtm-local"` (estável = notify_chat_init do seed) |
| Envio | send_alliance, send_alliance_r4 (R4+ senão 1846), send_kingdom, cross_capital_send_kingdom, send_room, send_p2p (bloqueio→1801, nível de estranho→1819), send_to_uids (beblocklist), send_to_self, share_to_chat | valida msg vazia (1812)/tamanho; sem aliança → 1510; devolve `mid` único, `rtmcode 0`, eco da `msg`; ring buffer de 200/sala em `social.chat`. **Não há push de mensagem**: o schema s2c não tem `notify_chat_msg` (mensagens vão por RTM externo) |
| Privacidade | block/unblock/temporary_block (1803/1804), ban_stranger, set_stranger_lv_limit, check_p2p_limit, set_show_self_skin (1847), set_recent_contact, set_p2p_history_del_ts | estado em `social` |
| Marcas | add/remove_unread_mark, set_read_mark, at, clean_at, set_reddot_ts, login_room | estado em `social` |
| Consulta | players_info_by_key (próprio + membros da aliança), translate (eco `[lang] texto` — sintético), translate_feedback, withdraw (só autor, ≤120 s) | — |
| **Grupos (group_*, 22)** | create/detail/add_member/del_member/quit/agree/disagree/modify_name/change_owner/invite_review/notice(+history/del)/vote_* (add/records/detail/select/finish/delete/top) | estado real em `social.groups`; pushes `notify_chat_group_join/leave/owner/modify_name/update/disbanded/vote_update`; limites e erros reais (10951/10953/10954/10955/10960/…) |

Não existem `req_chat_history/list/channels` no schema (histórico vem do RTM) → nada a fazer; o histórico local só alimenta withdraw.

## Gaps / riscos
1. 106 stubs de guerra/evento (arsenal, triangle, showdown, supremacy, duel, auto-join): só `code:0`; o cliente abre as telas vazias.
2. Só uma aliança "real" (a do seed); as outras são sintéticas e não persistem; entrar/criar reaproveita o mesmo registro.
3. Moeda premium = item 101 (assumido) e `donate_cost` usa ids 102–105, **ausentes no saldo do seed** → doação cai em 51 até o operador dar recurso (`account.grant`) ou usar `KS_SOCIAL_FREE=1`.
4. Regras inferidas (não achadas em cfg): pontos por doação, glória de ajuda, limites de lista, recompensa de dev_get_daily.
5. Validação = schema + round-trip + cenários em fake session; **não** testado ao vivo contra o cliente/mock (mock_v4 intocado). O contrato diz `session.account`; o mock tem `session.acct` — ambos suportados.
6. `account.social` entra no save JSON da conta (campos extras são recarregados por `from_dict`; ok).
