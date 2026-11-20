# Tabela dos grupos de protocolo (gerada dos schemas reais)

Legenda: `id` **nome** (dir) → `{request}` ⇒ `{response}`; `notify_*`: corpo `{campos}`. `*`=array; tipos nomeados são structs do schema; `…+N` = campos omitidos.


### G01 — Login / autenticação  _(gateway)_

- `1` **loginauth** (C→S) → {sdkToken:string, account:string, serverid:integer, version:string, uid:integer, is_create:boolean, group:integer, …+15} ⇒ {code:integer, serverid:integer, block_endtime:integer, uid:integer, is_new:boolean, is_first_role:boolean, role_list:*role_info, …+13}
- `21` **req_loaddata** (C→S) → {∅} ⇒ {code:integer}
- `33` **notify_game_init** (S→C) ⇒ {project_start_ts:integer, servertime:integer, utc_offset:integer, open_time:integer, zero_time:integer, logout_ts:integer, warzone_offset_ts:integer, …+1}
- **Servidor PRECISA validar:** sdkToken/account validados contra o IdP (nunca confiar em `uid` do cliente); `version` checada (gate de versão); `is_create` só com serverid válido; `inner_permission_*` e `group=0 (debug)` **recusados em produção**; nonce+timestamp anti-replay (o original reaproveita token entre conexões); resposta devolve `secret_key`+`crypt_method` (ver G03).

### G02 — Heartbeat / relógio  _(gateway)_

- `22` **req_heartbeat** (C→S) → {∅} ⇒ {time:integer}
- `8504` **req_update_4_new_day** (C→S) → {∅} ⇒ {code:integer}
- **Servidor PRECISA validar:** Resposta `time` = relógio do servidor (única fonte de tempo para cooldowns). Timeout de ociosidade (~3x o intervalo de 3–4 s observado); rate-limit; nunca aceitar timestamp do cliente.

### G03 — Cifra de sessão  _(gateway)_

- `1` **loginauth** (C→S) → {sdkToken:string, account:string, serverid:integer, version:string, uid:integer, is_create:boolean, group:integer, …+15} ⇒ {code:integer, serverid:integer, block_endtime:integer, uid:integer, is_new:boolean, is_first_role:boolean, role_list:*role_info, …+13}
- `30841` **req_report_userkey** (C→S) → {∅} ⇒ {code:integer, userkey:string, gen_ts:integer}
- **Servidor PRECISA validar:** `secret_key`(binary,tag17)+`crypt_method`(tag18: nil/1=XOR/2=RC4) vêm na resposta do login; `package.ud{crypt_method,crypt_length}` marca corpos cifrados. Gerar chave **aleatória por sessão** (CSPRNG, >=16 B) e preferir AEAD; o XOR de 4 B periódico original é só ofuscação (recuperável por crib).

### G04 — Anti-abuse / risco  _(gateway)_

- `13823` **req_dun163_risk_check** (C→S) → {token:string} ⇒ {code:integer, sdk_resp_data:string}
- `3613` **req_settings_set_device** (C→S) → {params:*string} ⇒ {code:integer, ver:string}
- `30841` **req_report_userkey** (C→S) → {∅} ⇒ {code:integer, userkey:string, gen_ts:integer}
- **Servidor PRECISA validar:** `token` do SDK de risco (NetEase Yidun) validado server-to-server; `sdk_resp_data` devolvido. Fingerprint de dispositivo só como sinal, nunca autorização; limite de contas por dispositivo.

### G05 — Conta: exclusão / reinos  _(conta)_

- `23` **req_del_account_pre_review** (C→S) → {info:info} ⇒ {code:integer, del_account_ts:integer}
- `24` **req_del_account** (C→S) → {∅} ⇒ {code:integer}
- `25` **req_del_account_cancel_pre_review** (C→S) → {∅} ⇒ {code:integer}
- `3601` **req_server_list** (C→S) → {∅} ⇒ {list:*server_info, code:integer, star_kid:integer}
- `16052` **req_delete_role_delete_role** (C→S) → {uid:integer} ⇒ {code:integer}
- **Servidor PRECISA validar:** Exclusão com janela de espera controlada pelo servidor (`del_account_ts`); reautenticação antes de `req_del_account`; auditoria; lista de reinos filtrada por região/versão.

### G06 — Perfil do jogador  _(jogador)_

- `1029` **req_players_base_info_with_permission** (C→S) → {uids:*integer, permission:integer} ⇒ {code:integer, result:*player_base, overload:integer}
- `1023` **req_players_base_info** (C→S) → {uids:*integer} ⇒ {code:integer, result:*player_base, overload:integer}
- `1021` **req_player_detail_info** (C→S) → {uid:integer} ⇒ {code:integer, result:player_detail}
- `1003` **req_player_modify_name** (C→S) → {name:string, use_diamond:boolean} ⇒ {code:integer, result:base_info}
- `1004` **req_player_check_name** (C→S) → {name:string} ⇒ {code:integer}
- `1005` **req_player_modify_image** (C→S) → {id:integer} ⇒ {code:integer, result:base_info}
- `1010` **notify_base_info** (S→C) ⇒ {nickName:string, lv:integer, exp:integer, uid:integer, power:integer, kid:integer, modify_name:boolean, …+31}
- `1012` **notify_player_level_up** (S→C) ⇒ {data:base_info}
- **Servidor PRECISA validar:** `uids[]` com teto de tamanho (consulta em lote = vetor de scraping); `permission` verificada por relação (amigo/aliança); nome: filtro de palavras + unicidade + custo/cooldown; imagens só entre as possuídas.

### G07 — Estado inicial (push pós-login)  _(gateway)_

- `33` **notify_game_init** (S→C) ⇒ {project_start_ts:integer, servertime:integer, utc_offset:integer, open_time:integer, zero_time:integer, logout_ts:integer, warzone_offset_ts:integer, …+1}
- `1301` **notify_resource_init** (S→C) ⇒ {data:*item_long}
- `1101` **notify_backpack_init** (S→C) ⇒ {data:*item_long}
- `1801` **notify_hero_init** (S→C) ⇒ {data:*hero}
- `8651` **notify_equipment_info** (S→C) ⇒ {equip_detail:*equip_detail_info, equip_common:*equip_common}
- `2950` **notify_queue_info** (S→C) ⇒ {queue_map:*queue}
- `3607` **notify_unlock_module_info** (S→C) ⇒ {module_unlocked:*integer}
- `3603` **notify_setting_info** (S→C) ⇒ {data:*set_info, notify:*notify_info, game_notice_id:integer, truck_fliter_my_kid:boolean, truck_enemy_fliter_my_kid:boolean}
- **Servidor PRECISA validar:** Rajada de ~50 `notify_*_init` em ~35 ms após `req_loaddata`(21): enviar só após login OK; montar do estado persistido; paginar/comprimir.

### G08 — Recursos / moedas  _(economia)_

- `1301` **notify_resource_init** (S→C) ⇒ {data:*item_long}
- `1302` **notify_resource_update** (S→C) ⇒ {type:string, data:*item_long}
- `1901` **notify_produced_resource_init** (S→C) ⇒ {data:*produced_resource}
- `1503` **req_get_hang_up_reward** (C→S) → {∅} ⇒ {code:integer, hang_start_time:integer, current_reward:*hungs_awards, expert_reward:*item}
- **Servidor PRECISA validar:** Saldo só no servidor; débito+crédito atômicos; produção offline = f(tempo servidor − última coleta) com teto de acúmulo; `notify_resource_update` é delta autoritativo.

### G09 — Inventário / itens  _(economia)_

- `1101` **notify_backpack_init** (S→C) ⇒ {data:*item_long}
- `1102` **notify_backpack_update** (S→C) ⇒ {type:string, data:*item_long}
- `1103` **req_use_item** (C→S) → {id:integer, count:integer, extra:use_item_extra} ⇒ {code:integer, result:*use_item_result}
- `1103` **notify_backpack_auto_use** (S→C) ⇒ {use_id:integer, use_count:integer, use_result:*use_item_result, is_expire:boolean, expire_get_items:*pair_int_int}
- **Servidor PRECISA validar:** Validar posse e quantidade (0<count<=posse), requisito de nível/módulo, item usável; lote com teto; efeito e remoção na mesma transação; idempotência.

### G10 — Loja interna  _(economia)_

- `2002` **req_shop_info** (C→S) → {shop_id:integer} ⇒ {code:integer, info:shop}
- `2003` **req_shop_buy** (C→S) → {shop_id:integer, goods_id:integer, count:integer} ⇒ {code:integer, goods:goods, new_goods:goods}
- `2001` **req_shop_quick_buy** (C→S) → {id:integer, count:integer, use:boolean, extra:use_item_extra} ⇒ {code:integer, result:*use_item_result}
- `2004` **req_shop_refresh** (C→S) → {shop_id:integer} ⇒ {code:integer, info:shop}
- `2005` **req_shop_info_array** (C→S) → {arr_id:*integer} ⇒ {code:integer, map_info:*shop}
- `2051` **notify_shop_open** (S→C) ⇒ {shop_id:integer, info:shop}
- **Servidor PRECISA validar:** Preço/estoque/limite diário **da config do servidor**; ignorar preço do request; débito atômico; estoque por conta/janela com lock; refresh custa e tem cap; loja só se `notify_shop_open` ativa.

### G11 — Recarga / pagamento  _(pagamento)_

- `6705` **req_recharge_get_first_reward** (C→S) → {∅} ⇒ {code:integer, total_reward:*item, first_recharge_award:*boolean}
- `6706` **req_recharge_collect_accumulative_reward** (C→S) → {reward_id:integer} ⇒ {code:integer, accumulative_reward:*pair_int_bool, items:*pair_int_int, last_accumulative_reward_ts:integer}
- `6707` **req_recharge_by_voucher** (C→S) → {id:integer} ⇒ {code:integer}
- `6708` **req_recharge_by_token** (C→S) → {id:integer} ⇒ {code:integer}
- `6701` **notify_recharge_init** (S→C) ⇒ {list:*recharge_data, total_recharge_amount:integer, first_recharge_ts:integer, first_recharge_award:*boolean, total_recharge_diamond:integer, accumulative_reward:*pair_int_bool, last_accumulative_reward_ts:integer, …+2}
- `6704` **notify_recharge_fail** (S→C) ⇒ {gid:integer, code:integer}
- `1211` **req_cheat_recharge** (C→S) → {id:integer} ⇒ {code:integer}
- **Servidor PRECISA validar:** Não existe `req_verify_receipt` no gateway: compra real = SDK de pagamento→servidor (server-to-server, `throughCargo`). No seu jogo: criar `orderId` no servidor, validar recibo Google/Apple, idempotência por `purchaseToken`, comparar uid do pedido×sessão, entregar 1x e só então consumir. `by_voucher/by_token` = resgate de crédito: código de uso único, rate-limit, anti-brute-force. Marcos (1ª/acumulada) só pelo total persistido.

### G12 — Passes (BP) / pacotes  _(pagamento)_

- `9251` **req_battle_pass_collect_reward** (C→S) → {id:integer, reward_id:integer} ⇒ {code:integer, reward_type:integer, rewards:*item}
- `9252` **req_battle_pass_buy_score** (C→S) → {id:integer, score:integer} ⇒ {code:integer, bp_info:battle_pass}
- `9253` **req_battle_pass_collect_all_reward** (C→S) → {id:integer} ⇒ {code:integer, bp_info:battle_pass, rewards:*item}
- `9270` **notify_battle_pass_info** (S→C) ⇒ {bp_info:battle_pass}
- `9271` **notify_battle_pass_purchase** (S→C) ⇒ {bp_info:battle_pass, rewards:*item}
- `7431` **req_gift_buy_free_gift** (C→S) → {gift_id:integer} ⇒ {code:integer}
- `15752` **req_push_customize_item_free_buy** (C→S) → {id:integer, group_id:integer, select_rewards:*item} ⇒ {code:integer, group_info:push_customize_item_group_info}
- **Servidor PRECISA validar:** Elegibilidade por pontos/nível; trilha paga confirmada pelo pedido; `collect_all` itera só o que o servidor marca disponível; 'free gift' 1x/janela; compra de pontos debita atomicamente.

### G13 — VIP  _(economia)_

- `4651` **req_vip_get_daily_exp** (C→S) → {∅} ⇒ {code:integer, add_vip_exp:integer, continuous_login_day:integer, lv_up:boolean}
- `4652` **req_vip_get_daily_free_gift** (C→S) → {lv:integer} ⇒ {code:integer, rewards:*pair_int_int, get_daily_gift_ts:integer, uncollected_daily_gift:*pair_int_int}
- `16172` **req_vip_privilege_turntable_play** (C→S) → {nums:integer} ⇒ {code:integer, lottery_info:*vip_lottery_info, replace_grid_info:*pair_int_bool, reward:*item}
- `4603` **notify_vip_info** (S→C) ⇒ {vip_lv:integer, vip_exp:integer, vip_active_endtime:integer, get_daily_exp_ts:integer, get_daily_gift_ts:integer, uncollected_daily_gift:*pair_int_int, vip_init_time:integer, …+1}
- `4604` **notify_vip_update** (S→C) ⇒ {vip_lv:integer, vip_exp:integer, vip_active_endtime:integer, get_daily_exp_ts:integer, get_daily_gift_ts:integer, uncollected_daily_gift:*pair_int_int, vip_init_time:integer, …+1}
- **Servidor PRECISA validar:** VIP calculado por exp no servidor; `daily` uma vez por dia no fuso do servidor; roleta: RNG no servidor, custo antes do resultado.

### G14 — Mail  _(social)_

- `2514` **req_mail_type_info** (C→S) → {∅} ⇒ {code:integer}
- `2501` **req_mail_cover_list** (C→S) → {first_type:integer, beginidx:integer, endidx:integer} ⇒ {code:integer, coverlist:*mail_cover}
- `2508` **req_mail_detail_info** (C→S) → {mailid:integer, mailid_new:string} ⇒ {code:integer, detail_info:binary}
- `2510` **req_mail_read** (C→S) → {mailid:integer, mailid_new:string} ⇒ {code:integer}
- `2506` **req_mail_receive** (C→S) → {mailid:integer, mailid_new:string} ⇒ {code:integer, rewards:*item}
- `2509` **req_mail_delete** (C→S) → {mailid:integer, mailid_new:string} ⇒ {code:integer}
- `2523` **req_mail_onekey_read** (C→S) → {first_type:integer} ⇒ {code:integer, rewards:*item, readlist:*string}
- `2560` **notify_mail_type_info_syn** (S→C) ⇒ {infolist:*mail_type_info, del_mail_lst:*string}
- `2562` **notify_mail_important** (S→C) ⇒ {covers:*mail_cover}
- **Servidor PRECISA validar:** Só o dono acessa o mail; anexo `req_mail_receive` 1x (flag atômica) e expira; delete não perde anexo sem confirmação; share/forward assinados (anti-mail forjado); paginação + teto.

### G15 — Chat (envio)  _(social)_

- `3405` **req_chat_get_token** (C→S) → {∅} ⇒ {code:integer, rtmcode:integer, token:string}
- `3402` **req_chat_send_p2p** (C→S) → {to:integer, msg:string, attrs:string} ⇒ {code:integer, rtmcode:integer, mid:string, lv_limit:integer, msg:string}
- `3403` **req_chat_send_kingdom** (C→S) → {msg:string, attrs:string} ⇒ {code:integer, rtmcode:integer, mid:string, broadcast_ts:integer, msg:string}
- `3404` **req_chat_send_alliance** (C→S) → {msg:string, attrs:string} ⇒ {code:integer, rtmcode:integer, mid:string, msg:string}
- `3408` **req_chat_send_to_uids** (C→S) → {tos:*integer, msg:string, attrs:string} ⇒ {code:integer, rtmcode:integer, mid:string, beblocklist:*integer, lv_limit:*integer, msg:string}
- `3424` **req_chat_withdraw** (C→S) → {mid:string, xid:integer, x_type:integer} ⇒ {code:integer, rtmcode:integer, ex:string}
- `3416` **req_chat_translate** (C→S) → {target:string, source_text:string, mark:integer, mid:string, type:integer} ⇒ {code:integer, target_text:string, mark:integer, mid:string, origin:integer, source:string}
- **Servidor PRECISA validar:** Rate-limit por canal, filtro/mute (`block`,`temporary_block`), nível mínimo p/ estranho, pertencimento a aliança/reino, tamanho máx; `chat_get_token` emite credencial do provedor RTM (original: iLiveData).

### G16 — Chat de grupo  _(social)_

- `13551` **req_chat_group_create** (C→S) → {uid_arr:*integer} ⇒ {code:integer, group_id:integer, fail_uid_arr:*integer, group_overview:chat_group, fail_send_msg_info:*msg_result_info}
- `13552` **req_chat_group_add_member** (C→S) → {group_id:integer, uid_arr:*integer} ⇒ {code:integer, fail_uid_arr:*integer, fail_send_msg_info:*msg_result_info, invite_succ_uid_arr:*integer, invite_fail_uid_arr:*integer, invite_exist_uid_arr:*integer}
- `13553` **req_chat_group_del_member** (C→S) → {group_id:integer, uid_arr:*integer} ⇒ {code:integer, disbanded:boolean}
- `13559` **req_chat_group_change_group_owner** (C→S) → {group_id:integer, uid:integer} ⇒ {code:integer}
- `17571` **req_chat_group_vote_add** (C→S) → {group_id:integer, is_multi:boolean, title:string, options:*string, top:boolean, time:integer} ⇒ {code:integer}
- `13581` **notify_chat_group_info** (S→C) ⇒ {info:chat_group_info, group_overview:*chat_group}
- **Servidor PRECISA validar:** Só dono altera/expulsa; cap de membros/grupos; convites com aprovação; 1 voto por uid.

### G17 — Amigos  _(social)_

- `8102` **req_friend_add** (C→S) → {uid:integer} ⇒ {code:integer, lv_limit:integer}
- `8103` **req_friend_accept** (C→S) → {uids:*integer} ⇒ {code:integer, results:*friend_req_result}
- `8104` **req_friend_refuse** (C→S) → {uids:*integer} ⇒ {code:integer, results:*friend_req_result}
- `8105` **req_friend_del** (C→S) → {uid:integer} ⇒ {code:integer}
- `8130` **req_friend_set_alias** (C→S) → {uid:integer, alias:string, del:boolean} ⇒ {code:integer}
- `8101` **notify_friend_init** (S→C) ⇒ {friend_list:*integer, application_list:*integer, gift_receive_count:integer, gift_receive_lasttime:integer, gift_inbox:*friend_gift_info, gift_outbox:*friend_gift_info, apply_lv_limit:integer, …+1}
- `8111` **notify_friend_gift** (S→C) ⇒ {uid:integer, time:integer}
- **Servidor PRECISA validar:** Cap de lista/pendentes; limite de nível (`apply_lv_limit`); simetria atômica; presentes 1x/dia/par; alias filtrado.

### G18 — Aliança: criar / entrar  _(aliança)_

- `5101` **req_alliance_create** (C→S) → {name:string, flag:integer, flag_bg:integer, manifesto:string, language:integer, public:boolean} ⇒ {code:integer, player:user_alliance, alliance:alliance}
- `5115` **req_alliance_join** (C→S) → {aid:integer} ⇒ {code:integer, alliance:alliance, player:user_alliance, ban_time:integer}
- `5116` **req_alliance_apply_join** (C→S) → {aid:integer} ⇒ {code:integer, alliance:alliance, player:user_alliance, ban_time:integer}
- `5121` **req_alliance_quit** (C→S) → {∅} ⇒ {code:integer, player:user_alliance}
- `5127` **req_alliance_search_by_key** (C→S) → {key:string} ⇒ {code:integer, alliances:*alliance, aids:*integer}
- `5128` **req_alliance_search_init** (C→S) → {language:integer} ⇒ {code:integer, alliances:*alliance, aids:*integer}
- `5171` **notify_alliance_init** (S→C) ⇒ {player:user_alliance, alliance:alliance}
- **Servidor PRECISA validar:** Custo e nível para criar; unicidade `name/abbr` + filtro; cooldown pós-saída; condição de recrutamento checada no servidor; cap de membros; busca paginada.

### G19 — Aliança: gestão / cargos  _(aliança)_

- `5104` **req_alliance_modify_notice** (C→S) → {notice:string, open_like:boolean, top:boolean, star:boolean} ⇒ {code:integer}
- `5105` **req_alliance_modify_name** (C→S) → {name:string} ⇒ {code:integer, setting:alliance_setting}
- `5107` **req_alliance_modify_flag** (C→S) → {flag:integer, flag_bg:integer} ⇒ {code:integer}
- `5109` **req_alliance_modify_recruit_type** (C→S) → {public:boolean} ⇒ {code:integer}
- `5112` **req_alliance_dismiss** (C→S) → {∅} ⇒ {code:integer, player:user_alliance}
- `5118` **req_alliance_invite_member** (C→S) → {uid:integer} ⇒ {code:integer}
- `5123` **req_alliance_members** (C→S) → {aid:integer, kid:integer} ⇒ {code:integer, members:*alliance_member}
- `5124` **req_alliance_applys** (C→S) → {∅} ⇒ {code:integer, applys:*alliance_apply}
- **Servidor PRECISA validar:** ACL por `rank` (R1–R5) em **cada** mensagem; transferência de líder e dissolução com cooldown/confirmação; auditoria.

### G20 — Aliança: ciência / doação / ajuda  _(aliança)_

- `5203` **req_alliance_science_research** (C→S) → {id:integer} ⇒ {code:integer}
- `5204` **req_alliance_science_donate** (C→S) → {id:integer, level:integer} ⇒ {code:integer, multiple:integer, rank_data:rank_data}
- `5205` **req_alliance_science_diamond_donate** (C→S) → {id:integer} ⇒ {code:integer, multiple:integer, rank_data:rank_data}
- `5251` **req_alliance_help_all** (C→S) → {∅} ⇒ {code:integer, count:integer, rewards:*item, day_glory:integer}
- `5282` **notify_alliance_help_update** (S→C) ⇒ {type:integer, data:*help}
- `2954` **notify_queue_be_help** (S→C) ⇒ {queue:queue, uid:integer, name:string, help_num:integer, help_max:integer, extra:extra_data, auto_help:boolean}
- **Servidor PRECISA validar:** Doação: débito atômico + teto diário; ajuda: 1 por membro por fila, reduz tempo por regra do servidor, sem auto-ajuda; pesquisa exige permissão.

### G21 — Ranking  _(competição)_

- `3201` **req_rank_info** (C→S) → {list_type:*rank_type, kid:integer} ⇒ {code:integer, list_info:*rank_info}
- `3202` **req_rank_range** (C→S) → {type:integer, key:integer, ext:rank_ext, kid:integer} ⇒ {code:integer, list_data:*rank_data, data:rank_data, rank:integer}
- `5402` **req_alliance_rank_data** (C→S) → {type:integer, season:integer} ⇒ {code:integer, rank_list:*rank_data, join_info:*join_info}
- `5403` **req_alliance_rank_get_rewards** (C→S) → {type:integer} ⇒ {code:integer, rewards:*item}
- `8451` **req_arena_rank_range** (C→S) → {∅} ⇒ {list_data:*rank_data, data:rank_data, rank:integer, cross_groupid:integer, extra_map_data:*extra_data}
- **Servidor PRECISA validar:** Ranking calculado no servidor (job/ZSET); `range` com teto de janela (ex. <=100) e rate-limit; recompensa 1x/ciclo com snapshot do fim do período.

### G22 — Arena (PvP assíncrono)  _(competição)_

- `8453` **req_arena_refresh_opponent** (C→S) → {∅} ⇒ {code:integer, opponents:*arena_opponent, refresh_opponent_times:integer, refresh_opponent_ts:integer}
- `8460` **req_arena_get_opponent** (C→S) → {∅} ⇒ {code:integer, opponents:*arena_opponent}
- `8452` **req_arena_set_defence_heroes** (C→S) → {hero_array:*integer} ⇒ {code:integer}
- `8454` **req_arena_fight** (C→S) → {opponent_type:integer, opponent_id:integer, hero_array:*integer, report_id:integer, version:integer} ⇒ {code:integer, base:arena_base, report:arena_report, rank_old:integer, rank_new:integer, rewards:*item, battle_data:battle_troops_info, …+2}
- `8455` **req_arena_buy_challenge_times** (C→S) → {buy_times:integer} ⇒ {code:integer, base:arena_base}
- `8456` **req_arena_report** (C→S) → {∅} ⇒ {code:integer, reports:*arena_report}
- `8402` **notify_arena_report** (S→C) ⇒ {report:arena_report}
- **Servidor PRECISA validar:** Oponente escolhido pelo servidor; `fight` consome tentativa antes; defesa só com heróis possuídos; resultado **simulado no servidor** (seed do servidor) ou verificado; compra de tentativas com cap.

### G23 — Torre (PvE em fases)  _(fases)_

- `20461` **req_climbtower_info** (C→S) → {∅} ⇒ {code:integer, towers:*climbtower_tower_info, total_passed_cnt:integer, rewarded_chests:*integer}
- `20462` **req_climbtower_tower_info** (C→S) → {id:integer, chapter:integer} ⇒ {code:integer, levels:*climbtower_level_info}
- `20463` **req_climbtower_challenge** (C→S) → {id:integer, formation_prefab:*formation_build_pair} ⇒ {code:integer, is_win:boolean, first_reward:*item, normal_reward:*item, battle_result:climbtower_battle_result, formation_prefab:*formation_build_pair, expert_reward:*item, …+1}
- `20464` **req_climbtower_quick_challenge** (C→S) → {tower_id:integer} ⇒ {code:integer, cur_passed_level:integer, first_reward:*item, normal_reward:*item, expert_reward:*item, expert_effect_source:*expert_effect_source}
- `20465` **req_climbtower_sweep** (C→S) → {tower_id:integer} ⇒ {code:integer, cur_passed_level:integer, normal_reward:*item, expert_reward:*item, expert_effect_source:*expert_effect_source}
- `20467` **req_climbtower_chest_reward** (C→S) → {chest_id_list:*integer} ⇒ {code:integer, chest_id_list:*integer}
- `20466` **notify_climbtower_tower_update** (S→C) ⇒ {tower_info:climbtower_tower_info, total_passed_cnt:integer}
- `20474` **notify_climbtower_currency_update** (S→C) ⇒ {currency:integer}
- **Servidor PRECISA validar:** msg 20463 observada ~3,5 s/ação, resposta → push 20466+20474. Servidor: `id/chapter` desbloqueado, tentativa/estamina, `sweep/quick` só se já vencido; recompensa 1x; contador de ações crescente.

### G24 — Aventura PVE / auto-batalha  _(fases)_

- `2602` **req_battle_adventure_battle_result_error** (C→S) → {battle_data:battle_troops_info, client_version:integer, operatedata:operatedata, client_enddata:*pawn_status, server_enddata:*pawn_status, err_type:integer} ⇒ {code:integer}
- `1550` **notify_adventure_pve_info** (S→C) ⇒ {adventure_pve_info:adventure_pve_info}
- `1503` **req_get_hang_up_reward** (C→S) → {∅} ⇒ {code:integer, hang_start_time:integer, current_reward:*hungs_awards, expert_reward:*item}
- `10851` **notify_battle_hero_arrange_data** (S→C) ⇒ {hero_arranges:*hero_arrange}
- **Servidor PRECISA validar:** `pass_checkpoint` avança só pelo servidor; `battle_result_error` carrega `battle_data/operatedata/client_enddata/server_enddata/err_type` (1=HP difere, 2=resultado difere) = **o original já recompara cliente×servidor**: replicar como divergência→flag.

### G25 — Batalha: sincronização / reprodução  _(combate)_

- `2603` **req_battle_by_key** (C→S) → {key:string} ⇒ {code:integer, battle_data:battle_troops_info, operatedata:*operatedata, atk_win:boolean, pawn_status:*pawn_status, old_server_enddata:*pawn_status, old_client_enddata:*pawn_status}
- `2602` **req_battle_adventure_battle_result_error** (C→S) → {battle_data:battle_troops_info, client_version:integer, operatedata:operatedata, client_enddata:*pawn_status, server_enddata:*pawn_status, err_type:integer} ⇒ {code:integer}
- `10851` **notify_battle_hero_arrange_data** (S→C) ⇒ {hero_arranges:*hero_arrange}
- **Servidor PRECISA validar:** Armazenar `battle_data` + seed + `operatedata` (comandos); servidor re-simula e compara `enddata`; versão de simulação (`client_version`) fixa; replay por chave.

### G26 — TD (Tower Defense)  _(fases)_

- `16351` **req_td_event_start_stage** (C→S) → {∅} ⇒ {code:integer, start_stage_ts:integer, td_box:*td_box, td_survivor:*td_survivor}
- `16352` **req_td_event_settle_stage** (C→S) → {is_win:boolean, td_survivor:*integer} ⇒ {code:integer, reward:*item}
- `16354` **req_td_event_fast_challenge** (C→S) → {event_id:integer} ⇒ {code:integer, reward:*item}
- `16353` **req_td_event_get_survivor** (C→S) → {∅} ⇒ {code:integer, td_survivor:*td_survivor}
- `16452` **req_td_box_get** (C→S) → {box_id:integer} ⇒ {code:integer}
- `16451` **req_td_box_set_pos** (C→S) → {box_id:integer, pos:point} ⇒ {code:integer}
- `16381` **notify_td_event_info** (S→C) ⇒ {info:td_event, history_trigger:*pair_int_bool}
- `16384` **notify_td_event_over** (S→C) ⇒ {event_id:integer}
- **Servidor PRECISA validar:** `start_stage` cria token de tentativa; `settle_stage` exige token, duração plausível, resultado coerente; caixa: conteúdo decidido pelo servidor, abrir 1x; `fast_challenge` só após clear.

### G27 — Sobreviventes + snapshot do cliente  _(combate)_

- `3001` **req_save_client_data** (C→S) → {data:client_data} ⇒ {code:integer}
- `2807` **req_survivor_work_start** (C→S) → {sid:integer} ⇒ {code:integer, time:integer}
- `2808` **req_survivor_work_pause** (C→S) → {sid_list:*integer, time:integer} ⇒ {code:integer}
- `2803` **req_survivor_update_cure_end_time** (C→S) → {sid:integer, cure_end_time:integer} ⇒ {code:integer}
- `2804` **req_survivor_cure_finish** (C→S) → {sid:integer} ⇒ {code:integer, suc:boolean}
- `2818` **req_survivor_multi_send** (C→S) → {send_list:*pair_int_int} ⇒ {code:integer, fail_sids:*integer}
- `2814` **req_survivor_alloc_td** (C→S) → {∅} ⇒ {code:integer, num_map:*pair_int_int}
- `2851` **notify_survivor_info** (S→C) ⇒ {survivor_list:*survivor, riot_data:riot_data, guide_selected:boolean, td_survivor:*td_survivor, num_map:*pair_int_int, switch:integer}
- **Servidor PRECISA validar:** **3001 `req_save_client_data{data:client_data{law_point,survivor[sid,res601..607]}}`** (~2.5 KB, crypt_method=1, ~30 s): estado enviado pelo cliente. No clone: tratar como **hint**, clampar doubles a [0,100], limitar taxa de variação por tempo, nunca creditar recurso a partir dele; `cure_end_time` calculado no servidor.

### G28 — Heróis  _(progressão)_

- `1811` **req_hero_upgrade** (C→S) → {id:integer, lev:integer} ⇒ {code:integer, result:hero}
- `1812` **req_hero_promote_star** (C→S) → {id:integer} ⇒ {code:integer, result:hero}
- `1816` **req_hero_upgrade_skill** (C→S) → {id:integer, skillid:integer} ⇒ {code:integer, result:hero}
- `1814` **req_hero_debris_exchange** (C→S) → {id:integer, count:integer} ⇒ {code:integer}
- `4701` **req_hero_search_times** (C→S) → {search_type:integer, cost_type:integer, times:integer} ⇒ {code:integer, hero_change_map:*hero_change_map, search_time:*search_time, reward_before_change:*item, sort_reward:*hero_search_show_reward, free_search_times:integer}
- `1802` **notify_hero_update** (S→C) ⇒ {data:hero, fragment_num:integer}
- `4703` **notify_hero_search_data** (S→C) ⇒ {free_search_times:integer, total_score:integer, search_time:*search_time, high_lev_first_rearch:boolean, epic_first_rearch:boolean}
- **Servidor PRECISA validar:** Custo/nível máx/fragmentos da config; gacha: RNG servidor + pity persistido; `search_times` cobra antes de sortear; lote limitado.

### G29 — Equipamento / skin  _(progressão)_

- `8601` **req_wear_equipment** (C→S) → {equip_info:equip_info} ⇒ {code:integer, uid:integer}
- `8608` **req_equipment_strength_recast** (C→S) → {uid:integer} ⇒ {code:integer, ret_item:*item}
- `8611` **req_equipment_break** (C→S) → {uid:integer, cost_item:equip_item} ⇒ {code:integer, ret_item:*item}
- `8612` **req_equipment_temper** (C→S) → {uid:integer, cost_item:equip_item} ⇒ {code:integer, ret_item:*item}
- `8701` **req_skin_equip** (C→S) → {id:integer} ⇒ {code:integer, expire_ts:integer}
- `8652` **notify_equipment_update** (S→C) ⇒ {equip_common:*equip_common, equip_detail_change:*equip_detail_change}
- **Servidor PRECISA validar:** Posse + slot compatível; recast: custo antes do RNG, resultado aplicado só pelo servidor; skin: possui/ativa.

### G30 — Pets  _(progressão)_

- `15321` **req_pet_upgrade** (C→S) → {id:integer, upgrade_lv:integer} ⇒ {code:integer, lv:integer}
- `15330` **req_pet_get_upgrade_initial_item** (C→S) → {∅} ⇒ {code:integer, reward:*item}
- `15351` **notify_pet_info** (S→C) ⇒ {info:*pet}
- `15352` **notify_pet_update** (S→C) ⇒ {info:pet}
- **Servidor PRECISA validar:** Idem heróis: custo e cap do servidor; itens iniciais 1x.

### G31 — Cidade / construção  _(cidade)_

- `2702` **req_upgrade_building** (C→S) → {bid:integer, use_diamond:boolean, qid:integer} ⇒ {code:integer, qid:integer, expert_reduce_time:integer}
- `2703` **req_upgrade_furniture** (C→S) → {bid:integer, conf_fid:integer, add_lv:integer} ⇒ {code:integer, lv:integer}
- `2708` **req_upgrade_building_cancel** (C→S) → {bid:integer} ⇒ {code:integer}
- `2902` **req_building_queue_speed** (C→S) → {qid:integer, use_diamond:boolean, items:*item} ⇒ {code:integer, give_change:*pair_int_int}
- `2751` **notify_building_upgrade_finish** (S→C) ⇒ {bid:integer, lv:integer, furniture_list:*furniture, mode:integer}
- `2752` **notify_stove_info** (S→C) ⇒ {switch:integer, overdrive:integer}
- **Servidor PRECISA validar:** Requisitos (pré-construção, `stove_lv`), custo, fila livre; término = start+duração no relógio do servidor; speedup consome itens e não excede tempo restante; cancelar reembolsa só %.

### G32 — Filas / aceleração  _(cidade)_

- `2901` **req_purchase_queue_time** (C→S) → {qid:integer, use_diamond:boolean, count:integer} ⇒ {code:integer, purchased_endtime:integer}
- `2903` **req_queue_ask_for_help** (C→S) → {qid:integer} ⇒ {code:integer, finish:boolean, help_num:integer, help_max:integer}
- `2953` **notify_queue_update** (S→C) ⇒ {queue_map:*queue}
- `2952` **notify_queue_timeout** (S→C) ⇒ {qid:integer}
- `2955` **notify_queue_cancel** (S→C) ⇒ {qid:integer}
- **Servidor PRECISA validar:** Fila é entidade do servidor (qid,status,endtime); compra de fila extra com custo; pedidos de ajuda com limite.

### G33 — Tropas: treino / hospital  _(cidade)_

- `2251` **req_barrack_train_soldier** (C→S) → {soldier_id:integer, soldier_num:integer, immediate:boolean} ⇒ {code:integer, barrack:barrack_data}
- `2252` **req_barrack_recruit_soldier** (C→S) → {arr_bid:*integer} ⇒ {code:integer, map_result:*barrack_recruit_result}
- `2253` **req_barrack_upgrade_soldier** (C→S) → {soldier_id:integer, soldier_num:integer, immediate:boolean} ⇒ {code:integer, barrack:barrack_data}
- `2254` **req_barrack_speed_up** (C→S) → {bid:integer, use_diamond:boolean, items:*item} ⇒ {code:integer, give_change:*pair_int_int}
- `2351` **req_hospital_heal_soldier** (C→S) → {soldiers:*pair_int_int, immediate:boolean} ⇒ {code:integer, heal_data:heal_data, wound_soldiers:*pair_int_int}
- `2354` **req_hospital_wound_dismiss** (C→S) → {id:integer, count:integer} ⇒ {code:integer, wound_soldiers:*pair_int_int}
- **Servidor PRECISA validar:** Capacidade do quartel, recursos, ordem de promoção; `recruit` só após `endtime`; cura limitada ao nº de feridos persistidos.

### G34 — Pesquisa  _(cidade)_

- `12701` **req_spar_science_begin_research** (C→S) → {tid_lev:integer, qid:integer} ⇒ {code:integer, researchinfo:researchinginfo}
- `12702` **req_spar_science_research_complete_immediately** (C→S) → {tid_lev:integer} ⇒ {code:integer}
- `12704` **req_spar_science_research_speed_up** (C→S) → {tid_lev:integer, use_diamond:boolean, items:*item} ⇒ {code:integer, give_change:*pair_int_int}
- `12731` **notify_spar_science_all_research** (S→C) ⇒ {researched:*researched, researching:*researching}
- **Servidor PRECISA validar:** Pré-requisito, custo, 1 pesquisa por fila; `complete_immediately` custo proporcional ao tempo restante calculado no servidor.

### G35 — Mundo / mapa  _(mundo)_

- `5601` **req_world_map_info** (C→S) → {args:*world_map_info_args, session:integer, fulldata:boolean, lod:integer} ⇒ {code:integer}
- `5617` **req_world_mapobj** (C→S) → {kid:integer, point:point} ⇒ {code:integer, mapobj:world_mapobj}
- `5615` **req_world_map_search** (C→S) → {mapobj_type:integer, level_min:integer, level_max:integer, res_id:integer, is_full:boolean} ⇒ {code:integer, point:point, is_create:boolean}
- `5604` **req_world_move_city** (C→S) → {point:point} ⇒ {code:integer, point:point}
- `5602` **req_world_random_move_city** (C→S) → {∅} ⇒ {code:integer, point:point}
- `5607` **req_world_resource_info** (C→S) → {point:point, kid:integer} ⇒ {code:integer, res_count:integer, collect_begin_time:integer, collect_speed:integer, collect_speed_add:integer, collect_finish_time:integer, collect_buff_info:*buff_info, …+1}
- `5651` **notify_world_player_init** (S→C) ⇒ {city_point:point, march_info:*world_march, mass_master_marchs:*world_march, kingdom_count:integer, world_extra_march:world_extra_march, is_respawned:boolean, war_ban_endtime:integer, …+5}
- **Servidor PRECISA validar:** Visibilidade por região (só enviar o que o jogador pode ver — vazamento de mapa); `move_city`: coordenada livre, item/cooldown, não em guerra.

### G36 — Marchas  _(mundo)_

- `5701` **req_world_march** (C→S) → {type:integer, endpoint:point, formation:formation_build, extra:extra} ⇒ {code:integer, march_info:world_march}
- `5702` **req_world_march_recall** (C→S) → {id:integer, itemid:integer} ⇒ {code:integer}
- `5703` **req_world_march_speedup** (C→S) → {id:integer, itemid:integer, owner:integer} ⇒ {code:integer, endtime:integer}
- `5709` **req_world_march_detail** (C→S) → {owner:integer, id:integer, kid:integer} ⇒ {code:integer, detail:world_march_detail}
- `5751` **notify_world_marchs** (S→C) ⇒ {session:integer, datalist:*world_march, end_flag:boolean, kid:integer, dellist:*world_march}
- `5752` **notify_world_march_add** (S→C) ⇒ {march:world_march, kid:integer}
- `5753` **notify_world_march_update** (S→C) ⇒ {id:integer, owner:integer, type:integer, change:world_march, kid:integer, del:world_march_del_keys}
- `5754` **notify_world_march_del** (S→C) ⇒ {id:integer, owner:integer, type:integer, kid:integer}
- **Servidor PRECISA validar:** Alvo válido/alcançável, tropas <= posse e <= capacidade, herói não duplicado; ETA calculado no servidor; combate resolvido no servidor; push só para quem vê a marcha.

### G37 — Missões / conquistas  _(progressão)_

- `4303` **notify_quests** (S→C) ⇒ {quests:*quest, finishs:*finishs}
- `4501` **req_get_growthquest_award** (C→S) → {questid:integer} ⇒ {code:integer, next_quest_list:*integer}
- `4401` **req_get_dailyquest_award** (C→S) → {questid:integer} ⇒ {code:integer, integral:integer, geted_boxid:*integer, expert_effect_map:*expert_effect_source}
- `4405` **req_get_all_dailyquest_award** (C→S) → {quest_ids:*integer} ⇒ {code:integer, integral:integer, geted_boxid:*integer, expert_effect_map:*expert_effect_source}
- `3901` **req_get_chapter_award** (C→S) → {chapterid:integer} ⇒ {code:integer}
- `30440` **req_get_expert_quest_award** (C→S) → {quest_id:integer} ⇒ {code:integer}
- `4502` **notify_growthquests** (S→C) ⇒ {quests:*quest, finishs:*finishs}
- **Servidor PRECISA validar:** Progresso só atualizado por eventos do servidor; `award` 1x, só se `progress>=alvo`; `all_award` itera estado do servidor.

### G38 — Check-in / recompensas periódicas  _(engajamento)_

- `15301` **req_sign_21day_get_reward** (C→S) → {day:integer} ⇒ {code:integer}
- `15302` **req_sign_21day_get_all_reward** (C→S) → {∅} ⇒ {code:integer, rewards:*item}
- `16132` **req_sign_draw_lottery** (C→S) → {id:integer, nums:integer} ⇒ {code:integer, ret_rewards:*sign_draw_reward}
- `9101` **req_receive_online_reward** (C→S) → {∅} ⇒ {code:integer, online_reward:*item, receive_start_time:integer}
- `15521` **req_get_personal_7days_reward** (C→S) → {questid:integer} ⇒ {code:integer, score:integer}
- `9111` **notify_reward_info** (S→C) ⇒ {online_reward:online_reward, spec_reward:spec_reward, bank:bank}
- **Servidor PRECISA validar:** Dia/fuso do servidor, 1x/dia, sem 'recuperar' dias sem compra; online reward por tempo acumulado de sessão do servidor.

### G39 — Eventos de atividade  _(engajamento)_

- `11401` **req_get_active_recharge_quest_reward** (C→S) → {id:integer, questid:integer} ⇒ {code:integer, score:integer}
- `12921` **req_daily_task_activity_get_task_reward** (C→S) → {id:integer, task_id:integer} ⇒ {code:integer}
- `9952` **req_continuous_recharge_reward** (C→S) → {id:integer, round:integer} ⇒ {code:integer}
- `15531` **notify_personal_7days_init** (S→C) ⇒ {fs_info:personal_7days}
- `9502` **notify_fund_info** (S→C) ⇒ {fund_list:*fund}
- **Servidor PRECISA validar:** Janela da atividade (`start/end_ts`) do servidor; score/ticket persistidos; recompensa 1x por marco.

### G40 — Gacha / roleta  _(engajamento)_

- `4701` **req_hero_search_times** (C→S) → {search_type:integer, cost_type:integer, times:integer} ⇒ {code:integer, hero_change_map:*hero_change_map, search_time:*search_time, reward_before_change:*item, sort_reward:*hero_search_show_reward, free_search_times:integer}
- `10351` **req_hero_turntable_play** (C→S) → {id:integer, count:integer, use_diamond:boolean} ⇒ {code:integer, slotid_list:*integer, reward:*slot_reward}
- `16172` **req_vip_privilege_turntable_play** (C→S) → {nums:integer} ⇒ {code:integer, lottery_info:*vip_lottery_info, replace_grid_info:*pair_int_bool, reward:*item}
- `16132` **req_sign_draw_lottery** (C→S) → {id:integer, nums:integer} ⇒ {code:integer, ret_rewards:*sign_draw_reward}
- `10352` **req_hero_turntable_extra_reward** (C→S) → {id:integer, times:integer} ⇒ {code:integer}
- **Servidor PRECISA validar:** Probabilidades e pity só no servidor; débito antes do sorteio; tabela de drop auditável (lojas exigem publicar taxas).

### G41 — Guerra de aliança (arsenal/supremacy/triangle)  _(guerra)_

- `11103` **req_arsenal_war_march** (C→S) → {type:integer, endpoint:point, formation:formation_build, extra:extra} ⇒ {code:integer, march_info:world_march}
- `17303` **req_arsenal_league_march** (C→S) → {type:integer, endpoint:point, formation:formation_build, extra:extra} ⇒ {code:integer, march_info:world_march}
- `15985` **req_triangle_war_march_move** (C→S) → {id:integer, path:*integer} ⇒ {code:integer, path:*integer}
- `16001` **req_triangle_war_heartbeat** (C→S) → {∅} ⇒ {warzone_ts:integer}
- `16034` **notify_triangle_war_player_init** (S→C) ⇒ {player_state:integer, quit_warzone_cd:integer, endtime:integer, chat_room_id:integer, main_chat_room_id:integer}
- **Servidor PRECISA validar:** Instância de guerra com estado autoritativo (HP/posse de prédios); janela de inscrição; ações ordenadas por tick do servidor; `triangle_war_heartbeat 16001` = heartbeat por instância.

### G42 — Espectador / heartbeat de instância  _(guerra)_

- `51` **req_spectator_agent_heartbeat** (C→S) → {∅} ⇒ {time:integer}
- `52` **req_spectator_agent_auth** (C→S) → {uid:integer, serverid:integer, token:string} ⇒ {code:integer, time:integer}
- `16001` **req_triangle_war_heartbeat** (C→S) → {∅} ⇒ {warzone_ts:integer}
- **Servidor PRECISA validar:** Agente espectador autentica separado e é read-only; heartbeat próprio com timeout para limpar assinaturas.

### G43 — Red packet  _(social)_

- `20511` **req_red_packet_send** (C→S) → {info:send_info} ⇒ {code:integer, id:integer, index:string, world_index:string}
- `20513` **req_red_packet_get** (C→S) → {channel_type:integer, id:integer, index:string} ⇒ {code:integer, reward:*item}
- `20515` **req_red_packet_get_detail** (C→S) → {channel_type:integer, id:integer, index:string} ⇒ {code:integer, info:*get_info}
- `20517` **req_red_packet_exist** (C→S) → {channel_type:integer, id_lst:*integer} ⇒ {code:integer, is_exist:boolean}
- **Servidor PRECISA validar:** Envio debita primeiro; `get` atômico (valor sorteado no servidor, 1x/uid); expiração e reembolso do resto.

### G44 — Upload de imagem / UGC  _(social)_

- `8326` **req_upload_image_erase** (C→S) → {∅} ⇒ {code:integer, state:integer}
- `8327` **req_get_hd_image** (C→S) → {uid:integer} ⇒ {code:integer, visible:boolean, check_image:string}
- `1014` **notify_player_upload_image** (S→C) ⇒ {upload_image:string, check_image:string}
- `8301` **notify_upload_image_init** (S→C) ⇒ {image_under_review:string, lasttime:integer, state:integer, block_endtime:integer, reduce_cd:boolean, token:string, check_image:string, …+2}
- **Servidor PRECISA validar:** Moderação (hash/classificador), tamanho/MIME, URL assinada de curta duração, rate-limit.

### G45 — Setup / tutorial / questionário  _(engajamento)_

- `8001` **req_guide_set_step** (C→S) → {id:integer, step:integer} ⇒ {code:integer}
- `3604` **req_update_setting_info** (C→S) → {data:*set_info} ⇒ {code:integer}
- `9201` **req_questionnaire_writed** (C→S) → {id:integer} ⇒ {code:integer}
- `9202` **req_questionnaire_get_reward** (C→S) → {id:integer} ⇒ {code:integer}
- `3613` **req_settings_set_device** (C→S) → {params:*string} ⇒ {code:integer, ver:string}
- `3603` **notify_setting_info** (S→C) ⇒ {data:*set_info, notify:*notify_info, game_notice_id:integer, truck_fliter_my_kid:boolean, truck_enemy_fliter_my_kid:boolean}
- **Servidor PRECISA validar:** `guide_set_step` monotônico; settings = whitelist de chaves com teto de tamanho; recompensa de questionário 1x.

### G46 — Polling leve (client-driven)  _(gateway)_

- `8501` **req_trigger_opinion** (C→S) → {type:integer, sid:integer, content_id:integer, choice_id:integer, is_anonymity:boolean} ⇒ {code:integer}
- `2518` **req_update_read_time** (C→S) → {first_type:integer} ⇒ {code:integer}
- `20959` **req_update_find_goods_server_time** (C→S) → {sign:integer} ⇒ {time:integer}
- `2810` **req_survivor_update_riot_detect_time** (C→S) → {time:integer} ⇒ {code:integer}
- **Servidor PRECISA validar:** Capturado: 8501 a cada ~14 s (resposta push 8552), 2803/2807 com timestamp. Rate-limit; resposta traz server time; nunca confiar no timestamp enviado.

### G47 — Push genérico notify_* (S→C sem session)  _(gateway)_

- `1102` **notify_backpack_update** (S→C) ⇒ {type:string, data:*item_long}
- `1302` **notify_resource_update** (S→C) ⇒ {type:string, data:*item_long}
- `2953` **notify_queue_update** (S→C) ⇒ {queue_map:*queue}
- `2560` **notify_mail_type_info_syn** (S→C) ⇒ {infolist:*mail_type_info, del_mail_lst:*string}
- `5753` **notify_world_march_update** (S→C) ⇒ {id:integer, owner:integer, type:integer, change:world_march, kid:integer, del:world_march_del_keys}
- `3421` **notify_chat_new_at** (S→C) ⇒ {data:chat_at, room_id:integer, type:integer}
- **Servidor PRECISA validar:** Push = `type` sem `session`. Ordem por conexão; entregar apenas ao dono/assinantes; ao reconectar re-enviar snapshot (sem replay de deltas antigos); fila limitada com backpressure.

### G48 — Notificações de compra/BP  _(pagamento)_

- `9271` **notify_battle_pass_purchase** (S→C) ⇒ {bp_info:battle_pass, rewards:*item}
- `15482` **notify_general_bp_purchase** (S→C) ⇒ {id:integer, type:integer, rewards:*item}
- `30832` **notify_hero_growth_bp_purchase** (S→C) ⇒ {id:integer, type:integer}
- `15312` **notify_sign_21day_purchase** (S→C) ⇒ {∅}
- `6704` **notify_recharge_fail** (S→C) ⇒ {gid:integer, code:integer}
- **Servidor PRECISA validar:** O servidor emite estes pushes **após** confirmar o recibo; o cliente nunca os dispara.

### G49 — Cheat / GM (OBRIGATÓRIO desabilitar)  _(segurança)_

- `1201` **req_cheat_add** (C→S) → {data:*item} ⇒ {code:integer}
- `1202` **req_cheat_reduce** (C→S) → {data:*item} ⇒ {code:integer}
- `1211` **req_cheat_recharge** (C→S) → {id:integer} ⇒ {code:integer}
- `1223` **req_cheat_change_sys_time** (C→S) → {time:integer} ⇒ {code:integer}
- `1221` **req_cheat_finish_chapter** (C→S) → {id:integer} ⇒ {code:integer}
- `1204` **req_cheat_echo** (C→S) → {payload:string} ⇒ {payload:string}
- **Servidor PRECISA validar:** **287 mensagens `req_cheat_*` (ids 1201–14xxx) existem no schema de produção** (adicionar itens, mudar hora do sistema, recarga grátis). No clone: nenhum handler em prod; ACL por build flag/`inner_permission`; log e ban em tentativa.

### G50 — Config / versão / módulos  _(gateway)_

- `1` **loginauth** (C→S) → {sdkToken:string, account:string, serverid:integer, version:string, uid:integer, is_create:boolean, group:integer, …+15} ⇒ {code:integer, serverid:integer, block_endtime:integer, uid:integer, is_new:boolean, is_first_role:boolean, role_list:*role_info, …+13}
- `3601` **req_server_list** (C→S) → {∅} ⇒ {list:*server_info, code:integer, star_kid:integer}
- `3653` **notify_setting_gm_mark** (S→C) ⇒ {gm_mark:*string}
- `3607` **notify_unlock_module_info** (S→C) ⇒ {module_unlocked:*integer}
- **Servidor PRECISA validar:** `version_info{appVersion,resVersion}` na resposta do login força update/hotfix; módulos liberados (`module_unlocked[]`) checados em cada handler, não só na UI.
