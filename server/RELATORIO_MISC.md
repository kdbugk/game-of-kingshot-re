# RELATORIO_MISC - LANE EXT-MISC (findinggame + 3 modulos do ranking)

Entregues (nada escrito no repo, `mock_v4.py` intocado): `ext_findinggame.py`, `ext_misc.py`, `extkit.py` (utilitarios
compartilhados, NAO e um ext_*: sem HANDLERS), `test_ext_misc.py`, este relatorio.
Teste: `python test_ext_misc.py` -> **N_ok/N = 272/272** (116 handlers x 2 sessoes [compartilhada e nova] com fixture
de `protocols/fixtures_all.json`, resposta/push codificados e decodificados via `sproto_lib` (round-trip: tudo que o
handler enviou reaparece), 0 excecoes engolidas, + 40 checagens de fluxo/regra).

## 1. Contrato
`HANDLERS = {"req_x": fun}`; `fun(session, m)` usa `session.reply(m,obj)`, `session.push(nome,obj)`, `session.account`
(fallback `session.acct`, nome real no mock_v4), `session.now()`, `session.replay` (ReplayRegistry). Todo handler e
embrulhado por `extkit.handler`: excecao -> `code:2` (param_illegal) e vai para `extkit.ERRORS` (o teste exige vazio).
Mensagens sem `response` no proto nao respondem; as fora do schema (so no MSGMAP) tambem nao.

## 2. Modulo FINDINGGAME (`ext_findinggame.py`, 36 handlers = todo `req_*find_goods*` do schema)
As mensagens reais sao `req_find_goods_*` (o nome do modulo Lua e findinggame). Dados: `find_chapter/level/map/map_item/
grade/config/two_config/two_reward`.
* **Single-player**: `start_chapter` -> `scene_start` (alvos = itens REAIS de `find_map_item` por dificuldade/mapa,
  contagem de `find_level.new_item_number`; energia 814 init 60; `stop_ts=0` ate `scene_time_begin`) -> `scene_mark`
  (valida alvo/tempo) -> `scene_tip` (dica gratis `free_prompt`) -> `over_option` (+30 s ou desistir) -> `settle`
  (exige todos marcados; avanca fase; fim do capitulo credita `file_rewards` + exp; push `notify_find_goods_progress_num`).
* **Anti-replay (server_rules)**: kind `findinggame` por rodada (`level_key:round:uid` -> `err_find_goods_round_already_settled`),
  `findinggame_grade`, `findinggame_daily`, `findinggame_task`; kinds novos sao registrados em runtime em
  `server_rules.REPLAY_ERR` (+`DAILY_KINDS` p/ reset diario) sem editar server_rules.py. Se a sessao nao tem `replay`, usa registro proprio no estado.
* **Progresso**: `progress_grade_reward` (todos os graus alcancados, credita `find_grade.rewards`), `progress_infinite_receive`
  (apos o ultimo grau, 1 premio por `ex_point`=2800), `daily_score_reward` (faixas `find_two_reward`, retorna `prev_received`),
  `task_reward` (lista de ids; 10 da moeda 620287 por tarefa, 1x/dia), `rank_info` (10 linhas sinteticas deterministicas + self_rank).
* **Dupla offline**: `create_room/join_room/match/match_cancel/room_ready/unready/room_scene_start/enter_confirm/room_scene_mark/
  dissolve/out/remove_member/quick_chat/share_invite/challenge_records`. `match` casa na hora com um **bot** (uid 900001)
  e empurra `notify_find_goods_match_result`; `room_scene_start` empurra `notify_find_goods_room_start`; marcar pontua
  `two_item_score` x engrenagem e soma no `daily_score`.
* **Cheats do modulo** (add_progress/add_daily_score/challenge_record/scene_time/pass_chapter_level/room_force_close) tambem tratados.
* `req_cheat_find_goods_room_settle` (so no fixtures, nao esta no schema) responde skeleton code 0.

## 3. Modulos extras escolhidos (ranking `fuzzcov/RELATORIO.md`, generico->real)
Ranking por n. de msgs genericas; exclui `?`(133, sem modulo), cfg/cheat, social (alliance_*, chat), warmaps (worldmap*,
supremacywar*, arsenalwar*, arsenalleague*, trianglewar*, slg3league*, brawlwar*, pivotfight) que sao das outras lanes.
Apos `findinggame` (32) os 3 seguintes elegiveis sao:
1. **garden_GardenCtrl (31 msgs)** - "homeland"/jardim; PvE/solo + loja + social leve; cfg `garden_*` ricas.
2. **linkagemonopoly_LinkageMonopolyCtrl (29)** - tabuleiro (dados, premios, boss, equipes); cfg `monopoly_linkage_*` completas.
3. **truck_escort_TruckEscortCtrl (19)** - comboio/saque; `truck_escort_*`. (Preferido a thanksgiving_cooking (18) por ter
   mais mensagens e por reutilizar item/formation ja usados no resto do servidor; arsenalwar/slg3league descartados = warmaps.)

### 3.1 `ext_misc.py` - Homeland (31)
Mapa persistente por ponto (place/move/upgrade/recovery/disassemble/repair com armazem e moedas), `enter/exit`,
caixas (`open_box` 1x -> `err_homeland_box_is_open`), moeda da arvore da vida (`garden_coin_speed`=40/h, teto 12 h),
lenhador (site/cabin/npc/wood), loja (`garden_shop`, limite `frequency`, preco), skins (set/upgrade/speed-up, erro same_skin/
skin_is_uprade), prosperidade (`garden_prosperity_task`: valor >= `req` e 1x), likes (limite diario cfg 100, is_like/not_like),
assist (limite `assists_num`=3, CD), visita a outro (homeland sintetica deterministica por uid), registros.
### 3.2 `ext_misc.py` - Linkage Monopoly (29)
Tabuleiro real (`monopoly_linkage_chequer` grupo 1, 26 casas): dado normal 1/5, dado de ouro (1..6, valida
`dice_points_error`), jogo gratis (1/h), cheat de pontos; custo via `monopoly_linkage_consume` (**sandbox: se faltar item
completa o saldo**); premio de casa (`prop_chequer_reward`) creditado; `get_reward(stage)` (extra_reward por `points_sum`, anti-replay
`already_get_reward`), `get_boss_reward` (boss_reward por `points_sum`), free gift 1x/dia (`free_gift_today`), quests, resumo,
equipe solo (lider = eu; accept/kick/quit/apply com erros reais; times recomendados sinteticos).
### 3.3 `ext_misc.py` - Truck Escort (19)
3 caminhoes proprios semeados ja concluidos (qualidade 2..4); `take_truck_reward` (credita itens `truck_escort_group.reward_c`,
1x), `refresh_truck_reward` (custo `truck_escort_diamond_cost`, sandbox), listas de saque/inimigos (8/5 comboios NPC
deterministicos, `refresh` com `requested_too_frequently`), `plunder_fight` (vence se enviou herois; limite 5/dia
`not_enough_count`; CD 2 s; credita saque; grava relatorio/recordo), `plunder_records/battle_report`, unidade de assistencia
(issue/modify/withdraw/get), `get_other_truck_info` (`can_not_fight_self`).

## 4. Fidelidade / limites (honesto)
* **Todos** os codigos de erro usam `errcodes.json` real (nomes `err_find_goods_*`, `err_homeland_*`, `err_linkage_monopoly_*`,
  `err_truck_escort_*`); a logica de QUANDO cada erro ocorre e inferida (nome+comentario do proto), sem captura de producao.
* Valores de recompensa de tarefas/caixas/coins (`task_reward`, `open_box`, saque do caminhao, `COIN_ITEM=118`) sao plausiveis,
  NAO medidos. Coords/rotas de comboio, ranks e outros "jogadores" sao sinteticos.
* Estado vive em `account.ext_state` (memoria): **nao** entra em `Account.to_dict/save`; ao reiniciar o servidor volta ao seed.
  Para persistir basta o mock incluir `ext_state` no JSON (campo simples, chaves int viram str - hoje usa chaves tupla/ponto em
  `hl.b`/`hl.wh`, entao precisaria normalizar).
* Anti-replay usa o `ReplayRegistry` da sessao; `findinggame*`/`homeland_*`/`linkage_*`/`truck_*` kinds nao constam no
  `REPLAY_ERR` original (registrados em runtime em `extkit.once`). `account.replay_done` do mock so recarrega kinds ja conhecidos
  no momento do `init_account` (importar os ext_* antes disso).
* O schema tem tipos inline sombreando globais (ex.: `record`/`cover` em `plunder_records`); o esqueleto e os testes resolvem pelo
  `owner` (`S.resolve`). Handlers ja validados por round-trip.
* Sem push automatico de `notify_find_goods_act_info/common` no login (poderia ser acrescentado ao burst do mock).
* Nao tratados com logica propria (resposta esqueleto code 0, schema-valida): `req_cheat_find_goods_room_settle`,
  `req_homeland_player_homeland_info`, `req_homeland_prosperity_task_all_reward`.
