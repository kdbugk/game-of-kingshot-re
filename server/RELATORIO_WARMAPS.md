# RELATORIO_WARMAPS — LANE EXT-WARMAPS (mapa-múndi / capital / supremacy war)

Entregues em `C:/Users/prs/work/server/` (nada escrito no repo; `mock_v4.py` intocado):
`ext_worldmap.py` (64 handlers), `ext_supremacywar.py` (59), `test_ext_warmaps.py`, este relatório.
Cobertura: **123/123** mensagens do mapa `coverage_full.json` dos módulos WorldMapCtrl/WorldPlayerCtrl/WorldMapFortCtrl/WorldMapCapitalCtrl/Supremacy*Ctrl
(sem buracos; o alvo estimado era ~40+37, na prática são 123 por incluir `req_capital_war_*` (38), `rsp_*` e espectador).

## Contrato
`HANDLERS = {"req_x": fun(session, m)}`; usam `session.reply/push/now()` e a conta via `session.account` (atributo **ou** callable) com fallback a `session.acct`
(só leem `base.uid/nickName/kid/image/power`). Estado volátil em `session._wm` (mapa/capital) e `session._sw` (supremacy) — por sessão, **não** persistido na Account.
Todo handler é embrulhado por `_safe`: qualquer exceção vira `{"code":1}` (nunca propaga). Protocolos com response vazia (`rsp_*`, struct `[]`) respondem `{}`.

## ext_worldmap.py
* **Mapa**: `req_world_map_info` → `{code:0}` + `notify_world_mapobjs` (chunk sintético **determinístico** por (kid,x,y) — recursos, monstros, cidades, fortes menores, cidade do jogador, capital em (597,597)) + `notify_world_marchs`. Janela limitada a 121×121 / 400 objs. `req_world_mapobj`, `map_search`, `map_fog`, `kingdom_info`, `resource_info`, `alliance_resource_info`, `territory_buff`, `control_list`, `fort_pro_progress`, `del_watch`.
* **Cidade/move**: `move_city`, `random_move_city`, `alliance_*move_city(_point)`, `fort_move_city`, `gohome(_to_point)`, `wormhole_jumping_*` — atualizam a posição da cidade da sessão e empurram `notify_player_city_update` (+ `notify_world_player_init` nas cross/aliança). Sandbox: sem custo, sem validação de terreno (só clamp 0..1199).
* **Capital (rei)**: estado sintético (presidente = o próprio jogador): manifesto, nome/bandeira do reino (valida 1..24 chars, senão `code:2`), modo de cargos, candidaturas, nomeações/demissões e `appoint_list`, agenda de tarefas (add/modify/get com ids), skills (contador+timestamp), gifts, goal_rank, histórico. Mutações empurram `notify_capital_war_init` + `notify_capital_war_office_init`. Fase da capital derivada de timestamps (ciclo semanal; guerra 18000 s = `capital_war_config.war_fight_time` no fim do ciclo). `receive_president_reward` 1× ok, depois `code:4004`.
* Não implementado de propósito: marchas do mapa-múndi (`req_world_march*` são de outro módulo, WorldMarchCtrl) — fora do alvo.

## ext_supremacywar.py
* **Fases por timestamp** (`war_phase(now)`, pura): ciclo 14 d ancorado na época; `Nothing(0) → Predicted(1,12h) → SignUp(2,48h) → Dispatched(3,48h) → Publicity(4,59h) → Fighting(5,7h) → Restored(6,198000s)` (econ_war.md §1.1 + `supremacy_ui_97`). `notify_supremacy_war_info` (act_info com `state/state_begin_ts/state_end_ts`) é empurrado em `enter`/`gov_group_overview`.
* **Batalha**: `enter` (resp com `city_point, begin/over_time, crystal, skills` + pushes info/player_init), `cheat_enter`, `exit` (registra `exit_time`), `map_info` (+`notify_supremacy_war_mapobjs`: palácio em (195,195) `supremacy_war_fixed_obj #1`, guardas, recursos 1/2, monstros, cidade, mapa 400×400 = `supremacy_war_area #1`), `march` (cria marcha 2 s/tile, push `march_add`), `recall/off_work` (push `march_del`; id inexistente → `code:2`), `speedup` (metade do tempo restante, push `march_update`), `march_detail`, `move_city`, `resource_info`, embaixada, repatriações, `fort_*_watch`.
* **Habilidades de aliança**: `use_alliance_skill` valida `skill_id` ∈ cfg `supremacy_war_skill` e aplica **cooldown real** (`cooling_time` da cfg, 3600 s) → `code:4004` dentro do cooldown; `get_alliance_skill_op_record` lista os usos. Custo em Pyrocrystals (510) **não** debitado (sandbox).
* **Governo/rank**: presidente/offices/manifesto/gift/dominance/top-100/points (listas sintéticas coerentes), `notify_supremacy_war_init`; **Banquete**: `feast_list/open/reserve/tables/records/satiated`, `world_search_supremacy_table`; **Espectador**: enter/exit/map_info/guard_info/control_list.
* **Sandbox**: `STRICT_PHASE=False` → `enter` aceita em qualquer fase. Com `True`: fora de `Fighting` → `code:4` e cooldown `enter_war_cd=600 s` → `4004` (códigos assumidos).

## Validação
`python test_ext_warmaps.py` (fake session, `sproto_lib` real, fixtures `fixtures_all.json`):
* Cada handler roda com a fixture + 2 variações de lixo (vazio / tipos errados) → **sem exceção**; resposta e **todos os pushes** validados campo-a-campo contra o schema (tipo, array, struct aninhada) e **round-trip `enc_struct`/`dec_struct`**.
* **N_ok/N = 123/123**; cenários de estado **13/13** (move_city fixa posição, chunk determinístico e contém a cidade, manifesto reflete no push, agenda add/list, reward 1×, fases do ciclo 0..6 em ordem, cooldown da skill ok→4004→ok após 3600 s, march add/speedup/recall, enter com pushes válidos).
* Achado de teste: o validador pegou 2 divergências de schema minhas (`kv{uid,goal}`; `alliance_resource_info` sem `res_count`), já corrigidas.

## Integração (para quem pluga no mock)
`for mod in (ext_worldmap, ext_supremacywar): H.update(mod.HANDLERS)`. Se `Session.account` não existir como atributo, o código cai em `session.acct`. Pushes usam `session.push(name,obj)` (mesmo do mock).

## Premissas / riscos (não verificadas contra captura real)
1. `world_mapobj.type` = (tag do campo − 1) (1 city, 2 res, 3 monstro, 4 camp, 5 forte…, 16 capital); supremacy: lido do schema em runtime com a mesma regra. **Se a UI não renderizar objetos, é o primeiro suspeito** (cfg `world_map_obj` tem chaves 0..5,20..48,101..105 sem mapeamento claro).
2. IDs de config de objetos (resource id 1250101.., monster 7100001..) vêm da cfg, mas níveis/`speed` são plausíveis, não reais.
3. `state` de capital (0 paz / 1 guerra) e do `world_march.state=1` são suposições; sem captura.
4. Códigos de erro 2 (param), 4004 (repetição/cooldown) assumidos (4004 é o do mock p/ interval); `code:4` (fora de fase) é palpite.
5. Estado volátil por sessão: reconexão reseta cidade/marchas/manifesto (não persiste em Account). Cidade nasce em posição pseudoaleatória estável por uid ao redor da capital — pode divergir da posição "real" do save.
6. Marcha do supremacy não evolui sozinha (sem timer de chegada/combate); só push inicial.
7. Sem fases `Predicted/SignUp` ligadas a handlers de inscrição (`req_alliance_supremacy_war_sign_up` etc. pertencem ao módulo SupremacyWarActivityCtrl — não estavam no alvo).
