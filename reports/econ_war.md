# ECON-WAR — gasto individual × requisito coletivo nas guerras de aliança (Kingshot, cfg offline)

Fontes: `lua-logic/cfg/*.json` (tabelas) + textos EN extraídos de `luapkg/lua/1427_64/game_languages_local_en.bin` (`lang.py` → `lang_en.json`, 31 202 chaves). Scripts nesta pasta: `peek.py`, `ld.py` (loader), `lang.py`, `heal_ratio.py`.
Tempo/escopo: ~40 min, análise estática de config. **Não há prova de comportamento do servidor** (fórmulas de pontos, ritmo real de guerra); só o que o cliente declara.

Nota de método: os JSONs omitem campos em default/ausentes (ex.: `alliance_dev_point` linhas sem `player_lv`). Valores ausentes = default 0/nulo, não herdados. IDs de recurso resolvidos via `resource_name_*`: 101 Gems, 102–105 Comida/Madeira(103)/Pedra/Ferro (individuais), 110 Alliance Token (individual, gasto na loja), 501–504 Alliance Bread/Wood/Stone/Iron (tesouro da aliança), 510 Pyrocrystals (cristal de campo de batalha), 742 Personal Prep Points, 743/745 Alliance Prep Points, 750 Personal Points da batalha, 112 Relic Coins.

## 0. Resumo executivo (veredictos)

| # | Alegação | Veredicto |
|---|---|---|
| A | "Quem paga sobe o reino": poder do grupo na guerra depende de gasto individual | **PARCIAL** (forte só no Supremacy; Arsenal ≈ não) |
| B | Gasto individual vira **requisito** (bloqueio) coletivo | **NÃO como bloqueio duro; SIM como bônus/vantagem competitiva** |
| C | Guerra contínua drena recursos individuais | **SIM no Supremacy** (cura a ~10% do custo de treino, por soldado, sem custo-teto); **NÃO no Arsenal** (cura grátis, ninguém morre) |
| D | Há mecânicas de pressão sobre quem não participa | **SIM, moderadas**: ranking de contribuição, "mínimo de membros contribuintes", janelas de recompensa, matchmaking por poder |

## 1. As três guerras (+ Triangle)

### 1.1 Supremacy ("Flamedragon Tyrant") — tabelas `supremacy_war_*`, `supremacy_battle_condition`
Fases (texto `supremacy_ui_13`): inscrição 48h (líder/R4) → despacho de combatentes 48h (**até 60 membros**, `supremacy_war_config.alliance_player_num=60`; quem entra na aliança depois é desclassificado) → véspera 59h → campo aberto 7h; `battle_prepare_time=300s`; `enter_war_cd=600s` ao sair; `build_open_time=3600` (palácio abre 1h depois). Palácio disputado por tempo de ocupação.

O que o MEMBRO precisa trazer (`supremacy_ui_19`):
- **Soldados próprios** ("Governors must bring their own soldiers"); marchas = filas desbloqueadas (investimento individual prévio). Sem expedições/escoltas ativas, sem barricada queimando.
- **Infirmary ilimitada durante a batalha, mas custo e tempo de cura PADRÃO**; excedente da capacidade original ao sair **perece**. Soldados podem **morrer** em ataque a cidades inimigas (só ficam gravemente feridos no Palácio/Aeries).
- Ataques a cidades de outros: livre (FFA contra outras alianças).

Fluxo membro → grupo:
1. **Pontos de aliança**: `supremacy_war_point_resource` (24 linhas; types 2/4/5; ex. linha 23 `points=200 type=4`, linha 24 `points=30000 type=5`) + `supremacy_ui_89`: pontos por Carnage (inimigos feridos), Casualty (**seus próprios feridos graves** geram pontos), Gathering (Pyrocrystal), Clearance (escoltas). → quanto mais o membro **perde/arrisca tropas**, mais pontos individuais e de aliança. Ranking de alíanças por pontos e por tempo de ocupação (`supremacy_war_alliance_rank`, `supremacy_war_alliancetime_rank`, `supremacy_war_occup_rank_reward`).
2. **Habilidades de aliança (`supremacy_war_skill`)** custam **Pyrocrystals (510)** — recurso coletado *por membros* no campo (`supremacy_war_resource`: veias de 600/1200 cristais, velocidade 1/1.5; `crystal_refresh_time=900s`). Custos: Dragonblood Healing 40 000 (cura 50% dos graves em vitória, 10 min, cooldown 3600s), Dragonsoul Revival 10 000 (50% das baixas viram feridos), Dragonbreath Fury 35 000 (teleporte forçado do alvo), Dragonscale Armor 50 000 (+15% ATK/DEF defensor, 30 min), Banner of Dragonroar 50 000 (+25% capacidade de rally/deploy, 30 min). Swiftwing (+100% velocidade) e Dragonborn Gathering (+50% coleta) sem `use_cost` (Aerie/ocupação). Logo, **o buff coletivo é comprado com trabalho de campo individual (tempo + marchas), não com gasto monetário direto** — mas exige membros gastando marchas/tropas em coleta em vez de lutar.
3. **Pré-fase "Champions' Eve" / Preparação (`supremacy_war_pre_*`, `integral_activity_conf` category 29)** — **aqui o gasto individual vira bônus coletivo explicitamente**:
   - `supremacy_war_pre_conf.need_lv=16` (Town Center 16+ contribui). Texto `supermacy_war_pre_ui_13`: membros "gain Alliance Preparation Points" abrindo baús.
   - Tarefas que alimentam pontos (`supremacy_war_pre_integral.integral_source` → `integral_activity_conf` 2221001…2221112): coletar 1000 pão/1000 madeira/200 pedra/50 ferro no mapa (`task_type 137`, textos `integral_task_desc_17-20`), matar bestas/terrors lv1–30, tiers 1…11 de `task_type 159` com recompensas 0,0,2,3,4,7,10,14,18,24,30 pts (a mapa exato descrição→id de `159` **não foi resolvido**), e promoção/treino de tropas (`desc_26/27`: "Raise Power by training/promoting troops"). O pool genérico `integral_activity_conf` (312 linhas, outras categorias) inclui **"Use N Gems"** (`desc_23`, cond item 101) e "Use N Hero Gear widgets" — **não confirmado** que a categoria 29 do Supremacy as inclua (nas linhas 2221xxx não aparecem).
   - `supremacy_war_pre_stage` (stage 2): baú pessoal exige **20 000 Personal Preparation Points (742)** e entrega **50 Alliance Preparation Points (743)** + itens.
   - `supremacy_war_pre_buff`: limiares de **Alliance Preparation Points = 0 / 50 000 / 100 000 / 150 000 / 200 000 / 250 000** destravam bônus de campo (textos: Healing Cost Down 10%→20%→30%; Healing Speed Up 100%→150%→200%; `supermacy_war_pre_ui_18-21,34-39`). Fases 1/2 de preparo.
   - Alianças inelegíveis (não inscritas) **não recebem o bônus**, só baús pessoais (`supermacy_war_pre_ui_42`).
   ⇒ **Gasto/progresso individual soma em contador coletivo, sem teto por pessoa, com bônus defensivo concreto (cura mais barata/rápida) para TODOS da aliança.** Não encontrei piso por membro.
   - Recompensas por ranking de pontos pessoais (`supremacy_war_point_rank_reward`: rank1 = 30 000 Gems + 700 ×2 itens + 300 ×…), por ocupação (`occup_rank_reward`: rank1 inclui 200 000 gemas + skins), `server_reward`. Existe também um chassi pago: skin "Flamedragon Call" (+2,5% letalidade, `item_desc_304505`) e speedups de rally exclusivos do campo (`item_name_301950/1`: −25%/−50% marcha do rally para participantes).
4. Pressão negativa: `supremacy_war_config` `burn_speed=533` (barricada queima 4000× mais rápido no campo; `outfire_cost=100` = **100 Gems? para apagar fogo** — recurso não rotulado no campo, assumo gemas **[hipótese]**); se defesa zera, cidade é teleportada à borda. Abstenção/ausência: `supremacy_ui_50/53` (abstenção) — quem se abstém não luta mas lista de combatentes pode não mudar.

### 1.2 Arsenal ("Swordland Showdown" / `arsenalwar_*`, `arsenal_league_*`, `arsenal_war_battlefield_*`)
- Registro: líder/R4 de alianças top-20 de poder (`arsenalwar_config.union_ranking=20`, `arsenal_league_config.league_group_limit=70` para liga), **30 combatentes + 10–20 substitutos** (`battle_quantity_limit=30`, `substitute_quantity_limit=10`; texto 20), 2 legiões por aliança, TC ≥ 16 (`player_castlelv`), cada membro só uma legião.
- **Matchmaking por poder** (`personal_matching_fraction=300000`, `matching_need_number=15`, `matching_rank_number_fraction=20`; texto `arsenalwar_ui_115`: "Matchmaking Points = Soldier Power dos top-20 inscritos", compostos por Governor Gear, Hero Gear, Battle Tech, Pet, Master). ⇒ investimento individual em poder define **contra quem** se luta, não bloqueia entrada.
- **Soldados não morrem; Infirmary ilimitada e cura GRÁTIS; tudo se cura sozinho ao sair** (`arsenalwar_ui_25/112/114`; `hospital_free=10`, `hospital_speed=10000`=+100%). 1 Advanced Teleporter grátis recarregável; fogo queima muito; saída = 12 min cooldown (`battle_quit_cooling_time=720`).
- Pontos: poder derrotado /10 000 → 40 (defesa) ou 80 (ataque) Relic Points **pessoais**, **0 de aliança**; ponto de aliança vem de **controlar prédios** (`arsenalwar_building`: `continued_storage` 6000/3000…; `arsenalwar_integral_build` seções 1–300 / 301+). O placar coletivo depende de **posição/controle**, não de consumo.
- Recompensas: `winner_reward`/`loser_reward` = 112 Relic Coins 2000/1500 + itens (aliança); `arsenalwar_personal_reward` 240 faixas por `gear` (pontos pessoais 1999→19999→41999…, Relic Coins 2 400→4 800 crescente); `arsenalwar_rank_*`; nota `arsenalwar_grade` C/B/A (fraction 0/3/5). Exige permanecer na aliança até a apuração. Sem custo de entrada.
- `arsenalwar_call_npc_buff` / `arsenalwar_config.call_npc_*`: NPC de apoio (cdtime 480s, dano 1000…5000, duração 300s). A tabela `call_npc_buff` está quase vazia (só `buff_id`); **o custo de invocar o NPC não aparece no cfg**. Sem evidência de buff pago em dinheiro.

### 1.3 Triangle war
Só `triangle_war_edge` (126 arestas): `road_id`, `distance` (220), `type`, `cost_food` (5500), `to` → custo logístico de FOOD (individual) por aresta do grafo. Nenhuma outra tabela `triangle_*` ⇒ **sem dados** de pontos/aliança. (Existem `brawl_war_*` e `cross_war_*` — "Kingdom of Power": o reino com mais pontos de preparação ganha bônus e a batalha ocorre no reino com menos pontos, `cross_war_des_01`; fora do escopo.)

## 2. Aliança — construção, doações, duels

- **Construção (`alliance_building_cost` 44 linhas; `alliance_building_conf` 23)**: custo em **recursos de aliança 501–504** (tesouro coletivo), crescente com a contagem de prédios (11–15º: 5 000 pão+madeira; 31–40º: 20 000; 91–100º: 36 000 + 8 000 pedra; primeiros do grupo 1: 700k/700k/400k/200k). Origem: coleta em território/minas (`alliance_resources_*`, `alliance_safe_mine`) e troca (`alliance_resources_exchange`, ex. 2:1). **Não é pago do bolso individual diretamente.**
- **Doações / tecnologia**: `alliance_science_detail` (279 níveis; 256 com `donate_cost`): cada contribuição gasta **recursos individuais 102–105** (40011: 1 000 madeira; 40012: 2 000; 40013: 3 000) somando em `need_donation_value` (123 000 → 148 000…); ao concluir consome também recursos de aliança (`cost_alliance_resource` 1 700…) e tempo (`cost_time` 3 600…). Soma de uma doação por nível: 300 000 (102) + 255 000 (103) + 36 750 (104) + 5 250 (105) ≈ 597 000 recursos individuais. Bônus (`alliance_science_type.add_type_vaule`, 60 tipos) vale para **todos** ⇒ **gasto individual → buff coletivo: SIM**. Tentativas são limitadas por tempo (`alliance_technology_ui_12`, "Insufficient Contribution attempts"), então o teto é temporal, não monetário.
- **Ranking de contribuição** (`alliance_donation_reward`, 8 linhas; `alliance_ui_147-152`, `alliance_leaderboard_ui_15/16`): prêmios por posição diária (type 1) e semanal: #1 diário = 300 de item 101 + 2 000 Alliance Token (110); #1 semanal = 1 500 + 10 000 tokens; #4+ 50/500. **Texto: "Not enough members made the minimum required contribution… members not eligible for rewards"** ⇒ **mínimo coletivo** que depende de N membros contribuindo = pressão social explícita. (Item 101 rotulado "Gems" em `resource_name_101`.)
- **Dev points**: `alliance_dev_point` (7 linhas, `player_lv` 5/3/2/1), `alliance_dev_personal_point` (`daily_aim=800`, recompensa pessoal 801310 + 100 000 tokens), `alliance_dev_config` (`player_limit=30`): meta diária **individual** com recompensa individual.
- **Duel (`alliance_duel_*`)**: `alliance_duel_config` `integral_condition=300 000`, `alliance_integral_condition=20 000 000`, `union_ranking=20`, `matching_time=3600`. `alliance_duel_stage_task` lista fontes de pontos (`2220xxx` em `integral_activity_conf`, categoria 22 — mesmos tipos de tarefa: coleta, bestas, gemas, treino) por estágio e `warzone_day`; `alliance_duel_stage_integral` (96 linhas): marcos de pontos (100 / 25 000 / 50 000…) com recompensa. Soma ações individuais num total de aliança; recompensa também individual por marco. A linha 2220018 é "Use Gems" (cond item 101) — **gemas contam em pelo menos esta categoria**.
- `alliance_chest`/`alliance_chest_event`: baús com `get_brilliant` 30/60… e `dropid`. Sem custo.

## 3. Cura/feridos — ritmo de drenagem

- `soldiers.cost_mh` (cura) vs `cost_res` (treino): **cura ≈ 10% (9,2–11,1%) do custo de treino**, todos os tiers (`heal_ratio.py`). T1 = 8 recursos/soldado (treino 72); T10 = 547 (5 469); T11 ≈ 1 349 (13 671).
- Supremacy: cura no preço padrão, reduzida só pelos bônus (−10/−20/−30% de custo; +100…+200% de velocidade na preparação; `supremacy_ui_97`: "Rearmament Bonus" +500% velocidade, −30% custo, `recovery_duration_time=198000`s ≈ 55h pós-evento). 1 000 T10 gravemente feridos ≈ 547 000 recursos brutos; −30% ⇒ ~383 k. Ferido vira morte só se exceder a capacidade original da infirmary ao sair; morte direta só em PvP de cidades.
- Skill "Dragonblood Healing": 50% dos graves curados após vitória em Palácio/Aerie — custo coletivo (Pyrocrystals), benefício individual.
- Arsenal e liga: **zero drenagem** (cura grátis, sem morte).
- Líquido: no Supremacy o desgaste é individual e proporcional à participação; o limite é a infirmary (investimento prévio). Não há dado de ritmo temporal (depende do servidor); só custo unitário.

## 4. Mecânicas de pressão

| Mecânica | Tabela/texto | Pune quem não participa? |
|---|---|---|
| Lista de combatentes travada (60 / 30+20) | `supremacy_ui_13/15`, `arsenalwar_ui_115` | Sim: entrar depois = desclassificado/sem recompensa |
| Sair da aliança bloqueado / perde apuração | `supremacy_ui_198/200/202`, `arsenalwar_ui_114` | Prende o membro |
| Bônus coletivo da preparação por limiares | `supremacy_war_pre_buff` (50k…250k) | Moderada: quem não contribui reduz o bônus de todos |
| Ranking de contribuição com mínimo de membros | `alliance_leaderboard_ui_15/16`, `alliance_ui_148/152` | **Sim (coletiva/social)** |
| Recompensa por rank (pessoal/aliança) | `supremacy_war_point_rank_reward`, `occup_rank_reward`, `arsenalwar_rank_*`, `alliance_duel_stage_integral` | Premia posição; sem piso para os demais |
| Matchmaking por poder top-20 | `arsenalwar_ui_115` | Empurra investimento em gear/hero/tech dos top |
| Cooldown de saída 10–12 min; barricada queima rápido | `enter_war_cd`, `battle_quit_cooling_time`, `burn_speed` | Pune abandono |
| Buffs "pagos": skin Flamedragon Call (+2,5% letalidade), speedups de rally do campo, skills com Pyrocrystals | `item_desc_304505`, `item_*_30195x`, `supremacy_war_skill` | Vantagem por gasto individual; coletiva só nas skills |
| `arsenalwar_call_npc_buff` | cfg vazio | Sem custo visível |

## 5. Veredictos

1. **"Poder do grupo em guerra depende de recursos individuais"** — **PARCIAL.** Supremacy: sim (tropas próprias, cura a custo padrão, pontos de preparação, doações de tech). Arsenal: só via *poder acumulado* (matchmaking), não consumo. Triangle: sem dados.
2. **"Gasto individual é requisito coletivo"** — **NÃO como bloqueio; SIM como bônus.** Nenhum piso de gasto por membro encontrado. Limiares são de pontos de aliança (50k…250k) e de contribuição mínima de N membros para recompensa de ranking; os únicos "requisitos" duros são lista de 60/30 combatentes, TC16 e permanência na aliança.
3. **"Quem paga sobe o reino e pressiona todos a gastar"** — **PARCIAL.** O mecanismo existe (limiares coletivos + ranking de contribuição + lista travada), mas atenuado: tarefas de pontos incluem coleta e bestas (sem gemas), doações limitadas por tempo, recompensas por marcos. **Pendente**: se "Use Gems" (`integral_task_desc_23`) conta na pré-fase do Supremacy (categoria 29) — nas linhas 2221xxx não aparece; aparece no Duel (2220018) e em outras categorias (7, 13, 14, 22…). É a linha decisiva para a crítica.
4. **"Guerra contínua drena recursos individuais"** — **SIM no Supremacy** (cura ~10% do treino, sem teto monetário); **NÃO no Arsenal**.
5. **"Buffs pagos de guerra"** — **PARCIAL**: skills de aliança custam Pyrocrystals de campo (trabalho, não dinheiro); itens pagos (skin/speedups) são individuais; `call_npc_buff` sem custo no cfg.

## 6. Limites / pendências
- Fórmulas do servidor (pontos reais por ação, `rank_num_param`) invisíveis; só tabelas.
- Mapa `integral_source` 2221101–111 ↔ descrição não resolvido; confirmar gemas na pré-fase lendo handlers Lua (`HANDLERS.tsv`, `supremacywar*`).
- Triangle war: só arestas de food.
- Rótulo de `outfire_cost=100` não confirmado.
- A pasta contém também `calc.py`, `full.py`, `heal.py` que não são meus (criados por outro processo); ignorados.
