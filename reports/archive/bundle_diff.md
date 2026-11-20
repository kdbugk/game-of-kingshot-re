# Diff de bundles Kingshot 1.9.5 → 1.14.27

## Resumo

- Parse: 100% dos bundles (blocksInfo + nós), **0 erros** — 6632 arquivos em 1.9.5 e 7279 em 1.14.27. Block 0 não foi necessário.
- Nomes lógicos (sem hash): 6632 → 7279; **+2044 novos**, **−1397 removidos**, 5235 em comum (2551 com tamanho alterado).
- Tamanho descomprimido total: 1956.8 MB → 2087.2 MB (130.4 MB).
- Nós (assets/CAB) totais: 7862 → 8772; nomes de nó distintos (sem hash): 7862 → 8772 (+2629 / −1719).

## O que sugere de features novas (interpretação)

- **Modo Tower Defense é o maior eixo**: +824 bundles `towerdefense_*` novos (−477 removidos). Inclui `versionconfig2610/2611_scenedata|config` (cenas/configs versionadas para as versões 26.10 e 26.11, ~270 bundles), `tree_skill_*` (hero/building/monster/soldier — árvore de habilidades), `tree_check`, `character_td_*` (activity/monster/hero/soldier), `effect_fx_*` (229) e `generated_astarmap` (mapas A* gerados). Sugere conteúdo TD de novas fases/temporadas e sistema de skills.
- **Heróis novos (IDs 50034–50040)**: diego, liz, luna, lotter, bayard, daya (+ variantes `_red`) e `captain_hendrik_octopus`; também `hero_exhibit_10006/10007_king`.
- **Eventos novos**: `peachfestival` (festival do pêssego), `duckmarket`, `midautumn` (37 painéis UI), `children2026` (43), `linkagemonopoly` (33, crossover tipo Monopoly), `dress2025`, `2026whitebear`, `brawlarena`, `slg3arena`, `accumulativerecharge`, `treasureroomnew`, `vvip` (castelo VVIP, 11 bundles `scene_vvip_vvip_castle`).
- **Cidade/mapa**: +121 `art_scene_city_got_*`, +49 `scene_city_got_*`, `scene_city_map_maproot` — mas 298 `scene_city_got` removidos: reestruturação/rearranjo (provável rename/rehash de skins de cidade).
- **Removidos**: `scene_world_building` (105), `towerdefense_effect_exhibit/buiding/march` (320), `ui_panel_dress` (62), `actor_climbtower_*` (~35: torre de escalada antiga), `ui_panel_threedayshop`, `redpacket`, `actor_hero_3d` (26) — features aposentadas ou refatoradas.
- **Código Lua**: `luapackage_32/64` cresceu 72.1 MB → 101.1 MB (+29 MB descomprimido, +40%): maior crescimento isolado, ou seja, muita lógica nova (TD, eventos, UI). Alvo prioritário para diff de Lua.
- Infra: novos `config_cdnretrydata`, `config_gamepadcursorsettings` (suporte a gamepad), `config_vfxtexturelibrary`, `3party_spine_runtime_spine-unity_depend`.
- Ressalva: nome lógico = nome sem hash; nomes “removidos” e “novos” com mesmo prefixo podem ser renomeações, não funcionalidades distintas. Nós de CAB têm nomes com hash por bundle, portanto os nós distintos ≈ nº de bundles (1 nó/bundle) — o diff de nós não acrescenta sinal além dos bundles.

## Bundles novos em 1.14.27

| prefixo | qtd | tamanho |
|---|---|---|
| towerdefense | 824 | 103.7 MB |
| ui | 514 | 122.6 MB |
| art | 385 | 227.0 MB |
| scene | 179 | 71.8 MB |
| spine | 76 | 20.0 MB |
| atlas | 34 | 29.6 MB |
| actor_battle_battle | 18 | 2.6 MB |
| actor_activity_peachfestival | 3 | 0.1 MB |
| backup | 3 | 1.3 MB |
| config | 3 | 0.0 MB |
| actor_hero_3d | 2 | 8.8 MB |
| 3party | 1 | 0.0 MB |
| actor_activity_duckmarket | 1 | 0.1 MB |
| mat | 1 | 0.0 MB |

<details><summary>towerdefense (824)</summary>

- `towerdefense_character_td_activity_city_building_beast_pen` (2.5 MB)
- `towerdefense_character_td_activity_city_building_house` (0.8 MB)
- `towerdefense_character_td_activity_city_building_meteor_shrine` (0.7 MB)
- `towerdefense_character_td_monster_61006_witch` (0.7 MB)
- `towerdefense_effect_fx_50036_hero_luna_skillxp_hit_dkb` (0.7 MB)
- `towerdefense_effect_fx_50035_hero_liz_xpskill_baodian_hjf01` (0.6 MB)
- `towerdefense_character_td_activity_city_building_goldmine` (0.6 MB)
- `towerdefense_character_td_soldier_pikeman_10` (0.6 MB)
- `towerdefense_character_td_soldier_pikeman_05` (0.6 MB)
- `towerdefense_character_td_activity_city_building_frost_shrine` (0.5 MB)
- `towerdefense_versionconfig2610_config_unitlevelnew` (0.5 MB)
- `towerdefense_versionconfig2611_config_unitlevelnew` (0.5 MB)
- `towerdefense_effect_fx_61011_skillxp` (0.5 MB)
- `towerdefense_character_td_monster_61011_blackknight` (0.5 MB)
- `towerdefense_effect_fx_50035_hero_liz_xpskill_xishou02_hjf01` (0.5 MB)
- `towerdefense_effect_fx_61006_skillxp_hit` (0.5 MB)
- `towerdefense_character_td_monster_60008_knight` (0.5 MB)
- `towerdefense_map_artscene_city_td_activity_3` (0.5 MB)
- `towerdefense_character_td_soldier_infantry_05` (0.5 MB)
- `towerdefense_character_td_monster_61010_badking` (0.5 MB)
- `towerdefense_character_td_soldier_archer_05` (0.5 MB)
- `towerdefense_character_td_soldier_infantry_10` (0.5 MB)
- `towerdefense_character_td_soldier_archer_10` (0.5 MB)
- `towerdefense_character_td_monster_61001_shieldguard` (0.4 MB)
- `towerdefense_character_td_monster_60010_militia` (0.4 MB)
- `towerdefense_effect_fx_50039_hero_bayard_xp_hit_wsy` (0.4 MB)
- `towerdefense_character_td_activity_city_building_stable_03` (0.4 MB)
- `towerdefense_character_td_pet_62002` (0.4 MB)
- `towerdefense_character_td_activity_city_building_castle_04` (0.4 MB)
- `towerdefense_character_td_activity_city_building_castle_05` (0.4 MB)
- `towerdefense_character_td_soldier_20100_activity` (0.4 MB)
- `towerdefense_effect_fx_50035_hero_liz_xpskill_dandao` (0.4 MB)
- `towerdefense_character_td_monster_60005_raider` (0.4 MB)
- `towerdefense_effect_fx_50036_hero_luna_skillxp_xuli_dkb` (0.4 MB)
- `towerdefense_character_td_monster_60009_wildknight` (0.4 MB)
- `towerdefense_effect_fx_50034_hero_diego_skillxp_hit_lq` (0.4 MB)
- `towerdefense_effect_fx_td_battlefield_skill4` (0.4 MB)
- `towerdefense_character_td_activity_city_building_stable_02` (0.4 MB)
- `towerdefense_character_td_monster_61009_witchdoctor` (0.4 MB)
- `towerdefense_character_td_monster_61005_alchemist` (0.4 MB)
- `towerdefense_character_td_monster_60012_archer` (0.4 MB)
- `towerdefense_character_td_monster_60003_coyote` (0.4 MB)
- `towerdefense_character_td_monster_61008_priest` (0.4 MB)
- `towerdefense_character_td_monster_60011_swordsman` (0.4 MB)
- `towerdefense_character_td_activity_city_building_lumbermill` (0.4 MB)
- `towerdefense_versionconfig2611_scenedata_diy_fight_bridge_cell` (0.4 MB)
- `towerdefense_versionconfig2610_scenedata_diy_fight_bridge_cell` (0.4 MB)
- `towerdefense_versionconfig2611_scenedata_diy_fight_empty_cell` (0.4 MB)
- `towerdefense_versionconfig2610_scenedata_diy_fight_empty_cell` (0.4 MB)
- `towerdefense_versionconfig2610_scenedata_diy_fight_cell` (0.4 MB)
- `towerdefense_versionconfig2611_scenedata_diy_fight_cell` (0.4 MB)
- `towerdefense_character_td_activity_city_building_castle_03` (0.4 MB)
- `towerdefense_character_td_monster_61003_destroyer` (0.4 MB)
- `towerdefense_map_artscene_city_td_activity` (0.3 MB)
- `towerdefense_character_td_monster_60007_headhunter` (0.3 MB)
- `towerdefense_effect_fx_soldier_10100_skill2` (0.3 MB)
- `towerdefense_effect_fx_50034_hero_diego_skillxp_lq` (0.3 MB)
- `towerdefense_character_td_activity_city_building_castle_01` (0.3 MB)
- `towerdefense_effect_fx_td_fire_cannon_skill3_hit` (0.3 MB)
- `towerdefense_map_artscene_city_td_activity_2` (0.3 MB)
- … +764

</details>

<details><summary>ui (514)</summary>

- `ui_single_hero_full_part_1` (4.3 MB)
- `ui_single_towerdefencegame_part_1` (4.3 MB)
- `ui_single_lord` (4.2 MB)
- `ui_single_towerdefencegame_part_2` (4.1 MB)
- `ui_single_hero_full` (2.8 MB)
- `ui_single_common` (2.4 MB)
- `ui_panel_linkagemonopoly_linkagemonopolyseriespreviewpanel` (2.2 MB)
- `ui_single_planet_area` (2.0 MB)
- `ui_panel_children2026_children2026eventfrozentreasuresubpanel` (1.9 MB)
- `ui_panel_treasureroomnew_treasureroomnewpopuppanel` (1.9 MB)
- `ui_panel_polarexpedition_polarexpeditionorangesubpanel` (1.9 MB)
- `ui_panel_treasureroomnew_treasureroomnewmainpanel` (1.8 MB)
- `ui_single_decorate_frame` (1.5 MB)
- `ui_panel_lobby_fxui_lobby_peachfestival_tishi_wwj` (1.3 MB)
- `ui_panel_towerdefencegame_tdgamepasschecksubpanel` (1.2 MB)
- `ui_panel_slg3arena_slg3arenacompetitionprimarypanel` (1.1 MB)
- `ui_panel_lobby_fxui_lobby_monopoly_tishi_wwj` (1.0 MB)
- `ui_panel_gift_gifttriggerbagpanel_490600` (1.0 MB)
- `ui_single_chat` (0.9 MB)
- `ui_panel_linkagemonopoly_linkagemonopolypreviewsubpanel` (0.9 MB)
- `ui_panel_main_sub_brawlwarcontinualkillsubpanel` (0.9 MB)
- `ui_panel_linkagemonopoly_linkagemonopolysubpanel` (0.8 MB)
- `ui_panel_chat_chatgifemojigiftpopuppanel` (0.8 MB)
- `ui_panel_capitalwar_capitalwarradiolvpanel` (0.7 MB)
- `ui_panel_vvipredpacket_vvipredpacketdiamondgetdetailpanel` (0.7 MB)
- `ui_panel_vvipredpacket_vvipredpacketdiamondpanel` (0.6 MB)
- `ui_panel_towerdefencegame_fx_tdacticivity_stage_2` (0.6 MB)
- `ui_panel_linkagemonopoly_linkagemonopolybossprogresspopuppanel` (0.6 MB)
- `ui_panel_children2026_children2026digtreasuresubpanel` (0.6 MB)
- `ui_panel_brawlarena_brawlarenaactivematchwaitpanel` (0.6 MB)
- `ui_panel_gift_gifttriggerbagpanel_498001` (0.6 MB)
- `ui_panel_allianceduel_allianceduelstageresultpanel` (0.6 MB)
- `ui_single_mail` (0.6 MB)
- `ui_panel_arsenalleaguehonour_arsenalleaguehonourmvpsubpanel` (0.5 MB)
- `ui_panel_brawlarena_brawlarenasubpanel` (0.5 MB)
- `ui_panel_starvip_starviptablepanel` (0.5 MB)
- `ui_panel_commonpasscheck_expert2025passchecksubpanel` (0.5 MB)
- `ui_panel_gloryredpacket_gloryredpacketdiamondgetdetailpanel` (0.5 MB)
- `ui_panel_children2026_children2026sevendayssubpanel` (0.5 MB)
- `ui_panel_chat_fxui_vipprivilege_paomadeng_top6_01_wwj` (0.5 MB)
- `ui_panel_main_sub_brawlarenadialogsubpanel` (0.5 MB)
- `ui_panel_main_sub_brawlwaritemssubpanel` (0.5 MB)
- `ui_panel_linkagemonopoly_linkagemonopolyteamrewardpanel` (0.4 MB)
- `ui_panel_brawlarena_brawlarenaactivematchsuccesspanel` (0.4 MB)
- `ui_panel_slg3arena_slg3arenastrengthsettlementpopuppanel` (0.4 MB)
- `ui_panel_plot_fx_plot_yindao_advanced_tech` (0.4 MB)
- `ui_panel_arsenalleaguehonour_arsenalleaguehonourranksubpanel` (0.4 MB)
- `ui_panel_slg3arena_slg3arenacompetitionsettlementpopuppanel` (0.4 MB)
- `ui_panel_chat_fxui_chat_vip_zunxiang_06_jxm` (0.4 MB)
- `ui_panel_chat_fxui_vipprivilege_paomadeng_top5_01_wwj` (0.4 MB)
- `ui_panel_towerdefencegame_tdgamegiftsubpanel` (0.4 MB)
- `ui_panelitem_expert_depend` (0.4 MB)
- `ui_panel_slg3arena_slg3arenacompetitionsignuppanel` (0.4 MB)
- `ui_single_dailyspecial` (0.4 MB)
- `ui_panel_froststarshop_froststarusashopsubpanel` (0.4 MB)
- `ui_panel_player_fxui_hero_skillselecting_pjg_04` (0.4 MB)
- `ui_panel_worldcupredpacket_worldcupredpacketdiamondgetdetailpanel` (0.4 MB)
- `ui_panel_midautumn_fxui_midautumn_lv9_guiling_lxy` (0.4 MB)
- `ui_panel_main_sub_brawlminimapsubpanel` (0.4 MB)
- `ui_panel_chat_fxui_vipprivilege_paomadeng_top4_01_wwj` (0.4 MB)
- … +454

</details>

<details><summary>art (385)</summary>

- `art_actor_towerdefense_activity_2026whitebear_3d_2026whitebear_scene_depend` (45.7 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50040_daya_depend` (7.8 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50038_lotter_depend` (6.8 MB)
- `art_scene_city_got_build_building_furnace_depend` (6.5 MB)
- `art_effect_ui_texture_treasuremap_depend` (5.3 MB)
- `art_scene_world_buildingdress_super_depend` (5.2 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50024_longfei_depend` (4.3 MB)
- `art_scene_city_got_build_building_firecrystal_pikeman_camp_depend` (4.0 MB)
- `art_scene_city_got_build_building_firecrystal_archer_house_depend` (3.6 MB)
- `art_actor_towerdefense_activity_duckmarket_3d_hero_chibl_jebell_depend` (3.5 MB)
- `art_scene_pitchpot_depend` (3.1 MB)
- `art_scene_city_got_build_building_td_wall_depend` (2.9 MB)
- `art_effect_ui_texture_towerdefense_depend` (2.8 MB)
- `art_effect_ui_texture_blackhole_depend` (2.6 MB)
- `art_effect_ui_texture_dress2026_depend` (2.3 MB)
- `art_effect_ui_texture_slg3league_depend` (2.2 MB)
- `art_spine_expert_2d_expert_class_soldier_depend` (2.1 MB)
- `art_effect_ui_texture_slotmatrix_depend` (2.1 MB)
- `art_effect_ui_mesh_new_depend` (1.9 MB)
- `art_spine_ui_fx_a_fxui_kingbattle_1_depend` (1.9 MB)
- `art_spine_ui_duckmarket_zhuanchang_anim_depend` (1.9 MB)
- `art_spine_ui_banner_slg3v3_banner_slg3v3_face_anim_depend` (1.8 MB)
- `art_scene_city_got_build_furnace_2026lookingdreams_depend` (1.8 MB)
- `art_scene_city_got_build_building_coalmine_depend` (1.7 MB)
- `art_scene_city_got_td_common_td_depend` (1.6 MB)
- `art_effect_ui_texture_pitchpot_depend` (1.6 MB)
- `art_effect_ui_texture_childrensday2026_depend` (1.6 MB)
- `art_actorrig_3d_npc_male_config_depend` (1.4 MB)
- `art_scene_anniversary_letter_3d_anniversary_anim_letter_2025_depend` (1.4 MB)
- `art_scene_city_got_build_building_ironworks_depend` (1.4 MB)
- `art_scene_hero_skin_anim_planet_choose_panel_depend` (1.3 MB)
- `art_scene_garden_terrain_terrain_depend` (1.3 MB)
- `art_scene_city_got_build_furnace_slg3league_depend` (1.2 MB)
- `art_effect_ui_texture_dress_dress_castle_building_furnace_childrens2026_day_tex_depend` (1.2 MB)
- `art_scene_city_got_build_building_sawmill_depend` (1.1 MB)
- `art_effect_ui_texture_expert_depend` (1.1 MB)
- `art_scene_city_got_build_furnace_frozenplanet_lv3_anim_anim_noscale_depend` (1.1 MB)
- `art_scene_city_got_build_furnace_frozenplanet_lv6_anim_anim_noscale_depend` (1.1 MB)
- `art_scene_city_got_build_furnace_frozenplanet_lv2_anim_anim_noscale_depend` (1.1 MB)
- `art_scene_city_got_build_furnace_slg3league_anim_anim_noscale_depend` (1.1 MB)
- `art_effect_ui_texture_frozenplanet_exhibit_depend` (1.1 MB)
- `art_effect_ui_material_blackhole_slg_depend` (1.0 MB)
- `art_scene_city_got_td_td_activity_scene_12_depend` (1.0 MB)
- `art_spine_expert_2d_expert_valeria_class_depend` (0.9 MB)
- `art_actor_towerdefense_activity_duckmarket_3d_hero_chibl_jebell_anim_anim_noscale_depend` (0.9 MB)
- `art_scene_city_got_build_building_firecrystal_pikeman_camp_anim_depend` (0.9 MB)
- `art_effect_ui_texture_dress_got_qiancheng_depend` (0.9 MB)
- `art_scene_city_got_build_furnace_frozenplanet_lv4_anim_anim_noscale_depend` (0.9 MB)
- `art_scene_city_got_build_furnace_frozenplanet_lv5_anim_anim_noscale_depend` (0.9 MB)
- `art_scene_city_got_build_building_pikeman_camp_depend` (0.9 MB)
- `art_scene_city_got_build_furnace_frozenplanet_lv6_depend` (0.9 MB)
- `art_effect_ui_texture_dress_got_2026arsenal_league02_depend` (0.9 MB)
- `art_effect_ui_texture_findinggame_depend` (0.8 MB)
- `art_scene_city_got_build_furnace_2025xmas_depend` (0.8 MB)
- `art_scene_city_got_build_furnace_frozenplanet_lv5_depend` (0.8 MB)
- `art_actor_towerdefense_hero_3d_hero_50038_lotter_anim_anim_noscale_depend` (0.8 MB)
- `art_scene_city_got_build_building_explorer_ship_timeline_3d_city_building_explorer_ship_timeline_depend` (0.8 MB)
- `art_effect_ui_texture_castle_dress_42_shijiebei2026_depend` (0.8 MB)
- `art_spine_expert_2d_expert_valeria_depend` (0.8 MB)
- `art_scene_city_got_build_building_firecrystal_expert_academy_depend` (0.8 MB)
- … +325

</details>

<details><summary>scene (179)</summary>

- `scene_starvip_starviptablescene` (3.8 MB)
- `scene_starvip_planet_area_6` (3.0 MB)
- `scene_vvip_vip_skin_planet_get_panel` (2.9 MB)
- `scene_starvip_planet_area_5` (2.3 MB)
- `scene_vvip_vvip_castle_dress_51` (2.3 MB)
- `scene_starvip_planet_area_4` (2.2 MB)
- `scene_starvip_planet_area_3` (2.0 MB)
- `scene_vvip_vvip_castle_dress_50` (1.8 MB)
- `scene_vvip_vvip_castle_dress_52` (1.6 MB)
- `scene_vvip_vvip_castle_dress_53` (1.6 MB)
- `scene_starvip_planet_area_1` (1.6 MB)
- `scene_activity_pitchpot_pitchpot_scene_01` (1.5 MB)
- `scene_starvip_planet_area_2` (1.5 MB)
- `scene_slg3arena_arena_scene_01` (1.2 MB)
- `scene_activity_pitchpot_pitchpot_bottle_01` (1.0 MB)
- `scene_activity_anniversary2026_got_anniversary2025letter` (1.0 MB)
- `scene_brawlwar_scene_planet_brawlwar_scene_planet_02` (1.0 MB)
- `scene_brawlwar_scene_planet_brawlwar_scene_planet_01` (1.0 MB)
- `scene_city_got_building_barrack_spear_camp_soldier` (0.7 MB)
- `scene_city_map_maproot_td_07` (0.7 MB)
- `scene_city_got_arena_arenaposternode` (0.7 MB)
- `scene_city_map_maproot_td_05` (0.7 MB)
- `scene_battle_effect_got_50036_luna_fx_50036_hero_luna_skillxp_hit_dkb` (0.7 MB)
- `scene_brawlwar_scene_planet_brawlwar_scene_planet_03` (0.6 MB)
- `scene_battle_effect_got_50035_liz_fx_50035_hero_liz_xpskill_baodian_hjf01` (0.6 MB)
- `scene_activity_pitchpot_activity_scene_npc_pitchpot` (0.6 MB)
- `scene_city_got_building_bell_anim_01` (0.6 MB)
- `scene_city_map_maproot_td_06` (0.5 MB)
- `scene_activity_pitchpot_pitchpot_bottle_02_start` (0.5 MB)
- `scene_activity_pitchpot_pitchpot_bottle_02` (0.5 MB)
- `scene_city_map_maproot_td_03` (0.5 MB)
- `scene_battle_effect_got_50035_liz_fx_50035_hero_liz_xpskill_xishou02_hjf01` (0.5 MB)
- `scene_brawlwar_scene_planet_brawlwar_scene_planet_04` (0.5 MB)
- `scene_battle_effect_got_50039_bayard_fx_50039_hero_bayard_xp_hit_wsy` (0.4 MB)
- `scene_vvip_vvip_castle_dress_48` (0.4 MB)
- `scene_vvip_vvip_castle_dress_49` (0.4 MB)
- `scene_vvip_vvip_castle_dress_48_ru` (0.4 MB)
- `scene_city_got_timeline_fx_new_guide_anim_01_6_2_goods_2` (0.4 MB)
- `scene_battle_bullet_fx_50035_hero_liz_xpskill_dandao` (0.4 MB)
- `scene_vvip_vvip_castle_dress_49_ru` (0.4 MB)
- `scene_battle_effect_got_50036_luna_fx_50036_hero_luna_skillxp_xuli_dkb` (0.4 MB)
- `scene_city_got_building_barrack_archer_camp_soldier` (0.4 MB)
- `scene_battle_effect_got_50034_diego_fx_50034_hero_diego_skillxp_hit_lq` (0.4 MB)
- `scene_city_map_maproot_td_04` (0.4 MB)
- `scene_city_map_maproot_td_01` (0.4 MB)
- `scene_vvip_vvip_castle_dress_47` (0.4 MB)
- `scene_city_map_maproot_td_02` (0.4 MB)
- `scene_vvip_vvip_castle_dress_46` (0.4 MB)
- `scene_city_got_timeline_fx_new_guide_anim_01_6_2_goods1` (0.3 MB)
- `scene_battle_effect_got_50034_diego_fx_50034_hero_diego_skillxp_lq` (0.3 MB)
- `scene_city_got_building_barrack_infantry_camp_soldier` (0.3 MB)
- `scene_vvip_vvip_castle_dress_45` (0.3 MB)
- `scene_city_got_timeline_fx_new_guide_anim_01_6_2_goods` (0.3 MB)
- `scene_battle_effect_got_50036_luna_fx_50036_hero_luna_skill1_xuli` (0.3 MB)
- `scene_battle_effect_got_50035_liz_fx_50035_hero_liz_xpskill_dguang_hjf01` (0.3 MB)
- `scene_city_got_building_city_anim_building_expert_academy_01` (0.3 MB)
- `scene_battle_effect_got_50036_luna_fx_50036_hero_luna_zhuanshu_skill_hit` (0.3 MB)
- `scene_battle_effect_got_50039_bayard_fx_50039_hero_bayard_xp_xuli_fly_wsy_02` (0.3 MB)
- `scene_battle_effect_got_50035_liz_fx_50035_hero_liz_zhuanshuhit` (0.3 MB)
- `scene_city_map_maproot_td_16` (0.3 MB)
- … +119

</details>

<details><summary>spine (76)</summary>

- `spine_got_expert_2d_expert_kacey` (1.4 MB)
- `spine_got_expert_2d_expert_ronne` (0.8 MB)
- `spine_got_expert_2d_expert_ronne_class` (0.8 MB)
- `spine_got_expert_2d_expert_baldur_class` (0.8 MB)
- `spine_got_expert_2d_expert_kacey_class` (0.8 MB)
- `spine_got_expert_2d_expert_fabian_class` (0.7 MB)
- `spine_got_expert_2d_expert_fabian` (0.7 MB)
- `spine_got_expert_2d_expert_cyril_class` (0.7 MB)
- `spine_got_expert_2d_expert_holger` (0.7 MB)
- `spine_got_expert_2d_expert_cyril_rest` (0.7 MB)
- `spine_got_expert_2d_expert_holger_class` (0.7 MB)
- `spine_got_expert_2d_expert_romulus` (0.7 MB)
- `spine_got_expert_2d_expert_ronne_rest` (0.7 MB)
- `spine_got_expert_2d_expert_romulus_class` (0.7 MB)
- `spine_got_expert_2d_expert_baldur` (0.7 MB)
- `spine_got_expert_2d_expert_fabian_rest` (0.7 MB)
- `spine_got_expert_2d_expert_baldur_rest` (0.7 MB)
- `spine_got_expert_2d_expert_kacey_rest` (0.7 MB)
- `spine_got_expert_2d_expert_cyril` (0.7 MB)
- `spine_got_expert_2d_expert_holger_rest` (0.7 MB)
- `spine_got_expert_2d_expert_romulus_rest` (0.6 MB)
- `spine_got_expert_2d_expert_agnes_class` (0.6 MB)
- `spine_got_expert_2d_expert_agnes_rest` (0.6 MB)
- `spine_got_expert_2d_expert_agnes` (0.6 MB)
- `spine_ui_banner_luandou_anim` (0.3 MB)
- `spine_christmas2026_christmasslotmatrix_christmas01_anim` (0.2 MB)
- `spine_christmas2026_christmasslotmatrix_christmas02_anim` (0.2 MB)
- `spine_midautumn_festival2026_midautumnfestivalslotmatrix_dengzhen02_anim` (0.2 MB)
- `spine_got_expert_2d_expert_emoji_struggle` (0.2 MB)
- `spine_got_expert_2d_expert_emoji_good` (0.2 MB)
- `spine_got_expert_2d_expert_emoji_exhaustion` (0.1 MB)
- `spine_got_expert_2d_expert_emoji_thinking` (0.1 MB)
- `spine_midautumn_festival2026_midautumnfestivalslotmatrix_dengzhen01_anim` (0.1 MB)
- `spine_got_expert_2d_expert_emoji_sleepy` (0.1 MB)
- `spine_got_worldcupredpacket_fxui_worldcupredpacket_redpacketdiamondgetdetailpanel_jxm` (0.1 MB)
- `spine_got_expert_2d_expert_emoji_hungry` (0.1 MB)
- `spine_got_expert_2d_expert_valeria_class_1` (0.0 MB)
- `spine_got_expert_2d_expert_valeria_rest_1` (0.0 MB)
- `spine_got_expert_2d_expert_valeria_rest` (0.0 MB)
- `spine_got_expert_2d_expert_justus_class` (0.0 MB)
- `spine_got_expert_2d_expert_justus_rest` (0.0 MB)
- `spine_got_expert_2d_expert_valeria_class` (0.0 MB)
- `spine_got_expert_2d_expert_class_soldier` (0.0 MB)
- `spine_got_expert_2d_expert_valeria_1` (0.0 MB)
- `spine_got_expert_2d_expert_valeria` (0.0 MB)
- `spine_got_expert_2d_expert_justus` (0.0 MB)
- `spine_ui_fxui_a_fxui_kingbattle_1` (0.0 MB)
- `spine_got_expert_2d_expert_class_survivor` (0.0 MB)
- `spine_ui_banner_slg3v3_face_anim` (0.0 MB)
- `spine_got_ui_polarexpedition_polarexpedition_blue_ship04_anim` (0.0 MB)
- `spine_ui_slotmatrix_christmas_box_spine_01` (0.0 MB)
- `spine_ui_slotmatrix_christmas_box_spine_02` (0.0 MB)
- `spine_got_ui_fxui_ani_polarexpedition_orange_zidong_yly_anim` (0.0 MB)
- `spine_got_ui_polarexpedition_polarexpedition_blue_ship01_anim` (0.0 MB)
- `spine_got_ui_polarexpedition_polarexpedition_blue_ship02_anim` (0.0 MB)
- `spine_got_ui_polarexpedition_polarexpedition_blue_ship03_anim` (0.0 MB)
- `spine_ui_banner_arsenalleague_upcoming_anim` (0.0 MB)
- `spine_ui_icon_con_luckybox_worldcup_01_anim` (0.0 MB)
- `spine_ui_brawlwar_expression_non_match` (0.0 MB)
- `spine_ui_brawlwar_expression_match` (0.0 MB)
- … +16

</details>

<details><summary>atlas (34)</summary>

- `atlas_ui_towerdefence_icon` (4.1 MB)
- `atlas_ui_towerdefence_icon_01` (4.1 MB)
- `atlas_world_buildingdress5` (2.5 MB)
- `atlas_ui_skin_icon_frame` (2.0 MB)
- `atlas_ui_skin_icon_build` (2.0 MB)
- `atlas_ui_towerdefencegame` (1.1 MB)
- `atlas_ui_box_01` (1.0 MB)
- `atlas_ui_td_skill` (1.0 MB)
- `atlas_ui_skin_icon_march` (1.0 MB)
- `atlas_ui_skin_icon_nameplate` (1.0 MB)
- `atlas_ui_skin_icon_other` (1.0 MB)
- `atlas_fx_monopoly` (0.9 MB)
- `atlas_ui_common_second` (0.5 MB)
- `atlas_ui_activities_01` (0.5 MB)
- `atlas_ui_alliance_01` (0.5 MB)
- `atlas_ui_peachfestival` (0.5 MB)
- `atlas_ui_bearfestival` (0.5 MB)
- `atlas_ui_children2026` (0.5 MB)
- `atlas_ui_icon_decorate_frame` (0.5 MB)
- `atlas_ui_icon_expert` (0.5 MB)
- `atlas_ui_icon_decorate_build` (0.5 MB)
- `atlas_ui_icon_decorate_march` (0.5 MB)
- `atlas_ui_icon_decorate_nameplate` (0.5 MB)
- `atlas_ui_towerdefence_icon_02` (0.5 MB)
- `atlas_ui_treasureroomnew` (0.3 MB)
- `atlas_ui_decorate_background_01` (0.3 MB)
- `atlas_fx_brawlwar` (0.3 MB)
- `atlas_ui_sportsmeet2026` (0.1 MB)
- `atlas_fx_monopoly_ptsz` (0.1 MB)
- `atlas_fx_battlepasscheck` (0.1 MB)
- `atlas_fx_monopoly_gjsz` (0.1 MB)
- `atlas_fx_children2026` (0.1 MB)
- `atlas_ui_common_01` (0.0 MB)
- `atlas_fx_midautumn` (0.0 MB)

</details>

<details><summary>actor_battle_battle (18)</summary>

- `actor_battle_battle_world_monster_027_red` (0.4 MB)
- `actor_battle_battle_world_monster_006_red` (0.4 MB)
- `actor_battle_battle_world_monster_003_red` (0.4 MB)
- `actor_battle_battle_world_monster_012_red` (0.3 MB)
- `actor_battle_battle_hero_captain_hendrik_octopus_red` (0.3 MB)
- `actor_battle_battle_hero_captain_hendrik_octopus` (0.3 MB)
- `actor_battle_battle_hero_50035_liz_red` (0.0 MB)
- `actor_battle_battle_hero_50036_luna_red` (0.0 MB)
- `actor_battle_battle_hero_50036_luna` (0.0 MB)
- `actor_battle_battle_hero_50040_daya` (0.0 MB)
- `actor_battle_battle_hero_50040_daya_red` (0.0 MB)
- `actor_battle_battle_hero_50039_bayard` (0.0 MB)
- `actor_battle_battle_hero_50039_bayard_red` (0.0 MB)
- `actor_battle_battle_hero_50038_lotter` (0.0 MB)
- `actor_battle_battle_hero_50038_lotter_red` (0.0 MB)
- `actor_battle_battle_hero_50035_liz` (0.0 MB)
- `actor_battle_battle_hero_50034_diego` (0.0 MB)
- `actor_battle_battle_hero_50034_diego_red` (0.0 MB)

</details>

<details><summary>actor_activity_peachfestival (3)</summary>

- `actor_activity_peachfestival_t_festival_npc_peachfestival_fish` (0.0 MB)
- `actor_activity_peachfestival_m_festival_npc_peachfestival_fish` (0.0 MB)
- `actor_activity_peachfestival_3d_festival_npc_peachfestival_fish` (0.0 MB)

</details>

<details><summary>backup (3)</summary>

- `backup_art_actor_npc_common_anim_male_depend` (1.1 MB)
- `backup_art_actor_npc_common_anim_female_depend` (0.2 MB)
- `backup_art_actor_hero_3d_hero_captain_hendrik_anim_battle_depend` (0.1 MB)

</details>

<details><summary>config (3)</summary>

- `config_gamepadcursorsettings` (0.0 MB)
- `config_cdnretrydata` (0.0 MB)
- `config_vfxtexturelibrary` (0.0 MB)

</details>

<details><summary>actor_hero_3d (2)</summary>

- `actor_hero_3d_hero_exhibit_10006_king` (4.5 MB)
- `actor_hero_3d_hero_exhibit_10007_king` (4.3 MB)

</details>

<details><summary>3party (1)</summary>

- `3party_spine_runtime_spine-unity_depend` (0.0 MB)

</details>

<details><summary>actor_activity_duckmarket (1)</summary>

- `actor_activity_duckmarket_3d_hero_chibl_jebell` (0.1 MB)

</details>

<details><summary>mat (1)</summary>

- `mat_imagepurecolor` (0.0 MB)

</details>

## Bundles removidos (presentes só em 1.9.5)

| prefixo | qtd | tamanho |
|---|---|---|
| towerdefense | 477 | 91.2 MB |
| scene | 470 | 115.2 MB |
| art | 235 | 218.0 MB |
| ui | 131 | 50.2 MB |
| actor_hero_3d | 26 | 10.1 MB |
| atlas | 22 | 60.9 MB |
| actor_climbtower_3d | 15 | 3.6 MB |
| actor_battle_battle | 10 | 2.2 MB |
| actor_climbtower_monster | 5 | 0.7 MB |
| actor_world_soldier | 3 | 0.0 MB |
| actor_world_part | 2 | 0.0 MB |
| actor_2025halloween_3d | 1 | 10.6 MB |

<details><summary>towerdefense (477)</summary>

- `towerdefense_effect_exhibit_fx_3d_city_hero_50021_zoe_dgnyh_old` (1.1 MB)
- `towerdefense_effect_exhibit_fx_3d_city_hero_50021_zoe_dgnyh` (1.1 MB)
- `towerdefense_effect_buiding_fx_castle_dress_12` (1.0 MB)
- `towerdefense_config_unitlevelnew` (0.9 MB)
- `towerdefense_effect_buiding_dress_castle_dress_7_fx_3d_world_build_dress_7_egg` (0.9 MB)
- `towerdefense_effect_march_fx_3d_world_march_skin_fengxuezhiyi_attack` (0.7 MB)
- `towerdefense_effect_fxui_fxui_kingbattle` (0.6 MB)
- `towerdefense_effect_buiding_dress_castle_dress_17_fx_3d_castle_dress_17_hit001` (0.6 MB)
- `towerdefense_effect_buiding_city_2025food_fx_3d_city_2025food_always001` (0.5 MB)
- `towerdefense_effect_fxui_fx_appstoreratingpanel_01_back` (0.5 MB)
- `towerdefense_character_td_monster_51001_bomber_kulou` (0.5 MB)
- `towerdefense_effect_buiding_dress_castle_dress_17_fx_3d_castle_dress_17_always001` (0.5 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50019_titan_stand02_01` (0.5 MB)
- `towerdefense_effect_buiding_furnace_lost_temple_castle_dress_13` (0.5 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50002_edwin` (0.5 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50019_titan_stand02_03` (0.5 MB)
- `towerdefense_effect_march_fx_world_march_draw_rabbit_move01_caidan001` (0.5 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50023_alcar_normalcolor` (0.5 MB)
- `towerdefense_effect_march_fx_world_march_draw_rabbit_attack_fire001` (0.4 MB)
- `towerdefense_effect_buiding_furnace_lost_temple_fx_building_castle_13` (0.4 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50030_sophia_stand2_xs` (0.4 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50010_eric_start` (0.4 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50014_margot_stand2_qiao01_dkb` (0.4 MB)
- `towerdefense_character_td_monster_20100_kulou` (0.4 MB)
- `towerdefense_effect_timeline_fx_new_guide_anim_01_6_2_goods_2` (0.4 MB)
- `towerdefense_effect_fxui_fxui_kingbattle_start` (0.4 MB)
- `towerdefense_effect_lod_fx_50011_amadeus_skillxp_lod` (0.4 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50007_nyhfashe` (0.4 MB)
- `towerdefense_effect_buiding_furnace_lost_temple_skin_anim_building_furnace_lost_temple_1` (0.4 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50001_smith_zadi` (0.4 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50020_jaeger_stand2_06` (0.4 MB)
- `towerdefense_effect_march_fx_world_march_skin_iron_whale_attack` (0.4 MB)
- `towerdefense_effect_march_fx_march_furnace_frozenplanet_heidongend_xsp` (0.4 MB)
- `towerdefense_effect_buiding_dress_castle_dress_17_fx_3d_castle_dress_17_hit002` (0.4 MB)
- `towerdefense_effect_fxui_fxui_dress_touxiang_esater_2024_a_1` (0.4 MB)
- `towerdefense_effect_buiding_furnace_lost_temple_fx_skin_anim_building_furnace_lost_temple_effect` (0.4 MB)
- `towerdefense_effect_march_fx_march_3d_king_dandao` (0.4 MB)
- `towerdefense_effect_buiding_skin_anim_building_furnace_frozenplanet_fx_march_furnace_frozenplanet_heidongend_xsp_city` (0.4 MB)
- `towerdefense_effect_buiding_furnace_lost_temple_fx_building_castle_13_effect` (0.4 MB)
- `towerdefense_effect_march_fx_world_march_draw_rabbit_attack_bullet001` (0.4 MB)
- `towerdefense_character_td_monster_30100_kulou` (0.3 MB)
- `towerdefense_effect_timeline_fx_new_guide_anim_01_6_2_goods1` (0.3 MB)
- `towerdefense_effect_march_march_3d_king_eff` (0.3 MB)
- `towerdefense_character_td_monster_51008_badking_kulou` (0.3 MB)
- `towerdefense_effect_march_fx_march_3d_unicorn_boom01` (0.3 MB)
- `towerdefense_effect_buiding_castle_dress_6_fx_castle_dress_6_03` (0.3 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50027_mikoto_stand2_fenwei_lwr` (0.3 MB)
- `towerdefense_effect_buiding_fx_castle_dress_11_chengbao` (0.3 MB)
- `towerdefense_effect_timeline_fx_new_guide_anim_01_6_2_goods` (0.3 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50019_titan_stand01_01` (0.3 MB)
- `towerdefense_effect_march_fx_world_march_draw_rabbit_move01_trail001` (0.3 MB)
- `towerdefense_effect_march_fx_world_march_draw_rabbit_move01_trail002` (0.3 MB)
- `towerdefense_effect_fxui_fx_aliance_liexiong_gx_04` (0.3 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50030_sophia_stand2_test` (0.3 MB)
- `towerdefense_effect_buiding_fx_river_1` (0.3 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50000_forst_start` (0.3 MB)
- `towerdefense_effect_exhibit_fx_3d_hero_exhibit_50030_sophia_stand2_zaohuan` (0.3 MB)
- `towerdefense_effect_exhibit_fx_hero_exhibit_50021_zoe_nyh_dg` (0.3 MB)
- `towerdefense_effect_buiding_fx_castle_dress_11_dummy001` (0.3 MB)
- `towerdefense_effect_exhibit_fx_world_exhibit_skin_mammoth_nyh_shuibao` (0.3 MB)
- … +417

</details>

<details><summary>scene (470)</summary>

- `scene_hero_supremacy_exhibit_scene` (10.3 MB)
- `scene_alliancewar_league_supremacy_scene` (7.6 MB)
- `scene_world_building_building_feast_10` (2.9 MB)
- `scene_world_building_3d_world_building_bouncingpumpkin` (2.2 MB)
- `scene_city_got_building_skin_anim_building_furnace_1st` (2.2 MB)
- `scene_city_got_building_skin_anim_building_furnace_2025guoqing` (2.1 MB)
- `scene_world_griditem_aura_fx_251100301` (1.9 MB)
- `scene_city_got_building_skin_anim_building_furnace_drake_tower` (1.8 MB)
- `scene_climbtower_climbtower_scene_03_01` (1.6 MB)
- `scene_city_got_building_skin_anim_building_furnace_2025thanksgiving` (1.6 MB)
- `scene_climbtower_climbtower_scene_06_01` (1.5 MB)
- `scene_climbtower_climbtower_scene_02_01` (1.5 MB)
- `scene_climbtower_climbtower_scene_05_01` (1.5 MB)
- `scene_climbtower_climbtower_scene_01_01` (1.4 MB)
- `scene_climbtower_climbtower_scene_04_01` (1.4 MB)
- `scene_city_got_building_skin_anim_building_furnace_easter` (1.3 MB)
- `scene_world_building_3d_castle_dress_26` (1.3 MB)
- `scene_world_building_building_feast_09` (1.3 MB)
- `scene_climbtower_climbtower_scene_01_02` (1.2 MB)
- `scene_climbtower_climbtower_scene_02_02` (1.2 MB)
- `scene_climbtower_climbtower_scene_04_02` (1.2 MB)
- `scene_climbtower_climbtower_scene_04_03` (1.2 MB)
- `scene_climbtower_climbtower_scene_05_02` (1.2 MB)
- `scene_climbtower_climbtower_scene_05_03` (1.2 MB)
- `scene_climbtower_climbtower_scene_01_03` (1.2 MB)
- `scene_climbtower_climbtower_scene_02_03` (1.2 MB)
- `scene_alliancewar_3d_alliance_puece_blu` (1.2 MB)
- `scene_city_got_building_city_building_firecrystal_furnace_03` (1.2 MB)
- `scene_alliancewar_3d_alliance_puece_red` (1.1 MB)
- `scene_world_building_building_feast_07` (1.1 MB)
- `scene_city_got_building_skin_anim_building_furnace_penguin_castle` (1.1 MB)
- `scene_city_got_building_city_building_firecrystal_furnace_02` (1.0 MB)
- `scene_city_got_plot_new_guide_anim_01_11_1_w_kulou` (1.0 MB)
- `scene_world_building_building_feast_08` (1.0 MB)
- `scene_city_got_building_skin_anim_building_furnace_frozenplanet` (0.9 MB)
- `scene_city_got_plot_new_guide_anim_01_1_kulou` (0.9 MB)
- `scene_world_griditem_aura_fx_251100201` (0.9 MB)
- `scene_world_griditem_aura_fx_293300101` (0.9 MB)
- `scene_world_building_3d_world_building_clownbox` (0.8 MB)
- `scene_city_got_building_skin_anim_building_furnace_2025xmas` (0.8 MB)
- `scene_city_got_building_skin_anim_building_furnace_sleepy_lion` (0.8 MB)
- `scene_hero_throne_exhibit_scene` (0.8 MB)
- `scene_city_got_building_skin_anim_building_furnace_frost_dragon` (0.7 MB)
- `scene_city_got_building_skin_anim_building_furnace_2025halloween` (0.7 MB)
- `scene_city_got_plot_new_guide_anim_01_11_1_kulou` (0.7 MB)
- `scene_world_building_fx_fx_building_feast_07_jinxing_jxm` (0.6 MB)
- `scene_world_movecity_fx_dress_qiancheng_teleporter_supremacy_gx_01` (0.6 MB)
- `scene_city_got_construction_city_anim_building_construction_gate02b_04_06` (0.5 MB)
- `scene_city_got_construction_city_anim_building_construction_gate03_04_06` (0.5 MB)
- `scene_world_building_feast_16` (0.5 MB)
- `scene_world_building_fx_fx_world_wenhao_lxy` (0.5 MB)
- `scene_city_got_building_skin_anim_building_furnace_2025food` (0.5 MB)
- `scene_city_got_building_skin_anim_building_furnace_2025moon` (0.5 MB)
- `scene_world_building_feast_15` (0.4 MB)
- `scene_world_building_feast_14` (0.4 MB)
- `scene_world_building_fx_fx_supremacy_feast_07_chuxian_jxm` (0.4 MB)
- `scene_world_building_3d_world_building_alliance_bomb` (0.4 MB)
- `scene_city_got_building_skin_anim_building_furnace_childrens_day` (0.4 MB)
- `scene_city_got_building_skin_anim_building_furnace_lost_temple` (0.4 MB)
- `scene_city_got_construction_city_anim_building_construction_gate02b_01_03` (0.4 MB)
- … +410

</details>

<details><summary>art (235)</summary>

- `art_scene_city_got_build_depend` (36.8 MB)
- `art_scene_world_building_stronghold_01_03_depend` (12.3 MB)
- `art_scene_world_building_stronghold_01_02_depend` (11.8 MB)
- `art_scene_world_building_stronghold_01_01_depend` (9.5 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50009_helga_depend` (8.8 MB)
- `art_scene_city_got_firecrystal_archer_house_depend` (7.7 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50011_amadeus_depend` (7.1 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50021_zoe_depend` (6.3 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50000_forst_depend` (6.3 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50012_jebell_depend` (5.6 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50008_diana_depend` (3.8 MB)
- `art_scene_city_got_furnace_depend` (3.7 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50005_gordon_depend` (3.7 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50007_pavlichenko_depend` (3.6 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50017_saul_depend` (3.3 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50001_smith_depend` (3.1 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50004_howard_depend` (2.8 MB)
- `art_scene_leaguesupremacy_depend` (2.8 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50003_olive_depend` (2.7 MB)
- `art_scene_city_got_firecrystal_pikeman_camp_depend` (2.6 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50005_gordon_anim_depend` (2.5 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50002_edwin_depend` (2.5 MB)
- `art_actor_dress_3d_world_exhibit_skin_ice_dragon_01_depend` (2.4 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50008_diana_anim_depend` (2.0 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50009_helga_anim_anim_noscale_depend` (2.0 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50006_queen_anim_depend` (1.9 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50017_saul_anim_noscale_depend` (1.7 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_2025halloween_depend` (1.7 MB)
- `art_scene_city_got_coalmine_depend` (1.7 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50012_jebell_anim_depend` (1.6 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_frost_dragon_depend` (1.6 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50000_forst_anim_depend` (1.4 MB)
- `art_scene_city_got_pier_depend` (1.4 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50011_amadeus_anim_anim_noscale_depend` (1.4 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_frost_dragon_anim_depend` (1.3 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_2025thanksgiving_depend` (1.2 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50001_smith_anim_depend` (1.2 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50003_olive_anim_depend` (1.1 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50004_howard_anim_depend` (1.1 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_drake_tower_depend` (1.0 MB)
- `art_actor_build_3d_world_build_dress_7_depend` (1.0 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50002_edwin_anim_anim_noscale_depend` (0.9 MB)
- `art_scene_city_got_firecrystal_pikeman_camp_anim_depend` (0.9 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_penguin_castle_anim_depend` (0.9 MB)
- `art_scene_city_got_build_3d_city_building_explorer_ship_timeline_depend` (0.8 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_drake_tower_anim_depend` (0.8 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_easter_depend` (0.8 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_2025thanksgiving_anim_anim_noscale_depend` (0.8 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_2025halloween_anim_anim_noscale_depend` (0.7 MB)
- `art_actor_towerdefense_hero_3d_hero_exhibit_50007_pavlichenko_anim_anim_noscale_depend` (0.7 MB)
- `art_scene_city_law_decorate_depend` (0.7 MB)
- `art_actorrig_3d_castle_dress_14_02_config_depend` (0.7 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_2025moon_anim_anim_noscale_depend` (0.6 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_atlantis_depend` (0.6 MB)
- `art_scene_city_got_firecrystal_infantry_quarters_depend` (0.6 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_penguin_castle_depend` (0.6 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_1st_depend` (0.6 MB)
- `art_actorrig_3d_castle_dress_14_01_config_depend` (0.6 MB)
- `art_scene_city_got_skin_3d_skin_building_furnace_2025moon_depend` (0.5 MB)
- `art_scene_city_got_alchemist_workshop_depend` (0.5 MB)
- … +175

</details>

<details><summary>ui (131)</summary>

- `ui_single_guide_part_1` (4.3 MB)
- `ui_panel_dress_fxui_dress_anniversary_oneyear_jxm` (2.2 MB)
- `ui_panel_dress_fxui_dress_touxiang_middle_jxm` (2.1 MB)
- `ui_panel_dress_fx_dress_wsj_gx_01` (1.6 MB)
- `ui_panel_dress_fxui_dress_touxiang_fishing_jxm` (1.5 MB)
- `ui_panel_dress_fxui_dress_touxiang_spring2026_jxm` (1.2 MB)
- `ui_panel_dress_fxui_dress_touxiang_2025food` (1.1 MB)
- `ui_panel_dress_fx_dress_diaoyu_tx_wwj` (1.0 MB)
- `ui_panel_dress_fxui_dress_touxiang_bazhu_jxm` (1.0 MB)
- `ui_panel_dress_fx_dress_zqgwtx_01_gx_old` (1.0 MB)
- `ui_panel_dress_fx_dress_etjtx_01_gx` (0.9 MB)
- `ui_panel_frozentreasure_halloweeneventfrozentreasuresubpanel` (0.9 MB)
- `ui_panel_dress_fxui_dress_24christmas_wwj` (0.8 MB)
- `ui_panel_dress_fxui_dress_touxiang_cn2026yuandan` (0.8 MB)
- `ui_panel_interactive_halloweeninteractivesubpanel` (0.7 MB)
- `ui_panel_city_spear_camp_soldier` (0.7 MB)
- `ui_panel_dress_fxui_decorate_frame_tx_cmg` (0.7 MB)
- `ui_panel_arena_arenaposternode` (0.7 MB)
- `ui_panel_dress_fxui_dress_touxiang_threeallianceswar_lxy` (0.7 MB)
- `ui_panel_dress_fx_dress_touxiang_cn2025guoqing` (0.7 MB)
- `ui_panel_dress_fxui_dress_touxiang_bazhuzhiyuan_jxm` (0.7 MB)
- `ui_panel_dress_fxui_dress_touxiang_esater_jxm` (0.6 MB)
- `ui_panel_dress_fxui_dress_dafuweng_tx_wwj` (0.6 MB)
- `ui_panel_dress_fxui_dress_touxiang_moguc_yly` (0.6 MB)
- `ui_panel_dress_fxui_dress_kaifu_txk_yly` (0.6 MB)
- `ui_panel_dress_fxui_dress_snowking_head_lxy` (0.6 MB)
- `ui_panel_city_bell_anim_01` (0.6 MB)
- `ui_panel_dress_fx_dress_baozhuzhan_tqcj_gx_01` (0.6 MB)
- `ui_panel_dress_fxui_dress_minewar_tx_wwj` (0.5 MB)
- `ui_panel_dress_fx_dress_zhongdongyue_gx_01` (0.5 MB)
- `ui_panel_dress_fxui_dress_kuanian2025_txk_yly` (0.5 MB)
- `ui_panel_dress_fxui_dress_ganenjie_tx_wwj` (0.5 MB)
- `ui_panel_dress_fxui_dress_touxiang_chengjiandr_yly` (0.4 MB)
- `ui_panel_city_archer_camp_soldier` (0.4 MB)
- `ui_panel_redpacket_vvipredpacketdiamondgetdetailpanel` (0.4 MB)
- `ui_panel_dress_fxui_dress_ancient_tx_01` (0.4 MB)
- `ui_panel_dress_fxui_dress_touxiang_esater_2024_jxm` (0.4 MB)
- `ui_panel_dress_fxui_dress_touxiang_esater_jxm_01` (0.4 MB)
- `ui_panel_dress_fxui_dress_touxiang_2025moon` (0.4 MB)
- `ui_panel_worldscene_thanksgiving_fxui_thanksgiving_jiacan_3d_haohua_jxm` (0.4 MB)
- `ui_panel_worldscene_thanksgiving_fxui_thanksgiving_jiacan_3d_super_jxm` (0.3 MB)
- `ui_panel_city_infantry_camp_soldier` (0.3 MB)
- `ui_panel_worldscene_musicfestival2025_fxui_musicfestival2025_jiacan_3d_haohua_jxm` (0.3 MB)
- `ui_panel_worldscene_musicfestival2025_fxui_musicfestival2025_jiacan_3d_super_jxm` (0.3 MB)
- `ui_panel_dress_fxui_dress_main630_tx02` (0.3 MB)
- `ui_panel_accumulativeactivity_christmasaccumulativeactivitysubpanel` (0.3 MB)
- `ui_panel_accumulativeactivity_halloweenaccumulativeactivitysubpanel` (0.3 MB)
- `ui_panel_dress_fxui_dress_touxiang_fire` (0.3 MB)
- `ui_panel_dress_fx_dress_zqgwtx_01_gx` (0.3 MB)
- `ui_panel_dress_fxui_dress_happybrithday_head_lxy` (0.3 MB)
- `ui_panel_dress_fxui_dress_touxiang_fav51_jxm` (0.3 MB)
- `ui_panel_guide_fx_plot_effect_bubble_001_kulou` (0.3 MB)
- `ui_panel_redpacket_vvipredpacketdiamondpanel` (0.3 MB)
- `ui_panel_dress_fxui_dress_twitter_tx_wwj` (0.3 MB)
- `ui_panel_worldscene_thanksgiving_fxui_thanksgiving_jiacan_3d_gaoji_jxm` (0.3 MB)
- `ui_panel_threedayshop_threedaystorepanel` (0.3 MB)
- `ui_panel_threedayshop_threedaystoreeidpanel` (0.3 MB)
- `ui_panel_dress_fxui_dress_touxiang_chrismas_jxm` (0.3 MB)
- `ui_panel_dress_fxui_dress_valentine2026_man_yly` (0.3 MB)
- `ui_panel_worldscene_musicfestival2025_fxui_musicfestival2025_jiacan_3d_gaoji_jxm` (0.2 MB)
- … +71

</details>

<details><summary>actor_hero_3d (26)</summary>

- `actor_hero_3d_hero_recruit_50004_howard` (0.9 MB)
- `actor_hero_3d_hero_exhibit_50004_howard` (0.9 MB)
- `actor_hero_3d_hero_exhibit_50012_jebell` (0.6 MB)
- `actor_hero_3d_hero_recruit_50012_jebell` (0.6 MB)
- `actor_hero_3d_hero_exhibit_50003_olive` (0.5 MB)
- `actor_hero_3d_hero_recruit_50003_olive` (0.5 MB)
- `actor_hero_3d_hero_exhibit_50007_pavlichenko` (0.4 MB)
- `actor_hero_3d_hero_recruit_50007_pavlichenko` (0.4 MB)
- `actor_hero_3d_hero_recruit_50001_smith` (0.4 MB)
- `actor_hero_3d_hero_exhibit_50001_smith` (0.4 MB)
- `actor_hero_3d_hero_exhibit_50009_helga` (0.4 MB)
- `actor_hero_3d_hero_recruit_50009_helga` (0.4 MB)
- `actor_hero_3d_hero_exhibit_50000_forst` (0.4 MB)
- `actor_hero_3d_hero_recruit_50000_forst` (0.4 MB)
- `actor_hero_3d_hero_recruit_50005_gordon` (0.3 MB)
- `actor_hero_3d_hero_exhibit_50005_gordon` (0.3 MB)
- `actor_hero_3d_hero_exhibit_50017_saul` (0.3 MB)
- `actor_hero_3d_hero_recruit_50017_saul` (0.3 MB)
- `actor_hero_3d_hero_exhibit_50002_edwin` (0.3 MB)
- `actor_hero_3d_hero_recruit_50002_edwin` (0.3 MB)
- `actor_hero_3d_hero_exhibit_50011_amadeus` (0.3 MB)
- `actor_hero_3d_hero_recruit_50011_amadeus` (0.3 MB)
- `actor_hero_3d_hero_exhibit_50006_queen` (0.2 MB)
- `actor_hero_3d_hero_recruit_50006_queen` (0.2 MB)
- `actor_hero_3d_hero_recruit_50008_diana` (0.0 MB)
- `actor_hero_3d_hero_exhibit_50008_diana` (0.0 MB)

</details>

<details><summary>atlas (22)</summary>

- `atlas_world_feast_07_07` (5.5 MB)
- `atlas_ui_skin_icon` (4.1 MB)
- `atlas_ui_decorate_frame` (4.1 MB)
- `atlas_ui_skin_icon4` (4.1 MB)
- `atlas_ui_skin_icon2` (4.0 MB)
- `atlas_ui_hero_full` (4.0 MB)
- `atlas_ui_hero_full_03` (4.0 MB)
- `atlas_ui_hero_full_01` (4.0 MB)
- `atlas_ui_hero_full_02` (4.0 MB)
- `atlas_world_feast_11_13` (2.8 MB)
- `atlas_world_feast` (2.6 MB)
- `atlas_world_buildingdress1` (2.1 MB)
- `atlas_ui_icon_g5` (2.1 MB)
- `atlas_ui_skin_icon3` (2.0 MB)
- `atlas_ui_hero_full_04` (2.0 MB)
- `atlas_world_soldier_base_a_r` (1.9 MB)
- `atlas_world_soldier_base_m` (1.9 MB)
- `atlas_world_soldier_base_r` (1.9 MB)
- `atlas_world_buildingdress2` (1.5 MB)
- `atlas_ui_decorate_frame1` (1.0 MB)
- `atlas_fx_musicfestival2025` (1.0 MB)
- `atlas_ui_wordart` (0.1 MB)

</details>

<details><summary>actor_climbtower_3d (15)</summary>

- `actor_climbtower_3d_soldier_tower_pikeman_11` (0.3 MB)
- `actor_climbtower_3d_soldier_tower_pikeman_10` (0.3 MB)
- `actor_climbtower_3d_enemy_tower_scarlet_predator_c` (0.3 MB)
- `actor_climbtower_3d_enemy_tower_underworld_dweller_1` (0.3 MB)
- `actor_climbtower_3d_enemy_tower_underworld_dweller_2` (0.3 MB)
- `actor_climbtower_3d_enemy_tower_scarlet_predator_a` (0.3 MB)
- `actor_climbtower_3d_enemy_tower_scarlet_predator_d` (0.2 MB)
- `actor_climbtower_3d_enemy_tower_underworld_dweller_3` (0.2 MB)
- `actor_climbtower_3d_enemy_tower_phaethon_soldier_1` (0.2 MB)
- `actor_climbtower_3d_soldier_tower_archer_11` (0.2 MB)
- `actor_climbtower_3d_soldier_tower_archer_10` (0.2 MB)
- `actor_climbtower_3d_soldier_tower_infantry_11` (0.2 MB)
- `actor_climbtower_3d_soldier_tower_infantry_10` (0.2 MB)
- `actor_climbtower_3d_enemy_tower_phaethon_soldier_3` (0.2 MB)
- `actor_climbtower_3d_enemy_tower_phaethon_soldier_2` (0.2 MB)

</details>

<details><summary>actor_battle_battle (10)</summary>

- `actor_battle_battle_monster_gpu_20100_kulou_red` (0.4 MB)
- `actor_battle_battle_monster_30100_kulou_red` (0.4 MB)
- `actor_battle_battle_monster_gpu_30100_kulou_red` (0.4 MB)
- `actor_battle_battle_monster_10100_kulou_red` (0.3 MB)
- `actor_battle_battle_monster_20100_kulou_red` (0.3 MB)
- `actor_battle_battle_monster_gpu_10100_kulou_red` (0.3 MB)
- `actor_battle_battle_monster_51000_sword_kulou_red` (0.0 MB)
- `actor_battle_battle_monster_51011_priest_kulou_red` (0.0 MB)
- `actor_battle_battle_monster_51004_bandit_kulou_red` (0.0 MB)
- `actor_battle_battle_monster_51003_spearmen_kulou_red` (0.0 MB)

</details>

<details><summary>actor_climbtower_monster (5)</summary>

- `actor_climbtower_monster_north_wolf` (0.2 MB)
- `actor_climbtower_monster_crocuta_spelaea` (0.2 MB)
- `actor_climbtower_monster_titanis` (0.1 MB)
- `actor_climbtower_monster_snow_leopard` (0.1 MB)
- `actor_climbtower_monster_megatapirus` (0.1 MB)

</details>

<details><summary>actor_world_soldier (3)</summary>

- `actor_world_soldier_2d_soldier_pikemanconfig` (0.0 MB)
- `actor_world_soldier_2d_soldier_archerconfig` (0.0 MB)
- `actor_world_soldier_2d_soldier_infantryconfig` (0.0 MB)

</details>

<details><summary>actor_world_part (2)</summary>

- `actor_world_part_2djunuconfig` (0.0 MB)
- `actor_world_part_2dkaoruzhuconfig` (0.0 MB)

</details>

<details><summary>actor_2025halloween_3d (1)</summary>

- `actor_2025halloween_3d_hero_exhibit_50012_halloween_jebell` (10.6 MB)

</details>

## 30 bundles que mais cresceram (nome comum)

| bundle | Δ | 1.9.5 | 1.14.27 |
|---|---|---|---|
| `luapackage_64` | +27.7 MB | 68.7 MB | 96.4 MB |
| `luapackage_32` | +27.7 MB | 68.7 MB | 96.4 MB |
| `art_scene_hero_depend` | +10.2 MB | 5.8 MB | 16.0 MB |
| `art_effect_ui_texture_exhibit_depend` | +9.7 MB | 6.2 MB | 15.9 MB |
| `art_effect_ui_texture_garden_depend` | +7.0 MB | 6.4 MB | 13.4 MB |
| `art_effect_ui_texture_common_depend` | +4.9 MB | 5.7 MB | 10.5 MB |
| `art_effect_ui_texture_dress2025_depend` | +4.5 MB | 13.8 MB | 18.3 MB |
| `ui_single_guide` | +4.2 MB | 1.0 MB | 5.2 MB |
| `ui_panel_player_playerequipmentpanel` | +3.0 MB | 0.7 MB | 3.7 MB |
| `atlas_world_building_stronghold_01_03` | +2.8 MB | 0.9 MB | 3.7 MB |
| `atlas_world_building_stronghold_01_01` | +2.6 MB | 0.5 MB | 3.1 MB |
| `art_effect_ui_material_dress2025_depend` | +2.4 MB | 1.5 MB | 3.9 MB |
| `atlas_world_building_stronghold_01_02` | +2.1 MB | 0.9 MB | 3.1 MB |
| `atlas_ui_firecrystalscience` | +2.0 MB | 2.1 MB | 4.1 MB |
| `atlas_ui_main` | +2.0 MB | 2.2 MB | 4.2 MB |
| `atlas_ui_worldscene` | +2.0 MB | 2.4 MB | 4.4 MB |
| `atlas_ui_decorate_nameplate` | +2.0 MB | 2.1 MB | 4.1 MB |
| `atlas_ui_resinfo` | +2.0 MB | 2.2 MB | 4.2 MB |
| `atlas_ui_towerdefense` | +1.8 MB | 0.3 MB | 2.1 MB |
| `art_effect_ui_material_exhibit_depend` | +1.8 MB | 1.3 MB | 3.1 MB |
| `art_effect_ui_texture_dress_got_depend` | +1.7 MB | 1.8 MB | 3.5 MB |
| `art_effect_ui_texture_login_depend` | +1.6 MB | 0.6 MB | 2.2 MB |
| `ui_single_giftbag_banner` | +1.4 MB | 0.7 MB | 2.1 MB |
| `art_effect_ui_texture_arsenalleague_depend` | +1.3 MB | 0.0 MB | 1.3 MB |
| `config_ab_mapping` | +1.1 MB | 1.5 MB | 2.6 MB |
| `atlas_ui_decorate_bubble` | +1.1 MB | 1.2 MB | 2.2 MB |
| `atlas_ui_hero_skill_01` | +1.0 MB | 1.0 MB | 2.1 MB |
| `atlas_fx_common` | +0.9 MB | 0.9 MB | 1.9 MB |
| `art_effect_ui_texture_dress_depend` | +0.9 MB | 2.2 MB | 3.1 MB |
| `scene_hero_lord_show_scene` | +0.9 MB | 0.3 MB | 1.2 MB |

## 15 que mais encolheram

- `art_scene_world_lighting_secondary_depend` -22.0 MB
- `art_effect_ui_texture_got_heroskill_depend` -5.9 MB
- `atlas_world_building_alliance_safe_mine` -3.0 MB
- `scene_activity_spring2026_spring_npc_exhibit_scene` -2.4 MB
- `art_effect_ui_texture_got_heroskill_ui_fx_tex_depend` -2.2 MB
- `art_effect_ui_texture_march_draw_rabbit_depend` -2.0 MB
- `atlas_ui_snow` -2.0 MB
- `ui_panel_divinationroom_divinationroompanel` -1.5 MB
- `atlas_world_lighting_building` -1.2 MB
- `ui_panel_polarexpedition_polarexpeditionbluesubpanel` -0.8 MB
- `ui_panel_hero_herorecruitresultpanel` -0.6 MB
- `art_effect_ui_texture_recruit_depend` -0.5 MB
- `art_actor_build_3d_world_build_dress18_depend` -0.4 MB
- `art_effect_ui_texture_world_depend` -0.4 MB
- `shader` -0.4 MB

## Nós (assets) novos — amostra

- `CAB-0045847a71330f975e69474fba2e13d5`
- `CAB-0054a2fb8777633341152c16d5eeb3f2`
- `CAB-005c34b33a83cd3d7ac54f2fb53bffd0`
- `CAB-006548a0af4ee85167c6a1089915cf85`
- `CAB-007f6deaf31f42560787f26367716120`
- `CAB-00a5c14d08b5b0f3e5f19dc4c26d5620`
- `CAB-00a5c14d08b5b0f3e5f19dc4c26d5620.resS`
- `CAB-00cbdb968b8be3727422b34465b3ff38`
- `CAB-00cbdb968b8be3727422b34465b3ff38.resS`
- `CAB-00ed2a5a6401c79036be5405f03f428e`
- `CAB-00ed2a5a6401c79036be5405f03f428e.resS`
- `CAB-00fbe8d6f7930e895b4fd6087d434955`
- `CAB-010ac301ce41cc71e4b3d2a1d2e76860`
- `CAB-011a0e92a1304ef6bca49c723c975a60`
- `CAB-0131d6d03a2634d9252b737f53d378a6`
- `CAB-013e475ec051d1efe986bb9e4b50e4ef`
- `CAB-013e475ec051d1efe986bb9e4b50e4ef.resS`
- `CAB-015b32ef2546e7ae0d360a6802b4f34a`
- `CAB-015ee0c9c8365fa11be9cecf7a82eb88`
- `CAB-017187a3238703158795a14031bf24c9`
- `CAB-01791c88dc975c28f5d89b2a7a52f77d`
- `CAB-01814e9d7c67cfa5ed6f4341d1956860`
- `CAB-01d9bbdedfc5fdf2db15f1febd58c123`
- `CAB-01dbf0aa3b5b475f514f854188e6b6b6`
- `CAB-020ed307c9f979abaad7256f918df8c5`
- `CAB-020ed307c9f979abaad7256f918df8c5.resS`
- `CAB-0236f8e9b847ad3ca3a63d6b9e63d999.resS`
- `CAB-025228ace7757666165cb64aa7a46afb`
- `CAB-025228ace7757666165cb64aa7a46afb.resS`
- `CAB-0268a13627082e7babefba885f223e0e`
- `CAB-0268a13627082e7babefba885f223e0e.resS`
- `CAB-029c90e2d4db0d5e1e8ed2502a93d261.resS`
- `CAB-02bc11831bad94592b1ddda12cefc32e`
- `CAB-02bc11831bad94592b1ddda12cefc32e.resS`
- `CAB-02bdd5806f4f90e681e19658c408779e`
- `CAB-02e9c94e702e88519834d387c9c76771`
- `CAB-02e9c94e702e88519834d387c9c76771.resS`
- `CAB-02ffaa499e7c685f6f261bb2ae1929d9`
- `CAB-02ffaa499e7c685f6f261bb2ae1929d9.resS`
- `CAB-031ce4ab4c8e30472994a68adce5bac2`
- `CAB-03a0b3088b51419ae5c37f771d9dd11f`
- `CAB-03a0b3088b51419ae5c37f771d9dd11f.resS`
- `CAB-03b99c20300a343f5bcabe942a29e569`
- `CAB-03bf078578a1310a591d38a21e4ce242`
- `CAB-03f6fd5f2d9e9b49f5a851ac47d24742`
- `CAB-041f080dbd190fa0e955d410fd83fbec`
- `CAB-04392c96d8d7b3accfabd6fec4bd977f`
- `CAB-0460063c57bb8a202abd693e9550923e`
- `CAB-0460063c57bb8a202abd693e9550923e.resS`
- `CAB-048ee80e5011dd8d58dc9f0623eec1de`
- `CAB-049d33aa6882757d6687545db490cb94`
- `CAB-049ef9cb5bb0a6c236cd3e7f88d49d1b`
- `CAB-04a6c84029e34779c2d02d2714176d9b`
- `CAB-04a6c918954f201c568377d3c5c9ef0f`
- `CAB-04b22438f5538c1b77e4148bbe33d8d3`
- `CAB-04b22d4eadab35fe08fee144e48e324f`
- `CAB-04b411f36badbda9457d8cff939ceb99`
- `CAB-04d9528916dfbbd88d43a53f865ff59a`
- `CAB-04de86515601ca5d904cd431ff23f0b6`
- `CAB-04f17b973aef512fbae8a9881d14c605`
- `CAB-056bb6cfbd33f125959045d7202078f1`
- `CAB-058f7da76f02649c7770900e2a2d3756`
- `CAB-0593e35247861e04f8d83f2187d1935f`
- `CAB-05b724ea300d6c32d819dc990930f470`
- `CAB-05f4a4ca0460c11e4f90ac61ba610103`
- `CAB-061af126108561cde70d573f74190cf9`
- `CAB-061af126108561cde70d573f74190cf9.resS`
- `CAB-0639322816e0430f6412c80f31ef7a74`
- `CAB-06498059dca4b8484b5cc0894585dd19`
- `CAB-06498059dca4b8484b5cc0894585dd19.resS`
- `CAB-064fd94b4e1c9d0c2ddfe0ff77d99767`
- `CAB-064fd94b4e1c9d0c2ddfe0ff77d99767.resS`
- `CAB-067643f801e9bbdfb638e5708eec2310`
- `CAB-067bece0f3fab636b39a3d7ac53e27b4`
- `CAB-0690ef11b9d483a1410ef1a07b99e1a5`
- `CAB-0699781d56586aae7b820a41443e1e8f`
- `CAB-0699781d56586aae7b820a41443e1e8f.resS`
- `CAB-06a7e0f256bfb7372437ed3de763d26e`
- `CAB-071d11806c55bf18adcb9c4bc165dbbf`
- `CAB-0732579ce6a139898e39abdf4720c862`
- `CAB-074126e8816f2576fb251e72c7ff9fc5`
- `CAB-07429eb51b4eff8c699020bbecdf46af`
- `CAB-07478dbb4f41b57d99f225d2874f9f2c`
- `CAB-076cb30e738bf7d2ccff8140014f4a00`
- `CAB-079a2289f6ff2c1594084b090c9e3799`
- `CAB-07dec4eedf6694e9d9f2dc2ca02f958d`
- `CAB-07dec4eedf6694e9d9f2dc2ca02f958d.resS`
- `CAB-080c7c319e109338bd98984ed1e1b765`
- `CAB-0818ab284b07585df2846553446943d1`
- `CAB-0839efd524bb02fe09e155be9c9be251`
- `CAB-084a5a3538b6220e0a33b80423f17631`
- `CAB-084ad4dfb3ece4f1a1eb4602076158ee`
- `CAB-0850a1fd141b5bf2225742bf10d67026`
- `CAB-0850a1fd141b5bf2225742bf10d67026.resS`
- `CAB-087de26413249d7849910827414b5638`
- `CAB-0881d19a52e9053615052eaeb405751e`
- `CAB-08b97c9306bde7212165ada51577d4f0`
- `CAB-08b97c9306bde7212165ada51577d4f0.resS`
- `CAB-08be2eff230d79bcb04ad1b5deb66f89`
- `CAB-08efccb4a5cba1ea9b9659e0022adfd2`
- `CAB-08efccb4a5cba1ea9b9659e0022adfd2.sharedAssets`
- `CAB-08fd4fb80bbd05e8103f001b24e6d8d4`
- `CAB-08fd4fb80bbd05e8103f001b24e6d8d4.sharedAssets`
- `CAB-090987cac52708ac86e03f387622ce8f`
- `CAB-094a7f2923505021c80dadb2f7e84ffa`
- `CAB-0958ebec77a2f3a74091a226507871de`
- `CAB-099b312ad596f0911e9815ea7739da1e`
- `CAB-09fa09e8df08de379de8cdb420e59fbe`
- `CAB-09feb85b4d747c97f7119686c444cbe1`
- `CAB-09feb85b4d747c97f7119686c444cbe1.resS`
- `CAB-0a2aaf30a21a2aef1a70880ada192bea`
- `CAB-0a2aaf30a21a2aef1a70880ada192bea.resS`
- `CAB-0a3239ac76f2cc27b8ae9ee032798312`
- `CAB-0ae5ca2626f8197ef8301648386ccdb7`
- `CAB-0ae5ca2626f8197ef8301648386ccdb7.resS`
- `CAB-0af034a38e1eeb9a5c23f2013a0ed67f`
- `CAB-0af034a38e1eeb9a5c23f2013a0ed67f.sharedAssets`
- `CAB-0b13e7fdff8a24719e66b58e7e674ed8`
- `CAB-0b26d71eee2c22f34e3d2204189c07ce`
- `CAB-0b50001e2a8d9b292ad1ee568049d342`
- `CAB-0b6d10e94a134d7d6b4a5087e60f3fce`
- `CAB-0be2a3443221069d448e4cbd4ff4dfec`
- `CAB-0bfc2696cd022066e58764bb6223a99a`
- `CAB-0c1c1c014b1f9b629b61561361563d7e`
- `CAB-0c1c1c014b1f9b629b61561361563d7e.resS`
- `CAB-0c35ae90f2bff64478de4b446f360315`
- `CAB-0c40ccd8ac835489e464a4e9e55004aa`
- `CAB-0c658adbb9165037b749070e70473fab`
- `CAB-0c734295f15267a2fbebb493000b964b`
- `CAB-0c734295f15267a2fbebb493000b964b.resS`
- `CAB-0c784fa6207b98856582776d8b0c93cc`
- `CAB-0c8ab9884a944e4e85bc832b2c994df9`
- `CAB-0c8ab9884a944e4e85bc832b2c994df9.resS`
- `CAB-0caf12c4509890c4bab7ef08b29bc163`
- `CAB-0cd20eec55efe0d2e37fa76810f4daec`
- `CAB-0cffc1de66f8a1b297740f4d8fc9db48`
- `CAB-0d4062709ba580cdf759c63d58fdb4af`
- `CAB-0d8c3206ab9dd1ece51d2181cc4ec211`
- `CAB-0d8f2c5e36b4c0990f79dd78b23abe38`
- `CAB-0d9391dcc626828c00b923974f7e54b5`
- `CAB-0d9a64158327ca1f6415d1e5ec62e329`
- `CAB-0da7533557a06c5e5328d6ca43960bb3`
- `CAB-0dbb209d2381d3aa84ad19a34fc3be7c`
- `CAB-0df208a42441dedfc132be16c23637ec`
- `CAB-0e150de13705eebc79552931544a56a5`
- `CAB-0e2374e60c3a936a34ff335c1b24564a`
- `CAB-0e2cd339e41e57613a8ee64b9cfb9b10`
- `CAB-0e642089749a22d20b1817b998a02a07`
- `CAB-0eb5c7c6c77e64078375c3894d405b6a`
- `CAB-0eb656780706d77739b59db90241485e`

## Nós removidos — amostra

- `CAB-0020b952fd2c336d005488b07a3a64b9`
- `CAB-0020b952fd2c336d005488b07a3a64b9.resS`
- `CAB-002bdd706b0d7f80171768b12743f590`
- `CAB-0049d9e13b2ae42375c496864a2f7f1c`
- `CAB-0049d9e13b2ae42375c496864a2f7f1c.resS`
- `CAB-011eb2259a8e23652155711e7d848a1b`
- `CAB-01386430231f14a595002b136e94b08c`
- `CAB-014b7eb5fcd10bb8a34f6b5f9f39ee8c`
- `CAB-015026e311a322bfa99515619dfb90a8`
- `CAB-01ab7080f8d8f2764b33182b56700514`
- `CAB-01c5d7473afb610131eaafdcdbdcc8e2`
- `CAB-0215da0ad66ccbc6afbef47891cc54b4`
- `CAB-021c462feaa9ebfb08c133d8737b04b1`
- `CAB-023a4969c0230d0a2053517b17d933b7`
- `CAB-027a5e85f02318d76e31bfd465400d0f`
- `CAB-027fdf3d17e9710100bab641465eea1b`
- `CAB-028d75eacd65678bc1349df043178597`
- `CAB-028d75eacd65678bc1349df043178597.resS`
- `CAB-0299debfbce2ac02b432649f875a517c`
- `CAB-02f725d261c5302e058d68f4ab686731`
- `CAB-02f9e99ec9fbf2c8a5d9698e91057449`
- `CAB-02f9e99ec9fbf2c8a5d9698e91057449.resS`
- `CAB-0356ada3f9d4169feff7bf4677d68e02`
- `CAB-035df8651393c3af73f1238be6767279`
- `CAB-0369ca0ed639bc7c112c64a67fe84b06`
- `CAB-037cbb055386bef138686d2353a06fda`
- `CAB-03dc21fee4b164b19455a50293a54ed9`
- `CAB-03fd29b6850a334ae5a389f38f9730d9`
- `CAB-0415c34e6736e7f7c5d21df298daed10`
- `CAB-0415c34e6736e7f7c5d21df298daed10.resS`
- `CAB-044968af996cc0ca1ff44c6c9e712881`
- `CAB-044e4ea38410a2b698cb1392bc29e509`
- `CAB-04ac50a0ee6b8c02809e0bf3fce717cf`
- `CAB-053bd2aa011eb2ff885108c64b012743`
- `CAB-056684e4a4caf17162c48c6f6bc2a71d`
- `CAB-05bfa1c577e76730dd69d1d1b63d7b38`
- `CAB-05bfa1c577e76730dd69d1d1b63d7b38.resS`
- `CAB-05d0446b61ce6801ca7d7ad29130fdb9`
- `CAB-05dce4e65771a030385eaadd1fbad2e5`
- `CAB-05ed3ca1f9f087c485f8fb29cd49d62d`
- `CAB-05eea5ad654493fc029d97f5ba2907a9`
- `CAB-05eea5ad654493fc029d97f5ba2907a9.resS`
- `CAB-063b6f00e596583d2ae409748cfafd1d`
- `CAB-063b6f00e596583d2ae409748cfafd1d.resS`
- `CAB-064e67a3158e472f1953b34dbbdbe0d6`
- `CAB-068d59205c2b2d31b612d1a796fa5485`
- `CAB-068e1b4b405509d211608a91b6046a35`
- `CAB-06aa9b769e0c063cc828495f3c0195d3`
- `CAB-071cd8114b0a1c73d4116d3877f5e101`
- `CAB-07ae810c264118e4cd6c66162ab4e599`
- `CAB-0805457f5243d6889d137bb782eb9a27`
- `CAB-086b493e4a15bfef960e472638cdd285`
- `CAB-08a5bf961487e20852f1652840149ed3`
- `CAB-08dc3535e55db11f2a8f37f1f33bf7c5`
- `CAB-092a764e0e77990c1be412c2b26c4fe6`
- `CAB-0939dd211e8b88c6a13dc88365317c23`
- `CAB-094cd78479ff6436701566e33af36eb8`
- `CAB-096ec215d099cf0aa964667b5cc3070b`
- `CAB-0997ba8a457010d2563683a0832631fe`
- `CAB-0a338c927b67a6dc84fa8a067600f59e`
- `CAB-0a3a847d15b58c2f3b30907a10711d2e`
- `CAB-0a73cb3f2177491d53110a0c87e102ed`
- `CAB-0a93feb3b68310fd27597e9527ef5d7d`
- `CAB-0a93feb3b68310fd27597e9527ef5d7d.resS`
- `CAB-0a9689f7d2ea31d78b04c77fa97ea92e`
- `CAB-0a9689f7d2ea31d78b04c77fa97ea92e.resS`
- `CAB-0acf1b3198156b5a63cc710d291651a8`
- `CAB-0acf1b3198156b5a63cc710d291651a8.resS`
- `CAB-0b50090473ee087d770ea9ea387db955`
- `CAB-0b995a2fc92408e4b4d71914cd59aebe`
- `CAB-0ba22c6c149158e0f8902caac76287b4`
- `CAB-0ba67063491722671547360d591cad2e`
- `CAB-0bc5a71a5b5b041e21c3632ba600f539`
- `CAB-0bcb9ecb955518bb1892a2badce83f27`
- `CAB-0bf0a41b07a0c4e96b66bff36365fd55`
- `CAB-0c0c87594a40b44c6e689dd78a1c295e`
- `CAB-0c661e92c3651f38880bd2db8ac5f854`
- `CAB-0c6f1ddad4dd966389da50361a2de253`
- `CAB-0d3246e0a446c7bc93b72a56430ba576`
- `CAB-0d8ff6ce6a171c03d52ba1d364166c0c`