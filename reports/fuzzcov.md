# RELATORIO — fuzz de cobertura do servidor-lab (mock_v4 --state)

Fixtures disparados: **1888** (1 por mensagem; sessão/estado/processo refeitos a cada 100). Timeout 2 s/comando.

## Resumo bruto (o que veio na rede)

- code0: **1853**
- responded_nocode: **31**
- skipped_login: **1**
- rule_code: **1**
- no_response: **1**
- desync: **1**

**Atenção:** o mock responde `{code:0}` a *qualquer* req via `h_default` (receita/template/default). Então 'respondeu code:0' ≠ 'implementado'. Reclassifiquei pelo caminho que cada msg percorre no código do mock:

## Resumo honesto (classificação final)

- generico: **1836**
- real: **48**
- skipped_login: **1**
- regra: **1**
- sem_response_no_proto: **1**
- desync: **1**

Legenda: `real` = handler dedicado ou receita gravada (resposta modelada, code 0); `regra` = código de regra/erro (ex.: 701 cap de loja); `generico` = resposta fabricada por template do fixture ou `{code:0}` default (sem lógica/estado); `no_response` = sem resposta (req sem response no proto, ou handler que não responde); `desync` = conexão caiu.

Caminhos no mock: default=1830, handler=38, receita=13, template=7

Mensagens não-c2s do fixture (rsp_*/watch_*) = `n/a`: o mapeamento é feito pelos nomes de req.

## Casos anormais

- `req_shop_buy` → rule_code code=701  módulo=L:store_StoreCtrl
- `req_triangle_war_building_detail` → no_response code=None  módulo=?
- `req_upgrade_building` → desync code=None fim módulo=L:city_CityCtrl

## Tabela por módulo (ordenada pior→melhor cobertura real+regra)

| módulo | msgs | real | regra | genérico | sem resp | desync | cobertura real+regra |
|---|---|---|---|---|---|---|---|
| ? | 133 | 0 | 0 | 131 | 1 | 0 | 0% |
| L:alliance_AllianceCtrl | 50 | 0 | 0 | 50 | 0 | 0 | 0% |
| L:world_WorldMapCapitalCtrl | 40 | 0 | 0 | 40 | 0 | 0 | 0% |
| L:supremacywar_SupremacyWarMapCtrl | 37 | 0 | 0 | 37 | 0 | 0 | 0% |
| L:findinggame_FindingGameCtrl | 34 | 0 | 0 | 34 | 0 | 0 | 0% |
| L:arsenalwar_ArsenalLeagueWarMapCtrl | 33 | 0 | 0 | 33 | 0 | 0 | 0% |
| L:garden_GardenCtrl | 31 | 0 | 0 | 31 | 0 | 0 | 0% |
| L:supremacywaractivity_SupremacyWarActivityCtrl | 30 | 0 | 0 | 30 | 0 | 0 | 0% |
| L:linkagemonopoly_LinkageMonopolyCtrl | 29 | 0 | 0 | 29 | 0 | 0 | 0% |
| L:arsenalleague_ArsenalLeagueCompetitionCtrl | 25 | 0 | 0 | 25 | 0 | 0 | 0% |
| L:arsenalwar_ArsenalNormalWarMapCtrl | 24 | 0 | 0 | 24 | 0 | 0 | 0% |
| L:slg3league_Slg3LeagueCompetitionCtrl | 22 | 0 | 0 | 22 | 0 | 0 | 0% |
| L:alliance_AllianceWarCtrl | 21 | 0 | 0 | 21 | 0 | 0 | 0% |
| L:trianglewaractivity_TriangleWarActivityCtrl | 21 | 0 | 0 | 21 | 0 | 0 | 0% |
| L:expert_ExpertTravelCtrl | 20 | 0 | 0 | 20 | 0 | 0 | 0% |
| L:alliance_AllianceMobilizationCtrl | 20 | 0 | 0 | 20 | 0 | 0 | 0% |
| L:trianglewar_TriangleWarMapCtrl | 19 | 0 | 0 | 19 | 0 | 0 | 0% |
| L:truck_escort_TruckEscortCtrl | 19 | 0 | 0 | 19 | 0 | 0 | 0% |
| L:bestzone_BestZoneCtrl | 18 | 0 | 0 | 18 | 0 | 0 | 0% |
| L:thanksgiving_ThanksgivingCookingCtrl | 18 | 0 | 0 | 18 | 0 | 0 | 0% |
| L:world_march_ctrl_WorldMarchCtrl | 17 | 0 | 0 | 17 | 0 | 0 | 0% |
| L:expert_ExpertCtrl | 17 | 0 | 0 | 17 | 0 | 0 | 0% |
| L:world_WorldPlayerCtrl | 16 | 0 | 0 | 16 | 0 | 0 | 0% |
| L:immigrant_ImmigrantCtrl | 15 | 0 | 0 | 15 | 0 | 0 | 0% |
| L:alliance_AllianceDuelCtrl | 14 | 0 | 0 | 14 | 0 | 0 | 0% |
| L:brawlwar_BrawlWarMapCtrl | 14 | 0 | 0 | 14 | 0 | 0 | 0% |
| L:city_PivotFightCtrl | 14 | 0 | 0 | 14 | 0 | 0 | 0% |
| L:supremacywar_SupremacyWarPrivilegeCtrl | 14 | 0 | 0 | 14 | 0 | 0 | 0% |
| L:fishing_FishingCompetitionCtrl | 13 | 0 | 0 | 13 | 0 | 0 | 0% |
| L:slg3arena_Slg3ArenaCtrl | 13 | 0 | 0 | 13 | 0 | 0 | 0% |
| L:player_PlayerCtrl | 12 | 0 | 0 | 12 | 0 | 0 | 0% |
| L:world_WorldMapExpressionCtrl | 12 | 0 | 0 | 12 | 0 | 0 | 0% |
| L:pet_PetCtrl | 12 | 0 | 0 | 12 | 0 | 0 | 0% |
| L:towerdefence_TowerDefenceGameCtrl | 12 | 0 | 0 | 12 | 0 | 0 | 0% |
| L:equip_HeroEquipCtrl | 12 | 0 | 0 | 12 | 0 | 0 | 0% |
| L:activity_AllianceTrapCtrl | 11 | 0 | 0 | 11 | 0 | 0 | 0% |
| L:city_GateCtrl | 11 | 0 | 0 | 11 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabSupremacyWar | 11 | 0 | 0 | 11 | 0 | 0 | 0% |
| L:alliance_AllianceMemberCtrl | 10 | 0 | 0 | 10 | 0 | 0 | 0% |
| L:login_LoginCtrl | 10 | 0 | 0 | 10 | 0 | 0 | 0% |
| L:settings_SettingsCtrl | 10 | 0 | 0 | 10 | 0 | 0 | 0% |
| L:hero_HeroCtrl | 10 | 0 | 0 | 10 | 0 | 0 | 0% |
| L:pet_PetAdventureCtrl | 10 | 0 | 0 | 10 | 0 | 0 | 0% |
| L:polarexpedition_PolarExpeditionCtrl | 10 | 0 | 0 | 10 | 0 | 0 | 0% |
| L:relicadventure_RelicAdventureCtrl | 10 | 0 | 0 | 10 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabArsenalLeague | 9 | 0 | 0 | 9 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatHyrioConfigView | 9 | 0 | 0 | 9 | 0 | 0 | 0% |
| L:blackknight_BlackKnightCtrl | 9 | 0 | 0 | 9 | 0 | 0 | 0% |
| L:thanksgiving_ThanksgivingFeastPreparationCtrl | 9 | 0 | 0 | 9 | 0 | 0 | 0% |
| L:minewar_MineWarMapCtrl | 9 | 0 | 0 | 9 | 0 | 0 | 0% |
| L:alliance_AllianceBuildingCtrl | 8 | 0 | 0 | 8 | 0 | 0 | 0% |
| L:alliancescience_AllianceScienceCtrl | 8 | 0 | 0 | 8 | 0 | 0 | 0% |
| L:arsenalleague_ArsenalLeagueGuessCtrl | 8 | 0 | 0 | 8 | 0 | 0 | 0% |
| L:supremacywar_SupremacyFeastCtrl | 8 | 0 | 0 | 8 | 0 | 0 | 0% |
| L:vip_VipPrivilegeCtrl | 8 | 0 | 0 | 8 | 0 | 0 | 0% |
| L:thanksgiving_ThanksgivingCtrl | 8 | 0 | 0 | 8 | 0 | 0 | 0% |
| L:threetiles_ThreeTilesCtrl | 8 | 0 | 0 | 8 | 0 | 0 | 0% |
| L:alliance_AllianceVoteCtrl | 7 | 0 | 0 | 7 | 0 | 0 | 0% |
| L:anniversary_AnniversaryCtrl | 7 | 0 | 0 | 7 | 0 | 0 | 0% |
| L:chat_ChatGroupVoteCtrl | 7 | 0 | 0 | 7 | 0 | 0 | 0% |
| L:halloween_HalloweenCtrl | 7 | 0 | 0 | 7 | 0 | 0 | 0% |
| L:crossmostlords_CrossMostLordsCtrl | 7 | 0 | 0 | 7 | 0 | 0 | 0% |
| L:activity_MineWarCtrl | 7 | 0 | 0 | 7 | 0 | 0 | 0% |
| L:monopoly_MonopolyCtrl | 7 | 0 | 0 | 7 | 0 | 0 | 0% |
| L:brawlarena_BrawlArenaCtrl | 6 | 0 | 0 | 6 | 0 | 0 | 0% |
| L:radar_RadarCtrl | 6 | 0 | 0 | 6 | 0 | 0 | 0% |
| L:knifehit_KnifeHitCtrl | 6 | 0 | 0 | 6 | 0 | 0 | 0% |
| L:festivalpasscheck_FestivalPassCheckCtrl | 6 | 0 | 0 | 6 | 0 | 0 | 0% |
| L:festivalturntable_FestivalTurntableCtrl | 6 | 0 | 0 | 6 | 0 | 0 | 0% |
| L:activity_DivinationRoomCtrl | 6 | 0 | 0 | 6 | 0 | 0 | 0% |
| L:halloween_HalloweenPumpkinCtrl | 6 | 0 | 0 | 6 | 0 | 0 | 0% |
| L:crescent_CrescentCtrl | 6 | 0 | 0 | 6 | 0 | 0 | 0% |
| L:slotmatrix_SlotMatrixCtrl | 6 | 0 | 0 | 6 | 0 | 0 | 0% |
| L:world_WorldMapCtrl | 6 | 0 | 0 | 6 | 0 | 0 | 0% |
| L:arsenalleaguehonour_ArsenalLeagueHonourCtrl | 5 | 0 | 0 | 5 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabBrawArena | 5 | 0 | 0 | 5 | 0 | 0 | 0% |
| L:magicpotion_MagicPotionCtrl | 5 | 0 | 0 | 5 | 0 | 0 | 0% |
| L:duckmarket_DuckMarketCtrl | 5 | 0 | 0 | 5 | 0 | 0 | 0% |
| L:activity_HuntTreasureCtrl | 5 | 0 | 0 | 5 | 0 | 0 | 0% |
| L:player_LordEquipmentCtrl | 5 | 0 | 0 | 5 | 0 | 0 | 0% |
| L:mercenary_MercenaryCtrl | 5 | 0 | 0 | 5 | 0 | 0 | 0% |
| L:world_march_ctrl_SupremacyWarAllianceSituationMarchCtrl | 5 | 0 | 0 | 5 | 0 | 0 | 0% |
| L:world_march_ctrl_NormalWorldAllianceMarchCtrl | 5 | 0 | 0 | 5 | 0 | 0 | 0% |
| L:activity_SocialMediaCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatZXConfigView | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:advertising_MirageTheatreCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:alliancewhitelist_AllianceWhitelistCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:alliance_AllianceChestCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:alliancedevelopment_AllianceDevelopmentCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:festivalpv_FestivalPvCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:annualsummary_AnnualSummaryCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:world_march_ctrl_ArsenalLeagueWarAllianceSituationMarchCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:arsenalleague_ArsenalLeagueHospitalCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:world_march_ctrl_ArsenalWorldAllianceMarchCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:arsenalwar_ArsenalWarHospitalCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:backpack_BackpackCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:battlepasscheck_BattlePassCheckCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:science_ScienceCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabBestZone | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabThreeTiles | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:pay_PayCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:world_WorldMapFogCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:activity_SevenFestivalCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:activity_DailyTaskCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:favorites_FavoritesNormalCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:favorites_FavoritesArsenalCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:favorites_FavoritesArsenalLeagueCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:favorites_FavoritesSupremacyCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:festivalpasscheckanddailytask_FestivalPassCheckAndDailyTaskCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:world_march_ctrl_MineWorldMarchCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:frozensoilpasscheck_FrozenSoilPassCheckCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:hero_train_HeroTrainCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:heroturntable_HeroTurntableCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:hospital_HospitalCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:conscript_ConscriptCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:slg3league_Slg3LeagueActCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:soldier_SoldierCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:firecrystalscience_FirecrystalScienceCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:world_march_ctrl_SupremacyWarPersonalSituationMarchCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:worldboss_WorldBossCtrl | 4 | 0 | 0 | 4 | 0 | 0 | 0% |
| L:intelligence_IntelligenceCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatOnewayConfigView | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:world_WorldAutoAttackMonsterCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:return_ReturnCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:bank_BankCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:brawlwar_BrawlWarHospitalCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:kingdomcard_KingdomCardCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:monthweekpasscheck_MonthWeekPassCheckCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatLyConfigView | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:minewar_MineWarSkillCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:icefieldhunter_HeroRevengeCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:activity_PinBallCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabTriangleWar | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:digtreasure_DigTreasureCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:fishingpasscheck_FishingPassCheckCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:activity_LuckyCardCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:froststarshop_FrostStarShopCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:commonpasscheck_CommonPassCheckCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:threedayshop_ThreeDayStoreCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:fivedaysrecharge_FiveDaysRechargeCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:mostlords_MostLordsCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:newrecruitspasscheck_NewRecruitsPassCheckCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:pitchpot_PitchPotCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:question_QuestionCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:anniversarySignIn_AnniversarySignInSubCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:activity_FireCrystalLabCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:supremacywaractivity_SupremacyWarGuessCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:development_DevelopmentCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:towerdefence_TowerDefencePassCheckCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:commonpasscheck_CommonSpecialPassCheckCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:vipsocialmedia_VipSocialMediaCtrl | 3 | 0 | 0 | 3 | 0 | 0 | 0% |
| L:activityaccumulative_AccumulativeActivityCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabConstruction | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabCommon | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:settings_LikeCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:alliance_AllianceHelpCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:world_march_ctrl_ArsenalLeagueWarPersonalSituationMarchCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:arsenalleague_ArsenalLeagueTaskCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:world_march_ctrl_ArsenalWorldWarMarchCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:returnpasscheck_ReturnPassCheckCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:activity_BackFestivalCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:queue_QueueCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:chat_BlackListCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatCggConfigView | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabAllianceDuel | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatZjConfigView | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatChtConfigView | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabHeroDevelopmentFund | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabLinkageMonopoly | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabMercenary | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabImmigrant | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabActivity | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabSlg3Arena | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabPet | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabGift | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_CheatGiftInfoItem | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabExpert | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabSlg3League | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabSlotMatrix | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabTowerDefence | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:law_LawCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:accountcommunity_AccountCommunityCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:continuousrecharge_ContinuousRechargeCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:customgift_CustomGiftCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:dailydeal_DailyDealCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:embassy_EmbassyCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:favorites_FavoritesTriangleCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:fourteensign_FourteenSignCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:activity_FrozenTreasureCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:activerecharge_ActiveRechargeCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:activity_FestivalSevenDaysCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:firecrystalscience_FirecrystalScienceTaskCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:activity_PetFestivalCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:activity_TrialOfSurvivalCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:sevensign_SevenSignCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:gift_GiftCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:herodevelopment_HeroDevelopmentFundCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:garden_GardenSignCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:icefieldhunter_IceFieldHunterCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:infinitebox_InfiniteBoxCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:mergemilestone_MergeMilestoneCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:paidsprint_PaidSprintCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:player_AttributeCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:pushcustomgift_PushCustomGiftCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:recharge_RechargeCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:twentyonesign_TwentyoneSignCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:snowfund_SnowFundCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:anniversaryshare_AnniversaryShareCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:purifying_PurifyCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:supervip_BirthdayGiftCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:supervip_SuperVipCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:supremacywarpre_SupremacyWarPreCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:tdbox_TowerDefenceBoxCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:commonsevendays_CommonSevenDaysCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:todo_ToDoListCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:valueexchange_ValueExchangeCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:vip_VipCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:world_WorldMapFortCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:world_march_ctrl_NormalWorldWarMarchCtrl | 2 | 0 | 0 | 2 | 0 | 0 | 0% |
| L:activity_EventCalendarCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:activity_ActivityDropCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:activity_ActivityGiftCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:gamecollection_GameCollectionCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:alliance_AllianceWarMailCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:allianceInfo_AllianceBriefInfoCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:world_march_ctrl_BrawlWarPersonalSituationMarchCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:glory_GloryCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabAllianceBuild | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatZQSConfigView | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabMarch | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatBestZoneKingdomView | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabDigTreasure | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatCJConfigView | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabMission | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabRadar | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabBackpack | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabWorld | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabMonopoly | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabMostLords | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabKnifeHit | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabQuestionnaire | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabCrescent | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatMainView | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabThanksgiving | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_item_cheat_tab_CheatTabOpinion | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| M:ui_view_cheat_CheatYunConfigView | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:citygain_CityGainCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:splitasset_SplitAssetCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:exchangeactivity_ExchangeActivityCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:fishing_FishingRankCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:world_march_ctrl_MineWorldWarMarchCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:welfare_FundCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:city_SnowGuideCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:googleachievement_GoogleAchievementCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:recruite_RecruitCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:heroictrials_HeroicTrialsCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:gardenguide_GardenGuideCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:homelandguide_HomelandGuideCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:icefieldhunter_SpSummonCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:activity_InteractiveCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:threedayshop_ThreeDayTaskCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:activity_ChristmasFindCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:welfare_MonthCardCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:multiplechoicepack_MultipleChoicePackCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:newserversprint_NewServerSprintCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:optionalgift_OptionalGiftCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:pickone_PickOneGiftCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:pushmultiplechoicepack_PushMultipleChoicePackCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:activity_FireCrystalLeakCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:system_SubHeartBeatCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:supremacywaractivity_SupremacyWarStoreCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:supremacywaractivity_SupremacyWarTaskCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:city_CityWallCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:versionup_VersionUpCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:commonspecial_CommonSpecialCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:world_march_ctrl_WorldWarMarchCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:world_march_ctrl_WorldAllianceMarchCtrl | 1 | 0 | 0 | 1 | 0 | 0 | 0% |
| L:cheat_CheatCtrl | 58 | 1 | 0 | 57 | 0 | 0 | 2% |
| L:arsenalwar_ArsenalWarActivityCtrl | 23 | 1 | 0 | 22 | 0 | 0 | 4% |
| L:chat_ChatCtrl | 44 | 2 | 0 | 42 | 0 | 0 | 5% |
| L:arena_ArenaCtrl | 12 | 1 | 0 | 11 | 0 | 0 | 8% |
| L:rank_RankCtrl | 8 | 1 | 0 | 7 | 0 | 0 | 12% |
| L:friend_FriendCtrl | 8 | 1 | 0 | 7 | 0 | 0 | 12% |
| L:redpacket_RedPacketCtrl | 7 | 1 | 0 | 6 | 0 | 0 | 14% |
| L:mission_MissionCtrl | 6 | 1 | 0 | 5 | 0 | 0 | 17% |
| L:climbtower_ClimbtowerCtrl | 15 | 3 | 0 | 12 | 0 | 0 | 20% |
| L:mail_MailCtrl | 15 | 4 | 0 | 11 | 0 | 0 | 27% |
| L:city_CityCtrl | 16 | 5 | 0 | 10 | 0 | 1 | 31% |
| M:SDKModule | 3 | 1 | 0 | 2 | 0 | 0 | 33% |
| L:opinion_OpinionCtrl | 3 | 1 | 0 | 2 | 0 | 0 | 33% |
| L:dress_DressCtrl | 3 | 1 | 0 | 2 | 0 | 0 | 33% |
| L:soldier_BarrackCtrl | 5 | 2 | 0 | 3 | 0 | 0 | 40% |
| L:tdevent_TowerDefenceCtrl | 5 | 2 | 0 | 3 | 0 | 0 | 40% |
| L:playercard_PlayerCardCtrl | 5 | 2 | 0 | 3 | 0 | 0 | 40% |
| L:city_SurvivorCtrl | 18 | 8 | 0 | 10 | 0 | 0 | 44% |
| L:adventure_AdventureCtrl | 4 | 2 | 0 | 2 | 0 | 0 | 50% |
| M:ui_item_cheat_tab_CheatTabHero | 2 | 1 | 0 | 1 | 0 | 0 | 50% |
| L:commonreward_CommonRewardCtrl | 2 | 1 | 0 | 1 | 0 | 0 | 50% |
| L:store_StoreCtrl | 5 | 2 | 1 | 2 | 0 | 0 | 60% |
| L:guide_GuideCtrl | 1 | 1 | 0 | 0 | 0 | 0 | 100% |
| L:system_HeartBeatCtrl | 1 | 1 | 0 | 0 | 0 | 0 | 100% |
| M:login_NetMsg | 1 | 1 | 0 | 0 | 0 | 0 | 100% |
| M:login_ServerProxy | 1 | 1 | 0 | 0 | 0 | 0 | 100% |
| L:unlock_UnlockCtrl | 1 | 1 | 0 | 0 | 0 | 0 | 100% |

## Top-20 buracos (módulos com mais mensagens só genéricas/sem resposta)

| # | módulo | msgs | buracos (genérico+sem resp+desync) | cobertura |
|---|---|---|---|---|
| 1 | ? | 133 | 132 | 0% |
| 2 | L:cheat_CheatCtrl | 58 | 57 | 2% |
| 3 | L:alliance_AllianceCtrl | 50 | 50 | 0% |
| 4 | L:chat_ChatCtrl | 44 | 42 | 5% |
| 5 | L:world_WorldMapCapitalCtrl | 40 | 40 | 0% |
| 6 | L:supremacywar_SupremacyWarMapCtrl | 37 | 37 | 0% |
| 7 | L:findinggame_FindingGameCtrl | 34 | 34 | 0% |
| 8 | L:arsenalwar_ArsenalLeagueWarMapCtrl | 33 | 33 | 0% |
| 9 | L:garden_GardenCtrl | 31 | 31 | 0% |
| 10 | L:supremacywaractivity_SupremacyWarActivityCtrl | 30 | 30 | 0% |
| 11 | L:linkagemonopoly_LinkageMonopolyCtrl | 29 | 29 | 0% |
| 12 | L:arsenalleague_ArsenalLeagueCompetitionCtrl | 25 | 25 | 0% |
| 13 | L:arsenalwar_ArsenalNormalWarMapCtrl | 24 | 24 | 0% |
| 14 | L:slg3league_Slg3LeagueCompetitionCtrl | 22 | 22 | 0% |
| 15 | L:arsenalwar_ArsenalWarActivityCtrl | 23 | 22 | 4% |
| 16 | L:alliance_AllianceWarCtrl | 21 | 21 | 0% |
| 17 | L:trianglewaractivity_TriangleWarActivityCtrl | 21 | 21 | 0% |
| 18 | L:expert_ExpertTravelCtrl | 20 | 20 | 0% |
| 19 | L:alliance_AllianceMobilizationCtrl | 20 | 20 | 0% |
| 20 | L:trianglewar_TriangleWarMapCtrl | 19 | 19 | 0% |

## Recomendação — 5 módulos que mais rendem se cobertos
(critério: nº de mensagens hoje só genéricas, excluindo cfg, cheat e não-mapeados; só módulos Lua L:)

- **L:alliance_AllianceCtrl** — 50 de 50 msgs sem lógica real
- **L:chat_ChatCtrl** — 42 de 44 msgs sem lógica real
- **L:world_WorldMapCapitalCtrl** — 40 de 40 msgs sem lógica real
- **L:supremacywar_SupremacyWarMapCtrl** — 37 de 37 msgs sem lógica real
- **L:findinggame_FindingGameCtrl** — 34 de 34 msgs sem lógica real

## Método / limites
- Cada fixture é um payload válido round-trip, mas sem contexto de jogo (ids reais, pré-condições); resposta code 0 genérica não prova comportamento.
- Mensagens de módulo múltiplo contam em cada módulo; tabela soma >1888.
- Pushes por mensagem em coverage_full.json.
## Achados acionáveis
- **Bug real:** `req_upgrade_building` com o payload do fixture derruba a conexão (handler provavelmente levanta exceção na thread da sessão) — corrigir no mock_v4 (h_upgrade_building).
- `req_triangle_war_building_detail`: único sem resposta (módulo não mapeado).
- Recomendação prática: chat/alliance são os de maior valor de jogo; módulos de guerra (supremacy/arsenal/triangle/world capital) são volumosos mas de baixa prioridade para um jogo solo.
- Ressalva: 'genérico' tem code:0 em 1836/1888 — cliente não quebra, mas nenhum estado muda. Cobertura de *respostas* é ~99%; cobertura de *comportamento* é ~2,6%.
