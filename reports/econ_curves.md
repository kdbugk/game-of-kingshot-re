# RELATÓRIO — Curvas de progressão vs. renda F2P (Kingshot 1.14.27, config do cliente, offline)

Scripts (mesma pasta): `econ.py` (extrai curvas → `castle_curve.json`, `hero_curve.json`, `tech_total.json`, `pass_curve.json`), `analise.py` (tabelas; saída bruta `analise_out.md`), `scan107.py` (varre fontes de exp de herói). Nada escrito no repo.

## 0. Limite honesto (leia primeiro)
- **A tabela de PRODUÇÃO passiva dos edifícios (renda/hora de fazenda/serraria) NÃO existe na config do cliente** (build302.. só têm costRes/costTime/need_exp/power; nenhum campo produce/output) → é calculada no servidor. A renda F2P abaixo é **modelada**, não lida.
- Única taxa de renda em config: `world_map_resource.speed` (nós de coleta nv1–7: food/wood 316.800→411.840, stone 63.360→82.368, 4º tipo 15.840→20.592; razão 20:4:1 = **exatamente a razão dos custos de construção** food:stone:iron → a coleta é calibrada contra os custos). **A unidade de `speed` não está na config.** Carga de marcha, nº de marchas, buffs: ausentes.
- Preço em R$ não inferível; uso US$ via `diamond_pay` (payment_id 120099/120499/120999/121999/124999/129999 → inferi US$0,99/4,99/9,99/19,99/49,99/99,99 — **inferência, moeda não verificada**; pacotes de 500/2.500/5.000/10.000/25.000/50.000 gems + bônus `give_rewards1` (+100%, 1ª compra) ou `give_rewards2` (+70%)). Conversão: **500 gems ≈ US$1** (com bônus 1ª compra, metade).

## 1. Sistema A — Castelo (build301)
**Tabelas/campos:** `build301.json` (`blv`, `costRes{id,qtd}` com 102 food, 103 wood, 104 stone, 105 iron, `costTime` em s, `preCond`, `power`); `world_map_resource.speed` (renda); `fixed_store` + `item_config` (speedup).
**Assunções de renda:**
- (A) `speed` = unidades/hora por marcha, nó nv7, **4 marchas × 16 h/dia** coletando, alocação ótima entre os 4 recursos, sem buffs/VIP/aliança, nós sempre disponíveis, carga ignorada. Tarefas diárias somam só ~44k food/dia (`daily_task`) → desprezível.
- (A/10) pessimista: unidade 10× menor.
- Fila única; sem speedup; tempo efetivo do nível = max(obra, coleta).
- **Calibração a favor de (A):** nv30 custa 300M food/wood e 40,2 d de obra → exige ~7,5M/dia de cada; sob (A) 1 marcha em nó nv7 faz 6,6M/dia: coleta e relógio de obra ficam equilibrados (design plausível). Sob (A/10) a coleta seria 10× o relógio — improvável. Não é prova.

Curva (custo food=wood/stone/iron; dias = por nível; “cum.” = acumulado dias, cenário A):

| nível | custo food=wood | stone | iron | tempo construção (d) | dias recurso A(4 marchas×16h) | A/10 | dias efetivos A | dias efetivos A/10 | cum. dias A (max) |
|---|---|---|---|---|---|---|---|---|---|
| 5 | 7,600 | 1,500 | 0 | 0.01 | 0.00 | 0.01 | 0.01 | 0.01 | 0 |
| 10 | 460,000 | 92,000 | 23,000 | 0.25 | 0.05 | 0.52 | 0.25 | 0.52 | 1 |
| 15 | 4,600,000 | 930,000 | 230,000 | 0.75 | 0.70 | 7.00 | 0.75 | 7.00 | 3 |
| 20 | 21,000,000 | 4,300,000 | 1,000,000 | 3.43 | 3.17 | 31.68 | 3.43 | 31.68 | 14 |
| 25 | 81,000,000 | 16,000,000 | 4,000,000 | 18.35 | 12.22 | 122.17 | 18.35 | 122.17 | 66 |
| 29 | 240,000,000 | 49,000,000 | 12,000,000 | 33.49 | 36.61 | 366.12 | 36.61 | 366.12 | 178 |
| 30 | 300,000,000 | 60,000,000 | 15,000,000 | 40.19 | 45.53 | 455.27 | 45.53 | 455.27 | 224 |
| 31 | 67,000,000 | 13,000,000 | 3,300,000 | 7.00 | 10.05 | 100.54 | 10.05 | 100.54 | 234 |
| 35 | 67,000,000 | 13,000,000 | 3,300,000 | 7.00 | 10.05 | 100.54 | 10.05 | 100.54 | 274 |
| 40 | 72,000,000 | 14,000,000 | 3,600,000 | 9.00 | 10.85 | 108.51 | 10.85 | 108.51 | 328 |
| 45 | 79,000,000 | 15,000,000 | 3,900,000 | 11.00 | 11.80 | 117.99 | 11.80 | 117.99 | 387 |
| 50 | 82,000,000 | 16,000,000 | 4,100,000 | 12.00 | 12.37 | 123.68 | 12.37 | 123.68 | 449 |
| 60 | 96,000,000 | 19,000,000 | 4,800,000 | 15.00 | 14.53 | 145.31 | 15.00 | 145.31 | 594 |
| 70 | 130,000,000 | 26,000,000 | 6,600,000 | 0.00 | 19.80 | 198.04 | 19.80 | 198.04 | 783 |
| 80 | 160,000,000 | 33,000,000 | 8,400,000 | 0.00 | 24.77 | 247.74 | 24.77 | 247.74 | 1015 |

Cumulativo até nv30: **1,29 bi food + 1,29 bi wood + 263M stone + 66M iron, 215 dias de obra em fila única**. Do nv31 em diante (fire crystal) cada nível custa 67–82M + item 100081 e 7–15 d: a curva **desce e achata** (nv70/80 têm `costTime` ausente = 0: dado faltante, não “grátis”).
**Ponto de quebra:** nv 20→25 (3 d → 18 d por nível) e nv 26–30 (18→45 d). Acumulado F2P em (A): nv20 ≈ 14 d, nv25 ≈ 66 d, **nv30 ≈ 224 d (~7,5 meses)**; em (A/10) nv30 ≈ 1.979 d (~5,4 anos).
**Atalho pago:** `fixed_store` 20112 → item 200103 (speedup 3.600 s) por **800 gems**. Pular só o tempo de obra: nv20 ≈ US$132, nv29 ≈ US$1.286, **nv30 ≈ US$1.543**, nv50 ≈ US$461 (linhas “skip” abaixo). `build_queue` tipo 2 tem `set_gift_id=4000711` e lista de países → **2ª fila de obra parece vendida como gift** (inferência pelo campo).

- skip de tempo nível 10: 6 h × 800 gems = 4,800 gems ≈ US$ 10
- skip de tempo nível 20: 82 h × 800 gems = 65,840 gems ≈ US$ 132
- skip de tempo nível 29: 804 h × 800 gems = 642,960 gems ≈ US$ 1,286
- skip de tempo nível 30: 964 h × 800 gems = 771,560 gems ≈ US$ 1,543
- skip de tempo nível 40: 216 h × 800 gems = 172,800 gems ≈ US$ 346
- skip de tempo nível 50: 288 h × 800 gems = 230,400 gems ≈ US$ 461

**Veredicto Castelo: PARCIAL.** Não é impossível de graça (sob A chega ao nv30 em ~7 meses), mas **a partir do nv ~20–25 cada nível leva >2 semanas e do 26 em diante >1 mês**; quem paga pula 40 d por ~US$1,5k. Sob (A/10) o veredicto vira "sim, exige pagamento a partir do ~nv15" (7 d/nível). Incerteza principal = unidade de `speed`.

## 2. Sistema B — Herói (hero_level)
**Tabelas:** `hero_level.json` (80 linhas; `uplv_cost{107:exp}`); fontes de exp: `daily_activity_reward` (soma 50.000 exp/dia no máximo de pontos), `explore_level_config` (1000 fases; `clear_reward` soma **5,49M exp one-shot**; `hangs_reward` 107 = 5.000–10.000 por tick, **unidade desconhecida**), `growth_task` (970 tarefas; varredura soma ~18,7M exp, **não validada**), `battle_pass` free (100k exp/passe). Loja: `fixed_store` 20105 → item 100071 (+1.000 exp) por **30 gems**.
**Assunção:** 50.000 exp/dia (piso) + one-shots finitos.

| nível | exp p/ subir | exp cumulativo | dias a 50k/dia | gems p/ comprar o nível (33,3 exp/gem) |
|---|---|---|---|---|
| 2 | 480 | 480 | 0.0 | 14 |
| 10 | 3,100 | 14,490 | 0.1 | 93 |
| 20 | 13,000 | 91,790 | 0.3 | 390 |
| 30 | 24,000 | 277,790 | 0.5 | 720 |
| 40 | 58,000 | 671,790 | 1.2 | 1,740 |
| 50 | 130,000 | 1,611,790 | 2.6 | 3,900 |
| 60 | 300,000 | 3,681,790 | 6.0 | 9,000 |
| 70 | 770,000 | 8,801,790 | 15.4 | 23,100 |
| 79 | 2,100,000 | 21,241,790 | 42.0 | 63,000 |

**Ponto de quebra:** nv ≥ 60 (300k/nível = 6 d), nv 70 = 15 d, nv 79–80 = 42–48 d **por nível** a 50k/dia. Total 1→80 = 23,6M exp: só a atividade diária levaria 473 d; as fontes one-shot vistas (explore 5,5M + growth_task ~18,7M se válidas) cobririam a maior parte → **depende do idle `hangs_reward` e de repetíveis não quantificados**. Comprar: nv80 = 72k gems ≈ US$144; 1→80 ≈ 709k gems ≈ US$1,4k.
**Veredicto Herói (só exp de nível): PARCIAL — provavelmente NÃO até ~nv60; explode de 70 em diante.** Estrelas (`hero_star.debris_cost`), skills (`hero_skill_upgrade.cost`) e equipamentos **não analisados a fundo → sem veredicto**.

## 3. Sistema C — Tecnologia (technology_detail_config)
193 técnicas / 720 níveis (`cost_item`, `cost_time`). Soma de TODAS: 1,23 bi food, 1,23 bi wood, 246M stone, 62M iron, 22M res106 e **428,9M s = 4.964 dias em fila única**. Nem todas são obrigatórias; não modelei árvore nem nº de filas (desconhecido). Recursos ≈ castelo nv30. Veredicto: **sim para “completar tudo” (anos mesmo sob A); indeterminado para o caminho crítico** — o relógio domina.

## 4. Sistema D — Passe (`battle_pass`: 837 linhas = 27 grupos × 31 níveis; `fes_battlepass_*`; `hero_develop_pass_*`)
`integral` (0,70,140… ≈ 2.100–2.700 pts/passe), `rewards01` (grátis) vs `rewards02` (pago). Grupo 1:
- **Grátis (30 níveis):** ~11M recursos (5M food-like + 5M wood + 1M stone), 100k exp herói, ~12 h de speedups (4 tipos × 3 h).
- **Pago:** **302.400 s = 84 h de speedup universal (2001)** + 1.800 gems + 300 res201. Grupo 26: 48 h.
84 h a preço de loja ≈ 67k gems (≈US$134); o preço do passe não está em `cfg`. Renda de pontos F2P (fonte do `integral`) não quantificada → sem dias. **Veredicto Passe: NÃO exige pagamento para a faixa grátis (rewards01 completa), mas o que a faixa paga vende é tempo (speedup) e gems**, o gargalo dos sistemas A/C.

## 5. O que a loja/ofertas vendem nos gargalos
- `fixed_store`: speedup 1 h = 800 gems; exp herói 1.000 = 30 gems; 20114/20115 (301900/301901) = 400/2.000.
- `battle_pass` pago = 48–84 h speedup/passe; `hero_develop_pass_reward`: `free_reward` (400 gems) vs `pay_reward` (1.000 gems + itens).
- `vip_level` 12 níveis (`vip_exp` 0→2.500…) com `free_gift`/`buy_gift`; `diamond_pay` 6 pacotes.
- Padrão: **as vendas miram TEMPO (speedup/fila) e exp de herói**, exatamente onde as curvas A/B explodem.

## 6. Resumo
| sistema | exige pagamento? | a partir de onde |
|---|---|---|
| Castelo | **parcial** (sensível a `speed`) | nv ~20–25 (>2 sem/nível); nv26–30 >1 mês cada; nv30 ≈ 224 d F2P vs ≈US$1,5k de skip |
| Herói (exp) | **não até ~nv60; parcial 70+** | nv70 (15 d/nível a 50k/dia) |
| Tecnologia | indeterminado (tempo domina) | — |
| Passe | **não** (faixa grátis) | — |

## 7. Residual
Unidade de `world_map_resource.speed` (dominante); sem produção passiva, carga, nº de marchas, buffs, nº de filas, repetíveis/eventos; unidade de `hangs_reward`; preço em moeda local; nv70/80 do castelo sem `costTime`; soma de `growth_task` não validada. Análise estática de config, sem validação contra servidor.
