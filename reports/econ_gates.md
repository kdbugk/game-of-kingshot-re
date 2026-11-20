# ECON-GATES — o que cada porta de pagamento tranca (kingshot, 100% offline)

Fonte: `work/lua-logic/cfg/*.json` (1389 tabelas, config do próprio cliente). Scripts: `common.py`, `a2.py`..`a5.py` (rodar com `PYTHONIOENCODING=utf8 python aN.py`).
Sem repo escrito. Sem textos de UI (os nomes são chaves de localização), então **o "que entrega" é lido por id de item/moeda**, não por nome comercial.

## 0. Convenções descobertas (base de todas as contas)

| Fato | Evidência |
|---|---|
| **1 USD ≈ 500 "pontos de recarga"**; ex.: SKU $9,99 → `statistics_type` 5000, $0,99 → 500, $99,99 → 50000 | `payment_config` (121 SKUs, 16 degraus de $0,99 a $99,99 + SKUs até $999,90) |
| Preço real = `price`, **ou `new_token_consume[2]/100` quando `price` falta** (ex.: 100499/110499/130499/132499 = **$4,99**, sem campo `price`). Placeholder `100000` (price 4294967295) = "sem pagamento" | `common.P()` |
| Moeda **101 = gemas** (item 100001 = 1 gema); 190 = pontos de recarga pagos | `item_config`, `diamond_pay` |
| Pontos acumulados alimentam VIP, recarga acumulada, top-ups de evento | `vip_level.vip_exp`, `accumulative_recharge.recharge_condition` |
| Tipos de condição `{1:tipo,2:..}`: o tipo 1 = nível (provável nível da base/Furnace), 11/24 = dia de servidor; **não confirmado** (sem o evaluator) | tabelas `*_condition` |

## 1. Inventário (tabelas de monetização; nº de entradas)

Núcleo: `payment_config` 121 · `gift_config` **1905** (1436 com preço real; 1178 com preço em gemas — o mesmo bundle é vendido por dinheiro **ou** gemas) · `diamond_pay` 6 · `month_card` 6 + `month_card_reward` 25 · `fund_config`/`fund_rewards` 1/12 · `snowfund_*` 1 · `battle_pass` 837 (27 grupos×31 níveis) + `fes_battlepass_*` + `week_bp_gift_*` 72/360 + `month_integral_*` + `hero_develop_pass_*` 16 · `vip_level` 12 · `vip_number` 100 · `vip_draw` 10 · `sup_vip_*` 14 níveis + 70 push + 220 birthday · `vvip_conf` 6 · `accumulative_recharge` 10 · `continuous_recharge` 51 · `month_recharge` 6 · `top_up_conf` 28 · `optional_top_up_conf` 6 · `daily_specials_gift` 372 · `personal_gift_group` 384 · `gift_activity_group/module` 101/69 · `good_value(_conf)` 1095/72 · `infinite_box_gift/recharge` 448/144 · `multiple_choice_pack(_content)` · `optional_gift_pack(_content)` · `paid_sprint_gift` 7 · `refund_gift` 16 · `store_item_sp_conf` 1260 · `store_base_conf` 46 · `fixed_store` · `advertising_reward` 40 · `ad_game_configs` 2 · `bp_rank_rewards` 50 · `target_rank_reward` 209 · `*_abtest` (android 3, **ios 58 modelos de aparelho**).
(Campos detalhados nos scripts; todos os pares `{1:id,2:qtd,3:id,4:qtd…}` = listas planas id/quantidade.)

## 2. Catálogo de portas

### 2.1 Pacote de gemas (loja de moeda) — `diamond_pay`
6 pacotes: $0,99/4,99/9,99/19,99/49,99/99,99 = 500/2500/5000/10000/25000/50000 pontos, **sem desconto por volume** (≈505 gemas/$ em todos). Bônus `give_rewards1` = +100% (primeira compra de cada pacote), `give_rewards2` = +70% (recompra). Nada é trancado por nível; é a moeda de tudo o resto.
Escalonamento: **linear puro**. Teto de SKU $99,99 (há SKUs maiores em `payment_config`, até $999,90).

### 2.2 Pacotes (`gift_config`, 1436 ofertas pagas)
Distribuição por preço: $0,99 ×36 · $1,99 ×8 · $2,99 ×28 · $3,99 ×2 · **$4,99 ×468** · **$9,99 ×363** · **$19,99 ×280** · **$49,99 ×246** · $74,99 ×2 · $99,99 ×3. ⇒ 98% da vitrine está nos degraus 4,99/9,99/19,99/49,99.
- **Escada do mesmo pacote** (`gift_group`): 149 grupos com 4 degraus, 36 com 5. Medido nos 160 grupos de 4 degraus ($4,99/9,99/19,99/49,99): conteúdo do $19,99 = **2,0×** o de $9,99 (389 itens), o de $49,99 = **5,0×** (332 itens); conteúdo dobra quando preço dobra ⇒ **não há "desconto de baleia"**: o gasto maior compra o mesmo valor por dólar. Pacotes de gemas pagos mantêm ~500 gemas/$ nos degraus.
- Os mesmos 1178 bundles são **vendidos por gemas** (2500/5000/10000/25000/50000 gemas = $4,99…$99,99). Existem grupos só-gemas (183) e grupos duplos (391).
- **Valor anunciado** (`discount`, ex. "2930%", "4000%"): mediana 2470 %, máx 7500 % ("+2470% de valor"). É texto de marketing sem lastro no conteúdo (conteúdo é linear ao preço) — são alegações de "valor de tabela" pré-calculadas.
- **Gatilho alliance** : 823 das 1436 ofertas pagas (57%) trazem `alliance_gift` (itens 90102–90105 distribuídos à aliança) ⇒ comprar rende presente para membros da aliança (pressão social).
- Limites: `purchase_type` 3 (530) / 2 (120) / 4 (22) — rótulos de reset (diário/semanal/mensal, a confirmar), `purchase_num` 2/5/20/99 (34/20/4/7).
- 137+14 ofertas com `open_push` (pop-up automático), 194 com `login_priority` (aparece no login), 175 com `lighting_item` (destaque).
- Desbloqueio: condições `personal_gift_group.condition` tipo 1 (126 — nível) e tipo 24 (125 — dia de servidor/idade da conta, a confirmar) ; `gift_activity_group.server_condition` (dia de servidor) e `personal_condition` tipo 25 (30). Dependência: **`mutex_id`** — 187 grupos mútuos em `personal_gift_group`, 65 em `gift_activity_group` (só um do grupo ativo por vez; rotação).

### 2.3 Oferta diária "Daily specials" — `daily_specials_gift` (372)
4 bancas por heroi/dia: $0,99 (500 gemas-equiv.), $1,99 (1000), $2,99 (1500) + 1 banca grátis (93 cada). Escalada **por dia de servidor** (`limit` 197–322, 323–448…) e por herói (97 `daily_specials_hero_gift`) — vitrine de "iscas" baratas para quebrar o primeiro pagamento.

### 2.4 Cartões mensais — `month_card` (6) / `month_card_reward` (25)
- Cartão 1: **$9,99** (130999; variante $4,99 `130499` "discount" na 1ª compra, `is_auto`=renovação automática, 30 dias): **5000 gemas na compra + 400 gemas/dia × 30 = 17000 gemas por $9,99 (≈1700 gemas/$, 3,4× o pacote de gemas)**.
- Cartão 2: $4,99 (132499): 400 gemas/dia + 200103 (60 min aceleração)×10 + 200102×72 + 200101×60 por dia.
- Cartões 3–6 **sem payment_id**: concedidos com condição de nível/dia de servidor (`show_condition`/`limit_condition` {1:nível,2:15/30/18…}) — provavelmente recompensa de outros caminhos (VIP/evento); **não confirmado**.
- **Todos os cartões dão +400 gemas/dia** ⇒ acumulam. **Reward escala com idade do servidor** (`warzone_day` 64→155→225→323→449: ex. cartão 2 aceleração 10→14, cartão 3 +500231 de 6→10).
- Efeito de retenção: valor entregue diariamente, cancelar = perder renda diária.

### 2.5 Fundo — `fund_config` + `snowfund_config`
Fundo **$19,99** (151999) → **250.000 gemas** em 12 marcos de nível (6,8,10,12,14,16,18,21,23,25,28,30 → 2000/2500/3500/4500/5500/7000/10000/15000/20000/30000/50000/**100000**). = **12.500 gemas/$ (≈25× o pacote)**; marketing "3700 %". Os últimos dois marcos (50k + 100k = 60% do valor) exigem nível 28 e 30 ⇒ **o pagamento antecipa a compra e prende o jogador na progressão**: o valor é "emprestado" pelo nível. `snowfund`: variante sazonal $19,99 → 10000 gemas + 200103×20 + 620001×60 + 100102×100.
Desbloqueio: aparece (`show_condition`) nível 6.

### 2.6 Passe de batalha / passes
- `battle_pass` 27 grupos × 31 níveis: **trilha paga = 1800 gemas** (25 slots) e **trilha grátis = 0 gemas** (25 slots só de itens). 27 grupos = temporadas sucessivas; todos iguais a partir do grupo 4 (integral 2700).
- Preços dos passes pagos: `week_bp_gift_conf` 72 (gift_id ⇒ `gift_config`), `month_integral_battle_pass` 20, `hero_develop_pass_*` 16 passes de herói, `fes_battlepass_*` (festival) — preço em `gift_config`; `bp_rank_rewards` (50 linhas): **ranking do BP festival — 1º lugar = 80.000 gemas + itens, 2º = 48.000, 3º = 28.800** ⇒ ranking de pontos do passe (competição entre pagantes/jogadores) com prêmio de gemas.
- Dependência: `week_bp_gift_conf.precondition` {1:nível} (44).

### 2.7 VIP — `vip_level` 12, `vip_number` 100, `vip_draw` 10
Pontos de VIP (500/$): VIP1 0 · VIP2 2.500 ($5) · VIP3 5.000 ($10) · VIP4 12.500 ($25) · VIP5 30.000 ($60) · VIP6 40.000 ($80) · VIP7 60.000 ($120) · VIP8 100.000 ($200) · VIP9 350.000 ($700) · VIP10 600.000 ($1.200) · VIP11 1.200.000 ($2.400) · **VIP12 2.400.000 ($4.800)**.
Gratuito: `vip_daily_reward` = +20 pontos/dia **com teto 5.000** ⇒ o F2P chega só ao **VIP3 (em 250 dias)**. Cada VIP tem baú grátis (`free_gift`) + pacote VIP à venda (`buy_gift` 400051…400062) + privilégios (`privilege`, ex. +capacidade/velocidade).
Hierarquias acima: **`sup_vip_config` 14 níveis até 10.000.000 pontos (~$20.000)** e **`vvip_conf` 5 níveis: 75M–375M pontos (~$150.000–$750.000)** com chat VIP (`vvip_chat`), presentes de aniversário (`sup_vip_birthday_gift` 220) e ofertas empurradas por nível (`sup_vip_push_gift` 70). **O cliente prevê gastadores até ~$750k acumulados.**
`vip_draw`: roleta de VIP (custos 1/10/50/100 giros; item 116 + prêmio raro 1,33%).

### 2.8 Recarga acumulada e eventos de top-up
- `accumulative_recharge` (10 marcos, pontos/$): $10 · $25 · $40 · $60 · $100 · **$200 · $400 · $600 · $800 · $1.000**. Os 4 últimos (+$200) só aparecem (`display_condition` 5001005) depois de bater $200. Recompensas: itens únicos/raros nos marcos altos (781917 permanente, 600020–23 em quantidade) — **prestígio crescente por marco**.
- `top_up_conf` (28 eventos periódicos) com faixas $5 · $15 · $25 · $40 · $60 · $80 · $100 · **$300** (`range` 2500…150000 pontos); `optional_top_up_conf` (6): jogador escolhe prêmios por faixa $5/$15/$40.
- `continuous_recharge` (51): **recarga consecutiva N dias**; cada dia exige `pay` 2500 (=$5) ou 5000 (=$10), recompensa crescente por dia; quebrar a sequência perde o bônus (retenção por pagamento diário).
- `month_recharge` (6 faixas): `pay` 98.000…5.998.000 — **unidade não confirmada** (se pontos: $196 a $11.996 no mês); recompensa 10.000→150.000 gemas ⇒ **retorno decrescente** (51 gemas/$ na faixa 1 → 12,5 gemas/$ na faixa 6, na hipótese de pontos).
- `pet_recharge_conf` (faixas 2500–30000), `active_recharge_collect` (pontos de atividade).
- **Ranking de gasto explícito: não achei tabela.** Há ranking do BP festival (`bp_rank_rewards`, 1º = 80.000 gemas) e eventos com prêmio por faixa; `target_rank_reward` (1º = 50.000 gemas) é de atividade/guerra. Ranking de gasto, se existe, é derivado no servidor.

### 2.9 Outros
- `infinite_box_gift` (448): caixa de loot com preço em gemas que cresce rápido (700 → 95.000) e recompra paga (`infinite_box_recharge` 144).
- `refund_gift` (16 SKUs $0,99…): pacote de retorno/reembolso. `paid_sprint_gift` (7): janela de "corrida" com `end_condition` (fim por dia de servidor), 5 gifts em sequência.
- `pick_one_gift`, `multiple_choice_pack`, `optional_gift_pack`: conteúdo escolhido pelo jogador. `mobilization_gift_config` (18, por dia da semana). `good_value` (1095 trocas com moeda de evento, `limit_num` 370).
- Lojas: `store_item_sp_conf` 1260 itens (ex.: `original_price` 400000 → `price` 280000 "-30%", `limit_num` 10, moeda 102). Loja Misteriosa: refresh 0→100→…→2000 gemas (reports/lua_logic.md).

## 3. Mapa de dependências

```
gemas (diamond_pay) ──► tudo que é "currency 101" (1178 bundles por gema, lojas, refresh, roleta)
1ª compra de cada pacote ──► +100% de bônus (give_rewards1); recompra +70%
pontos 190 (todo pagamento) ──► VIP (2,5k..2,4M) ──► sup_vip (100k..10M) ──► vvip (75M..375M)
                                   └► pushes sup_vip_push_gift / presentes de aniversário
recarga acumulada $200 (5001005) ──► só então EXIBE os marcos $400..$1000
recarga consecutiva dia N ──► dia N+1 (quebra = perde)
fundo ($19,99, nível ≥6) ──► marcos por nível 6..30 (60% do valor só em 28/30)
mutex_id: 187 (personal) + 65 (activity) grupos de ofertas se excluem (rotação)
cartões 3–6 ──► sem payment_id: concedidos por condição (provável VIP/nível/dia) — não confirmado
alliance_gift (57% dos pacotes) ──► a compra gera presente a membros da aliança
```
Sem "compre A para poder comprar B" forte no catálogo de gemas (aberto desde o início). As barreiras são **nível** (fundo 6; cartões 15/18/30), **tempo/ordem** (sequência acumulada $200) e **janelas** (mutex/duração).

## 4. Escalonamento (resposta direta)
1. **Preço×conteúdo é linear** (2,0× e 5,0× em 160 escadas de 4 degraus). Não há desconto por quantidade; o escalonamento está no **teto de gasto** (SKU até $999,90; VIP até $4.800; sup_vip $20k; vvip $750k; acumulada $1.000/evento) e no **prestígio** (itens únicos nos marcos altos).
2. **Os melhores valores por dólar são produtos de retenção**: cartão $9,99 = 17.000 gemas (≈3,4× o pacote); fundo $19,99 = 250.000 gemas (≈25×, 60% trancado em nível 28/30); passe pago 1800 gemas/temporada. Valor grande chega com tempo/progressão.
3. **Recarga acumulada premia gastar mais** (marcos até $1.000, `continuous_recharge`, top-up $300); `month_recharge` tem retorno decrescente; BP festival tem ranking (1º = 80k gemas).
4. **Ranking de gasto explícito: não encontrado** (só indiretos).

## 5. Publicidade (linha de base F2P "com anúncio")
`advertising_reward`: **40 slots** (num 1..40; 34 com recompensa). Por anúncio: 1–2 aceleradores 200102 (5 min) + caixa 100101 (recursos 100013 + 100023 + 2×100032 + 5×100041); faixas de condição tipo 23 = 10 / 30 / 70 nos slots 1–10 / 11–20 / 21–30 (31–40 sem condição, só `special_reward`); **a cada 2º/3º anúncio +20/30 gemas** (16 slots).
Total dos 40: **400 gemas + 450 min de aceleração + 660 caixas de recursos**. Se for um limite diário (reset **não está na tabela**): ≈400 gemas/dia ≈ $0,79/dia de gema — o **mesmo fluxo de gemas do cartão mensal (400/dia por $9,99/mês)**. Anúncio não destrava fundo, passe pago nem VIP (VIP F2P limitado a 5000 pts). `ad_game_configs` (2) = minigames de anúncio (torre). `download_reward` = 200 gemas + itens (one-shot).

## 6. Urgência / visibilidade
- `gift_activity_module`: 16 módulos de 1–8 dias (mais comuns 4 d e 2 d); `personal_gift_group.gift_end_time` fecha por dia de servidor; `paid_sprint_gift.end_condition` encerra a janela.
- 151 ofertas com pop-up (`open_push`), 194 com prioridade de login, 175 com destaque (`lighting_item`); `daily_specials` com 4 bancas diárias; `purchase_num` 2/5/20/99; mutex rotativo; "valor" anunciado +1300–7500%.
- `sup_vip_push_gift`: 70 ofertas empurradas por nível VIP. **Teste A/B por aparelho**: `ios_gift_abtest` 58 modelos + `android_gift_abtest` 3 camadas (versão de aparelho).
- Contagem regressiva nativa (`duration`, `gift_end_time`, `countdown_remaining`).

## 7. VEREDICTO: agressividade monetária = **ALTA**

| Critério | Medida | Peso |
|---|---|---|
| Densidade de ofertas | 1436 pacotes pagos (98% em 4 degraus); pop-up 151 + login 194 | ALTA |
| Teto de gasto | SKU até $999,90; VIP $4.800; sup_vip $20k; vvip $750k; acumulada $1.000/evento | ALTA |
| Recompensa progressiva por gasto | acumulada até $1.000, `continuous_recharge`, top-up $300 | ALTA |
| Retenção paga | cartões (+400 gemas/dia, `is_auto`), fundo preso por nível, VIP F2P travado em 5000 pts | ALTA |
| Urgência | durações 1–8 d, "sprint", limites de unidade, mutex, valor anunciado 13–75× | ALTA |
| Pressão social | 57% dos pacotes dão presente à aliança | MÉDIA-ALTA |
| Preço linear (sem "taxa de baleia") | conteúdo ∝ preço | ATENUA |
| Entrada barata | 72 pacotes $0,99–$2,99, banca grátis diária, anúncios (400 gemas) | ATENUA |
| Passe grátis | trilha grátis sem gemas; paga 1800 gemas/temporada | ALTA (vs F2P) |

Resumo: **alta** — retenção + urgência + hierarquia de gasto até ~$750k; atenuada só por preço linear e entrada barata.

## 8. Limites honestos
- Sem textos de UI → "o que tranca" por ID; interpretações (condição tipo 24 = dia de servidor, `purchase_type` = reset diário/semanal/mensal, `month_recharge.pay` em pontos, ads = limite diário) são **hipóteses**.
- Cartões 3–6 sem payment_id; origem de concessão não resolvida.
- Valor "gema-equivalente" só considera item 101; itens de equipamento/herói não têm preço de referência no cliente.
- Cliente = catálogo esperado, não receita real; servidor decide a compra (ver reports/spec_blueprint.md; `req_cheat_set_bind_account` não analisado aqui).
- Pasta já tinha `analise.py`/`inventario*` de rodada anterior (12:36), mantidos; `a2–a5.py` + `common.py` são desta rodada.
