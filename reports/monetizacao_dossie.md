# MONETIZAÇÃO_DOSSIÉ — Kingshot 1.14.27 (análise objetiva das configs do cliente)

**Fontes**: 1.389 tabelas de config reais extraídas do luapackage (work/lua-logic/cfg) + schemas sproto.
Método: análise estática das configs; renda F2P MODELADA (o cliente não traz a produção passiva);
sem dados de servidor. Veredictos seguem a evidência — refutar também é resultado.
Relatórios completos: `econ-curves/`, `econ-war/`, `econ-gates/` (work/) e reports/.

---

## ALEGAÇÃO 1 — "O jogo força pagamento para subir o nível dos reinos"

**VEREDICTO: PARCIAL (parede de tempo, não de dinheiro)**

| Evidência | Número |
|---|---|
| Castelo (build301): tempo/nível | >2 semanas a partir do nv20–25; **>1 mês nos nv26–30** |
| F2P até o nv30 | ~224 dias (cenário otimista) a **5,4 anos** (conservador) |
| Pular SÓ o tempo de obra do nv30 | **≈ US$1.500** (964h × 800 gemas/h; conversão de diamond_pay) |
| Herói | F2P ok até ~nv60; **≥15 dias/nível a partir do nv70** |
| Tecnologia | 4.964 dias em fila única (árvore não modelada) |
| O que a loja vende | **exatamente tempo (speedup) e exp de herói** — onde as curvas explodem |

A progressão é matematicamente alcançável sem pagar — mas os níveis altos viram
**meses de espera**, e a loja vende a passagem desse tempo. O design não trava;
ele **esgota a paciência**. Confiança: média-alta (renda modelada com assunções explícitas).

## ALEGAÇÃO 2 — "Exige que os outros também gastem"

**VEREDICTO: PARCIAL (pressão social projetada; sem bloqueio duro)**

O que NÃO existe (procurado e não achado): piso de gasto por membro; paywall coletivo de entrada.

O que EXISTE (mecanismos de pressão, por força):
1. **Bônus de preparação da guerra** (Supremacy): pontos individuais de membros somam num
   contador coletivo; destravam em 50k/100k/150k/200k/250k → −10 a −30% custo de cura e
   +100 a +200% velocidade de cura **para todos**. Sem teto por pessoa.
2. **Ranking de contribuição da aliança**: texto literal da config — *"Not enough members made
   the minimum required contribution… members not eligible for rewards"* — **se poucos
   contribuem acima do mínimo, NINGUÉM ganha o prêmio**. É a pressão coletiva mais explícita.
3. **Doações de tecnologia**: recursos individuais (≈597k por nível de tech) viram buff para todos.
4. **Matchmaking por poder** (Arsenal): top-20 por Soldier Power define os confrontos —
   o investimento individual de cada um define **contra quem a aliança toda luta**.
5. **Supremacy em si**: cada membro traz tropas PRÓPRIAS e paga cura própria (~10% do custo
   de treino por soldado, sem teto) — quem não investe, pesa.
6. 57% dos pacotes pagos dão **presente à aliança** (pressão social embutida na oferta).

## PANORAMA — Agressividade monetária: **ALTA**

| Dimensão | Medida |
|---|---|
| Ofertas | **1.436 SKUs pagos**; 151 com pop-up automático; 194 priorizados no login |
| Preços | 98% em 4 degraus ($4,99–$49,99); conteúdo LINEAR ao preço (sem desconto por volume) |
| "Valor" anunciado | médio **2.470%** (máx 7.500%) — sem lastro no conteúdo |
| Retenção | cartão $9,99 ≈ 17k gemas (3,4× o pacote); fundo $19,99 ≈ 250k gemas com **60% preso nos nv28–30** |
| Teto de gasto | VIP12 **$4.800** · sup_vip **$20k** · vvip **$150k–$750k** · recarga acumulada $1.000/evento |
| Urgência | eventos de 1–8 dias; A/B de ofertas **por modelo de aparelho** (58 modelos de iPhone) |
| Atenuantes | entrada barata (72 SKUs ≤$2,99), anúncios (400 gemas/dia ≈ cartão mensal), passe grátis completável |

## Fronteira honesta do que NÃO podemos afirmar
- Comportamento do servidor (fórmulas de pontos, ritmo real, validação de compras)
- Matchmaking/dificuldade dinâmica por perfil de gasto (mora no servidor)
- Receita real (o cliente mostra o catálogo, não as vendas)

## Lições para o SEU jogo (o lado bom da descoberta)
1. Curva de tempo é a moeda real — se for cobrar, cobre **conveniência**, com teto de vantagem
2. Pressão social coletiva é eficiente e tóxica na mesma medida — "mínimo de contribuintes"
   pune os pobres do grupo pelo design; se usar algo parecido, recompense quem contribui
   sem punir quem não pode
3. Anunciar "valor 2.470%" sem lastro destrói confiança a longo prazo
4. Retenção forçada (60% do fundo preso nos níveis finais) gera churn exatamente no endgame
5. A/B de ofertas por aparelho: legal no papel, mas os jogadores percebem — e postam
