# ROADMAP — Servidor de testes completo (do mock ao "prod faithful")

> Objetivo: evoluir o mock v4 até um servidor que o cliente real trate como produção —
> estado, regras e tempo de verdade. Cada fase tem critério de pronto e o que destrava.
> Regra de ouro do projeto: gramática (wire) já é 100%; o trabalho é LEGISLAÇÃO (estado+regras).

## Fase 0 — o que JÁ existe (mock v4, nov/2026)
- ✅ Wire sproto byte-exato (decode+encode 312/312), session pairing, XOR por sessão
- ✅ ~25 handlers de gameplay + auto-reflection de notifies (tabela 12k relações)
- ✅ GM console; cliente real conecta e joga (túnel USB; castelo/TD/mail funcionam)
- ✅ Catálogo: 58 comandos com payload real; fixtures sintéticos de todos os 1.888 (ver protocols/fixtures_all.json)

## Fase 1 — ESTADO (a conta existe)
**Modelo de conta em memória + persistência (JSON/SQLite):**
recursos, mochila, prédios+níveis, heróis, sobreviventes (ingestão do `req_save_client_data`),
quests, mails, torre (níveis passados), lojas (contadores de compra/refresh).
Seed: fixture do transcript + tabelas cfg (valores reais). Save periódico + restore no login.
- **Pronto quando:** reiniciar o servidor preserva a conta; `save_client_data` altera o modelo.
- **Destrava:** comportamento consistente entre sessões; validação da Fase 2 tem chão.

## Fase 2 — VALIDAÇÃO (a lei)
A especificação são os erros reais da produção (`protocols/errcodes.json`):
- **Sequência**: login → loaddata → ações; fora de ordem → `2 param_illegal`
- **Anti-replay**: fase passada é passada → `16807`; recompensa diária já pega → código equivalente
- **Caps da cfg**: contagem de compra/refresh da loja (tabelas fixed_store); recursos insuficientes
- **Destrava:** o mock vira treinador fiel — o que passa nele passa no prod.

## Fase 3 — ORQUESTRAÇÃO E TEMPO (o mundo vive)
- Notifies **semânticos** por sistema (estado mudou → push certo; auto-reflection vira fallback)
- **Timers reais**: obra com duração real (cfg), `work_endtime` coerente, cura, pesquisa
- **Progresso offline**: hang_up calculado pelo tempo fora (fórmula das cfg)
- **Pronto quando:** as receitas extraídas das capturas (hunt_receita.py) fecham byte-a-byte.

## Fase 4 — FIDELIDADE E OPS
- Multi-conta (várias sessões; 2 clientes simultâneos: ver dois-aparelhos / UID-split no HANDOVER)
- **Suíte de regressão**: replays das capturas (cap115/combate/mock_live) como golden tests
- **Diff harness**: mesmo comando → mock vs prod → relatório de divergência (o medidor de fidelidade)
- GM completo (com auditoria — a lição 3-4 do dossiê)

## Ordem de investimento recomendada
Fase 1 → 2 (juntas fazem o servidor "existir de verdade") → 3 (jogo vivível) → 4 (engenharia).
Estimativa grosseira por fase: 1-2 dias de lane-cada, no ritmo que a maratona mostrou.
