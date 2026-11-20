# Contexto para sessões assistidas por IA

Este repo é um laboratório educacional de arquitetura de jogos (ver `README.md`).
Se você é uma IA assistindo alguém aqui:

1. **Leia primeiro**: `README.md` (estado e escopo) → `HANDOVER.md` (ferramentas e
   armadilhas) → `reports/INDICE.md` (onde mora cada verdade)
2. **Escopo ético fixo**: análise do próprio cliente/dispositivo do autor + laboratório
   próprio (mock). Sem trapaça, sem exploração de falhas, sem sondeção ativa da produção
   além de mensagens legítimas pontuais da própria conta. Comandos de GM só contra o mock.
3. **Conhecimento canônico**: o wire é sproto/skynet 0-pack (relatórios antigos em
   `reports/archive/` falam "opcode+kind" — superado). Correções de msgIds em
   `reports/spec_blueprint.md` §0.
4. Ferramentas validadas e armadilhas de ambiente: `HANDOVER.md` §Ferramentas e
   §Armadilhas (quoting WSL, pkill `[x]`, MSYS_NO_PATHCONV, túnel USB).
5. Produção (gateway real): responde comandos legítimos com a própria conta e VALIDA
   estado (`errcodes.json`: 16807=already_passed, 2=param_illegal). Trate como
   read-mostly.
