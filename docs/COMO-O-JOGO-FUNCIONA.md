# Como o jogo funciona — Kingshot por dentro (5 min)

> TL;DR: um cliente **Unity + IL2CPP + Lua** rico e semi-autoritativo, conversando com um
> backend **skynet/sproto** que valida tudo. A "cascas" de proteção e cifras são
> industrializadas; o jogo em si é um tower-defense de sobreviventes com meta de reinos.

## 1. As camadas do cliente (da casca pro miolo)

```
APK ─┬─ libunity.so / libil2cpp.so     ← engine Unity + código C# compilado (IL2CPP)
     ├─ libnesec.so                    ← guarda-costas (ver docs/ANTI-TAMPER)
     ├─ luapackage (~100 MB cifrado)   ← 8.333 módulos Lua: A LÓGICA DO JOGO
     └─ bundles .htp                   ← assets cifrados (ver docs/ASSETS)
```

O segredo arquitetural: **a maior parte do jogo está em Lua**, embutida cifrada. O C#
(dumpcs_114.cs: 271 mil linhas, 4 mil classes) é quase só motor/UI/SDKs — loja,
conquista, guerra, mail: tudo Lua. *(detalhes: reports/lua_logic.md)*

## 2. Quem manda no quê (a divisão de autoridade)

| Sistema | Cliente | Servidor |
|---|---|---|
| Combate da prova mística | **SIMULA TUDO** (envia o estado: `req_save_client_data` com `survivor[].res601..607`) | guarda/replaya |
| Loja | mostra catálogo (preço vêm de config LOCAL) | **valida e cobra** (`req_shop_buy`) |
| Fases/passadas | pede | **decide** (anti-replay: erro 16807) |
| Recompensas | anima | **emite** |

A prova de que o servidor manda: mandamos comprar/lutar "na mão" e ele responde
`16807 already_passed` ou `2 param_illegal` — **estado é lei, protocolo é só gramática**.
*(detalhes: reports/spec_server.md §validação)*

## 3. O loop do jogo (o que prende o jogador)

- **Loop interno (minutos)**: tower-defense — sobreviventes com atributos (os "31×5 doubles"
  que decodificamos), ondas, torre que sobe de nível (`req_climbtower_challenge`)
- **Loop médio (dias)**: o abrigo — móveis, beliches, caça, doentes, cura
- **Loop externo (semanas/meses)**: o reino — aliança, guerras (supremacy/arsenal/triangle),
  ranking — onde o gasto individual vira vantagem coletiva
- **A cola econômica**: tudo custa **tempo**; a loja vende passagem de tempo. Castelo nv26-30
  ≈ 1 mês/nível; pular só uma obra ≈ US$ 1.500. *(detalhes: reports/monetizacao_dossie.md)*

## 4. Os 3 canais de rede

1. **Gateway TCP :30101** — o jogo em si (sproto) → ver docs/REDE
2. **Chat RTM** (ilivedata/FPNN) — canal separado, token via `notify_chat_init`
3. **HTTP/CDN** — assets, analytics, pagamento (Best HTTP + SDKs Century Games)

## Onde se aprofundar

- Arquitetura completa do backend: `reports/spec_blueprint.md`
- Lógica de negócio em Lua: `reports/lua_logic.md` + `protocols/HANDLERS.tsv`
- Economia pelos números: `reports/monetizacao_dossie.md`
- A API inteira com nomes: `protocols/game_proto_c2s.sproto` (1.888 mensagens)
