# Relatório — fixtures sintéticas c2s

**Cobertura: 1888 / 1888 mensagens passaram no round-trip (100%, 0 falhas).**
- 1869 são `req_*`; as 19 restantes são mensagens não-`req_` do mesmo schema (ex.: `loginauth`, `watch_capital_war_*`), também geradas.
- 346 têm request vazio (payload `{}`), válidas pelo schema.
- Determinístico: o `Random` é semeado pelo nome da mensagem, então reexecutar dá o mesmo JSON.

## Método
`gen_fixtures.py` percorre os campos de `request` de cada mensagem, via `Schema.c2s_by_name`.
- integer: heurística pelo nome/comentário chinês. Tempo (`time/_at/expire/start/end`, 时间) ≈ 1.79e9; `lev/level/grade/star` (等级) 1–30; `count/num/amount/total` (数量/次数) 1–99; `x/y/pos` 1–1199; `type/idx/slot/page` 1–9; demais 1000–999999.
- string: `"test"`. boolean: aleatório. double: `1.5`. binary: `"deadbeef"` (hex, como o `sproto_lib` espera).
- structs recursivos até profundidade 3. Campos que exigiriam um nível 4 são omitidos.
- Arrays têm 1–2 elementos no nível raiz e 1 nos níveis aninhados (evita explosão exponencial). Maps (`*tipo(chave)` e `*pair_*()`) têm exatamente 1 entrada.
- Validação: `build_request` → `Peer.parse(..., "C>S")`. Exige mesmo nome/tag e objeto decodificado `==` ao original, valor a valor. Só então entra em `fixtures_all.json`.

## Tipos / pontos problemáticos
- Nenhuma falha de tipo. Contagem de campos sintetizados: integer 2781, string 203, boolean 154, struct 170, array de struct 152, array de integer 126, double 10, array de string 6, binary 1.
- `integer(0)` / `integer(N)`: o parser do `sproto_lib` trata como integer comum, sem casas fixas. Os valores gerados cabem em int32, então **o caminho de int64 (>2^31) do encoder não foi exercitado**. Se `integer(0)` deveria ser 64 bits, vale um teste manual.
- `*integer` e `*boolean`: o `Peer.parse` não devolveu falha para eles. Observação: o decoder de `boolean[]` é próprio (corrigido na lib), e o round-trip passou.
- Truncamento por profundidade: só 1 mensagem perdeu campos, `req_battle_adventure_battle_result_error` (6 campos opcionais fundos, ex. `hero`, `soldier`, `skills`, omitidos por passarem de 3 níveis). Ainda assim ela faz round-trip.
- Quirks da lib (não são falhas, mas afetam um validador ingênuo):
  - `Peer.parse` devolve `consumed=0` para request vazio, embora o corpo tenha 2 bytes de header.
  - O 0-unpack deixa padding de até 7 bytes, então checar `consumed == blen` dá falso negativo. O gerador tolera <8 bytes.
- O round-trip só prova coerência encode↔decode da própria lib (que usa o mesmo schema). Não prova compatibilidade com o servidor real. Valores como ids e níveis são plausíveis, mas não existem em nenhum catálogo.

## Exemplos interessantes (todos em fixtures_all.json)
1. **Array de inteiros** — `req_alliance_activity_auto_join_info`: `{"auto_mass_id_list": [875158, 35865]}`
2. **Map (pair_int_int)** — `req_alliance_triangle_war_set_formation`: `{"formationid": 723330, "hero_map": [{"k": 525267, "v": 269614}]}`
3. **Map com booleans** — `req_arsenal_war_hospital_heal_soldier`: `{"soldiers": [{"k": 879972, "v": 82449}], "immediate": true, "is_free": true}`
4. **Struct profunda (4 níveis de dict)** — `req_cheat_slg_3_league_save_formation`: `{"formation_prefab": [{"id": 399697, "prefab": {"hero_id": [{"k":145132,"v":98347}], "soldier": [{"k":971337,"v":236283}]}}]}`
5. **Mensagem larga com struct aninhada** — `loginauth`: ~25 campos (strings `"test"`, `serverid`, `uid`, `is_create: true`, `source_player_info: {serverid, uid}` …).

Mais profundas: `req_battle_adventure_battle_result_error`, `req_cheat_publish_kingdom_channel`, `req_cheat_slg_3_league_save_formation` (profundidade 4 de dict, contando o raiz).

## Arquivos
`fixtures_all.json` (1888 payloads), `gen_fixtures.py` (rodar: `python -X utf8 gen_fixtures.py [dir_protocols]`; o `-X utf8` é necessário no Windows por causa dos comentários chineses), `failures.json` (vazio `{}`), este relatório.
