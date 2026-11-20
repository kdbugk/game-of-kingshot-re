import sys, json, collections, os
sys.path.insert(0, r"C:/Users/prs/work/mockserver"); sys.path.append(r"C:/Users/prs/work/server")
import mock_v4 as M
import sproto_lib as L
S = L.default_schema()
fx = json.load(open(r"C:/Users/prs/work/mockserver/fixture_v4.json", encoding="utf8"))
tpls = fx.get("templates") or {}
H = set(M.Session.H) if hasattr(M.Session, "H") else set()
res = json.load(open("coverage_full.json"))
def path(n):
    if n in H: return "handler"
    rec = M.RECIPES.get(n)
    if rec and rec.get("response") is not None and n in S.c2s_by_name and S.c2s_by_name[n]["response"] is not None: return "receita"
    if n in tpls: return "template"
    return "default"
for n, v in res.items():
    v["path"] = path(n) if n in S.c2s_by_name else "n/a"
    v["final"] = ("real" if v["path"] in ("handler", "receita") and v["cls"] in ("code0", "responded_nocode") else
                  "regra" if v["cls"] == "rule_code" else
                  "generico" if v["cls"] in ("code0", "responded_nocode") else v["cls"])
    if v["path"] == "default" and "response" in S.c2s_by_name.get(n, {}) and S.c2s_by_name[n]["response"] is None: v["final"] = "sem_response_no_proto"
json.dump(res, open("coverage_full.json", "w"), indent=1)
json.dump({k: v["final"] for k, v in res.items()}, open("coverage.json", "w"), indent=1)
tot = collections.Counter(v["final"] for v in res.values()); pt = collections.Counter(v["path"] for v in res.values())
mods = collections.defaultdict(collections.Counter)
for n, v in res.items():
    ms = [x for x in (v.get("module") or "?").split(";") if x]
    ms = [x for x in ms if x.startswith("L:") or x.startswith("game_config")] or ms
    for m in set(ms): mods[m][v["final"]] += 1
def short(m): return m.replace("game_config_default_", "cfg:")
rows = []
for m, c in mods.items():
    N = sum(c.values()); good = c["real"] + c["regra"]
    rows.append((m, N, c["real"], c["regra"], c["generico"], c["no_response"] + c["sem_response_no_proto"], c["desync"] + c["parse_error"] + c["build_error"], good / N))
rows.sort(key=lambda r: (r[7], -r[1]))
o = ["# RELATORIO — fuzz de cobertura do servidor-lab (mock_v4 --state)\n",
     f"Fixtures disparados: **{len(res)}** (1 por mensagem; sessão/estado/processo refeitos a cada 100). Timeout 2 s/comando.\n",
     "## Resumo bruto (o que veio na rede)\n"]
raw = collections.Counter(v["cls"] for v in res.values())
for k, v in raw.most_common(): o.append(f"- {k}: **{v}**")
o += ["", "**Atenção:** o mock responde `{code:0}` a *qualquer* req via `h_default` (receita/template/default). Então 'respondeu code:0' ≠ 'implementado'. Reclassifiquei pelo caminho que cada msg percorre no código do mock:\n",
      "## Resumo honesto (classificação final)\n"]
for k, v in tot.most_common(): o.append(f"- {k}: **{v}**")
o += ["", "Legenda: `real` = handler dedicado ou receita gravada (resposta modelada, code 0); `regra` = código de regra/erro (ex.: 701 cap de loja); `generico` = resposta fabricada por template do fixture ou `{code:0}` default (sem lógica/estado); `no_response` = sem resposta (req sem response no proto, ou handler que não responde); `desync` = conexão caiu.\n",
      "Caminhos no mock: " + ", ".join(f"{k}={v}" for k, v in pt.most_common()) + "\n",
      "Mensagens não-c2s do fixture (rsp_*/watch_*) = `n/a`: o mapeamento é feito pelos nomes de req.\n"]
o += ["## Casos anormais\n"]
for n, v in res.items():
    if v["cls"] in ("desync", "no_response", "rule_code", "parse_error", "build_error"):
        o.append(f"- `{n}` → {v['cls']} code={v.get('code')} {v.get('err','')} módulo={v['module']}")
o += ["", "## Tabela por módulo (ordenada pior→melhor cobertura real+regra)\n", "| módulo | msgs | real | regra | genérico | sem resp | desync | cobertura real+regra |", "|---|---|---|---|---|---|---|---|"]
for r in rows: o.append(f"| {short(r[0])} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]} | {r[6]} | {r[7]*100:.0f}% |")
o += ["", "## Top-20 buracos (módulos com mais mensagens só genéricas/sem resposta)\n", "| # | módulo | msgs | buracos (genérico+sem resp+desync) | cobertura |", "|---|---|---|---|---|"]
holes = sorted(rows, key=lambda r: -(r[4] + r[5] + r[6]))[:20]
for i, r in enumerate(holes, 1): o.append(f"| {i} | {short(r[0])} | {r[1]} | {r[4]+r[5]+r[6]} | {r[7]*100:.0f}% |")
top5 = [r for r in holes if not r[0].startswith("game_config") and r[0] != "?" and "cheat" not in r[0]][:5]
o += ["", "## Recomendação — 5 módulos que mais rendem se cobertos\n(critério: nº de mensagens hoje só genéricas, excluindo cfg, cheat e não-mapeados; só módulos Lua L:)\n"]
for r in top5: o.append(f"- **{r[0]}** — {r[4]+r[5]+r[6]} de {r[1]} msgs sem lógica real")
o += ["", "## Método / limites\n- Cada fixture é um payload válido round-trip, mas sem contexto de jogo (ids reais, pré-condições); resposta code 0 genérica não prova comportamento.\n- Mensagens de módulo múltiplo contam em cada módulo; tabela soma >1888.\n- Pushes por mensagem em coverage_full.json."]
open("RELATORIO.md", "w", encoding="utf8").write("\n".join(o))
print(tot, pt); print("\n".join(o[-40:]))
