# Índice dos relatórios

Legenda: ✅ atual (a verdade de hoje) · 🕰 histórico do estudo (linha do tempo) · ⚠️ parcialmente superado (ler com nota)

## Protocolo e arquitetura
| Doc | Status | Assunto |
|---|---|---|
| `spec_server.md` | ✅ | **O wire é sproto (skynet) 0-pack** — 1771/1771 frames; corrige a leitura antiga de "opcode+kind" |
| `spec_blueprint.md` + `tabela_grupos.md` | ✅ | Blueprint do backend: top-50 grupos de protocolo, correções de msgIds (21=req_loaddata, 20463=climbtower_challenge), secret_key no login, 287 req_cheat_* |
| `kind03_codec.md` | ⚠️ | Decodificou o canal "kind 03" (XOR 4B) — a moldura externa foi superada pelo sproto, mas a camada XOR e a análise de conteúdo seguem válidas |
| `capture115.md` | ✅ | Captura cold-start 1.14.27 (a fonte do transcript) |
| `capture_combat.md` + `capture_combat_census.md` | ✅ | Captura em combate (prova mística); census op/família |
| `luapkg.md` | ✅ | Extração do luapackage: 8333 módulos LuaJIT + **schemas sproto completos** + chave XOR por crib |

## Formato de assets / cifras
| Doc | Status | Assunto |
|---|---|---|
| `block0k_decoded.md` | ✅ | Bloco 0 dos bundles decifrado 119/119 (emulando F_01412580) |
| `block0k_portpy.md` | ✅ | Port Python puro (byte-idêntico; T4[2], K9, classes A-D) |
| `block0k_gen.md` / `block0k_status.md` | 🕰 | A investigação que levou lá (convenções de endereço corrigidas aqui) |

## Proteção do cliente (motor anti-abuso)
| Doc | Status | Assunto |
|---|---|---|
| `nesec_unpack.md` + `nes_emu2.md` | ✅ | libnesec desempacotado (emulador Unicorn); arquitetura do packer |
| `detect_logic.md` | ✅ | Detecção vive no nesec (TracerPid por thread, magisk, emuladores); "frida" no il2cpp era "Friday" |
| `termo_map.md` / `nes_static.md` / `nes_follow.md` | ✅ | Mapa de terminação; orquestrador+policy; veredito em níveis 1-4 |
| `inline_xref.md` | ✅ | Libs pequenos: sem call sites de terminação |

## Servidor-lab (mock)
| Doc | Status | Assunto |
|---|---|---|
| `MOCK_V4.md` | ✅ | Sproto-lib byte-exato + mock schema-driven |
| `mock_handlers2.md` / `RELATORIO_L3.md` / `RELATORIO_NOTIFY.md` / `RELATORIO_CHAT.md` | ✅ | Lotes de handlers, auto-reflection de notifies, origem do endpoint do chat |

## Economia / game design
| Doc | Status | Assunto |
|---|---|---|
| `monetizacao_dossie.md` | ✅ | Dossiê objetivo (alegações testadas contra 1389 cfg) |
| `econ_curves.md` / `econ_war.md` / `econ_gates.md` | ✅ | Curvas F2P × pagamento; guerra/aliança; portas de pagamento |
| `lua_logic.md` | ✅ | Lógica de loja/pass/guerra do LuaJIT + HANDLERS.tsv + 1389 tabelas cfg |

## Arquivo
`archive/` — 29 documentos da era 1.9.5/frida (abril) e rascunhos superados. Valor: linha do tempo e métodos originais. Ler com `spec_server.md` na mão (a leitura de "opcode+kind" da época foi corrigida pelo sproto).
