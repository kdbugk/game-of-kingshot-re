# game-of-kingshot-re — Laboratório de arquitetura de jogos (Kingshot)

> **Projeto educacional** sobre o próprio jogo e dispositivo do autor: entender como um
> jogo mobile moderno (Unity/IL2CPP + SDKs nativos de proteção) se comunica, protege-se
> e monetiza — e usar esse conhecimento como blueprint de engenharia.
> **Escopo:** análise passiva do próprio cliente, laboratório próprio (servidor mock),
> sem trapaça, sem exploração, sem sondeção ativa da produção além de comandos legítimos
> pontuais com a própria conta.

---

## O que este repo é (estado: pós-maratona de 2 dias)

De um APK fechado a um laboratório completo. As **10 conquistas-chave**:

1. **Packer HTProtect quebrado offline** (2 variantes) — emulador Unicorn reproduzível
   → `reports/nesec_unpack.md`, `scripts/analysis/emu_unpack_nesec.py`
2. **Assets decifrados**: bloco 0 dos bundles 119/119 (CRC variante → RC4-mod → classes XOR)
   → `reports/block0k_decoded.md`, `scripts/dec_block0.py`
3. **O luapackage aberto**: 8.333 módulos LuaJIT + **schemas sproto completos**
   (1.888 req + 1.005 notify com nomes e comentários) → `protocols/*.sproto`
4. **O wire decifrado**: sproto/skynet com 0-pack (não "opcode+kind") — 1771/1771 frames
   → `reports/spec_server.md`, `protocols/sproto_py.py`
5. **Motor anti-abuso mapeado por dentro**: detecção por thread, níveis 1-4, cadeia de saída
   → `reports/detect_logic.md`, `nes_static.md`, `nes_follow.md`
6. **Servidor-lab que roda o cliente real**: mock v4 sproto + túnel USB
   (`go_mock.sh`/`go_prod.sh` alternam com 1 comando) → `reports/MOCK_V4.md`
7. **Console de comandos**: qualquer um dos 1.888 comandos com payload real e resposta
   decodificada → `scripts/cmd_console.py` + `protocols/catalog.json` (58 com payload real)
8. **Dossiê de monetização objetivo**: 1.389 tabelas de balanceamento, alegações testadas
   → `reports/monetizacao_dossie.md` + `econ_*.md`
9. **Lógica de negócio extraída**: loja/pass/guerra do bytecode Lua + mapa msgId→handler
   → `reports/lua_logic.md`, `protocols/HANDLERS.tsv`
10. **Validação server-side ao vivo**: `16807 already_passed` / `2 param_illegal` —
    a diferença mock×prod é a camada de validação → lição nº1 do blueprint

## Mapa do repo

| Pasta | O que é |
|---|---|
| `protocols/` | **A joia**: schemas sproto (c2s/s2c), catálogo de comandos, HANDLERS.tsv, errcodes.json, sproto_py/sproto_lib |
| `reports/` | Relatórios por assunto — comece pelo `INDICE.md` |
| `reports/archive/` | Era 1.9.5/frida (abril) — linha do tempo |
| `scripts/` | Ferramentas: console, mock v4, decodificadores, switches go_prod/go_mock |
| `captures/` | pcaps próprios (cap115, cap_combat2) |
| `dump/`, `il2cpp_dump/`, `ghidra_decompile/` | Artefatos de análise (imagens, dumps, decompiles) |
| `SETUP.md` | Ambiente (WSL, Ghidra, libs) |
| `HANDOVER.md` | **Guia pra quem assume** |

## Comece por aqui

```bash
# listar os 58 comandos com payload real
python3 scripts/cmd_console.py mock list

# mandar um comando legítimo pro SEU servidor mock (ver HANDOVER pra subir)
python3 scripts/cmd_console.py mock req_get_hang_up_reward
```

## Nota de escopo e ética

Este projeto analisa apenas o próprio jogo/aparelho/conta do autor, com duas regras
invioláveis: (1) nada contra outros jogadores ou o serviço de terceiros (sem trapaça,
sondagem ativa ou exploração de falhas — comandos de teste contra a produção limitam-se
a mensagens legítimas pontuais da própria conta, e o servidor de produção recusa o que
não bate com o estado: ver lição 10); (2) o campo de provas é o **mock próprio**, que
replica fielmente o protocolo. O objetivo final é construtivo: o blueprint de um jogo
próprio.

## docs/ — as cartilhas teóricas (comece aqui!)

| Cartilha | Lê em |
|---|---|
| `docs/COMO-O-JOGO-FUNCIONA.md` | 5 min — arquitetura, quem manda no quê, os loops |
| `docs/COMO-A-REDE-FUNCIONA.md` | 5 min — sproto, sessões, cifras, o catálogo |
| `docs/COMO-O-ANTI-TAMPER-FUNCIONA.md` | 5 min — packer, motor de vigilância, veredito |
| `docs/COMO-OS-ASSETS-FUNCIONAM.md` | 4 min — bundles, cifra do bloco 0, o luapackage |
