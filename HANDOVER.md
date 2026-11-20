# HANDOVER — guia para quem assume

Projeto em estado "laboratório funcional": o cliente real do jogo conversa com o nosso
servidor mock, e todas as ferramentas principais estão validadas (auditoria de 2026-11-20).
Este guia te coloca em pé de bala em 30 minutos.

## Pré-requisitos

- **WSL** distro `kingshot-re` (user `re`) com: python3 + capstone, unicorn, scapy.
  Prefixo mágico do Windows: `MSYS_NO_PATHCONV=1 wsl.exe -d kingshot-re -u re --`
- **Ghidra 12.2** em `C:/Users/prs/tools/ghidra_12.2_PUBLIC` + JDK25
- **Celular de teste** (moto g8, root magisk, jogo instalado) + adb Windows
  (`C:/Users/prs/platform-tools/adb.exe`) via **USB**
- Assets de trabalho fora do repo: `C:/Users/prs/work/` (imagens, projetos Ghidra,
  transcript em `/home/re/work/apk/`)

## Subir o laboratório (mock + jogo)

```powershell
# 1. servidor (WSL) — uma vez por boot
wsl -d kingshot-re -u re -- bash /mnt/c/Users/prs/work/mockserver/start_mock.sh
# 2. túnel USB + redirecionamento
adb reverse tcp:30101 tcp:30101
adb shell su -c "sh /data/local/tmp/go_mock.sh"
# 3. jogo frio (a regra só pega conexão NOVA)
adb shell am force-stop com.run.tower.defense
adb shell monkey -p com.run.tower.defense -c android.intent.category.LAUNCHER 1
```
Voltar ao servidor normal: `adb shell su -c "sh /data/local/tmp/go_prod.sh"` + relançar.

## Ferramentas (validadas em 2026-11-20)

| Ferramenta | Status | Uso |
|---|---|---|
| `scripts/cmd_console.py` | ✅ | Cliente de linha de comando: `mock list`, `mock <cmd>`, `prod <cmd-leve>` |
| `scripts/mock_v4.py` (+ `start_mock.sh`) | ✅ | Servidor-lab sproto (handlers, auto-notify, GM) |
| `scripts/gm_console.py` / `lab_gm.sh` | ✅ | Console de GM contra o mock |
| `protocols/sproto_py.py` + `sproto_lib.py` | ✅ | Decode/encode sproto (312/312 byte-exato) |
| `scripts/dec_block0.py` | ✅ | Decifrador de bundles (input: arquivo) |
| `scripts/analysis/emu_unpack_nesec.py` | ✅ | Emulador do packer (gera nesec_image.bin) |
| `scripts/analysis/termo_scan.py` | ✅ | Scanner de terminação em binários |
| `scripts/build_catalog.py` | ✅ | Regenera catalog.json das capturas |

## Onde mora cada verdade

| Assunto | Documento |
|---|---|
| Como o protocolo funciona | `reports/spec_server.md` → `spec_blueprint.md` |
| Schemas e comandos | `protocols/` (INDICE no README) |
| Formato de assets/cifras | `reports/block0k_decoded.md` |
| Motor anti-abuso | `reports/detect_logic.md` + `nes_static/follow` |
| Economia/design | `reports/monetizacao_dossie.md` + `econ_*` + `lua_logic.md` |
| Servidor-lab | `reports/MOCK_V4.md` + `RELATORIO_L3/NOTIFY/CHAT` |
| Histórico (era 1.9.5) | `reports/archive/` |

## Armadilhas conhecidas (pagas com suor)

1. **Quoting do WSL**: `wsl.exe -- bash -c` engole variáveis/pipes intermitentemente →
   **escreva .sh e chame `bash /mnt/c/.../script.sh`**
2. **pkill**: `pkill -f mock_gateway` mata a própria linha → use o truque `[m]ock_gateway`
3. **adb + paths `/sdcard`** no Git-Bash: **sempre** `MSYS_NO_PATHCONV=1`, e `rm` só após
   conferir tamanho do pull
4. **DNAT por IP é frágil** (conntrack, IP de backup, troca de sub-rede): **túnel USB
   (`adb reverse`) é a via estável**
5. **Relógio do mock**: tem que ser tempo real (`time.time()`) — relógio sintético mandava
   `work_endtime` no passado e a UI travava em loop
6. **Cada modo da UI** espera o conjunto certo de `notify_*` — a receita exata de qualquer
   modo está nas **capturas reais** (extraia a janela pós-ação: `work/mockserver/hunt_receita.py` é o modelo)
7. **Ghidra**: projeto do libunity packed usa endereço = vaddr+0x100000; o `img` (raw) usa
   file offsets; não confunda
8. Schemas c2s/s2c **colidem em msgId** — dispatcher sempre por direção

## Fila de trabalho (pendências honestas)

1. **Camada de validação estilo-prod no mock** (estado por conta, anti-replay de fase,
   sequência de sessão) — especificação gratuita: os erros 16807/2 da produção
2. Modo caça ainda trava no jogo real contra o mock (3 fixes aplicados; próximos passos
   no scratchpad)
3. Chat RTM local (listener FPNN) — endpoint vem do `notify_chat_init`
4. Port restante do decodificador (rotas magic alternativas; ramo curto L<0xA0)
5. O jogo do autor nascer daqui: `spec_blueprint.md` é a fundação
