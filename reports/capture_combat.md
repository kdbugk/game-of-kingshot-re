# RELATÓRIO — Captura em combate 1.14.27 (lane CAPTURE-COMBATE)

## 1. Método
* Celular (moto g8, USB, **adb do Windows** `C:/Users/prs/platform-tools/adb.exe`): `su` root (context `u:r:magisk:s0`), `versionName=1.14.27` confirmado.
* `su -c "nohup timeout 600 tcpdump -i any -U -s 0 -w /sdcard/cap_combat2.pcap port 30101 &"` — 21:37→21:47 (10 min). **Sem frida, sem ptrace**, nada tocado em /data/local/tmp. Operador jogou ~9 min (foco em batalha/ação).
* **Incidente:** a 1ª captura (21:25–21:35, 338 KB) foi **perdida**: `adb pull /sdcard/...` sob Git-Bash foi convertido para `C:/Program Files/Git/sdcard/...` (falhou) e o `rm` seguinte apagou o original. Lição: `MSYS_NO_PATHCONV=1` sempre; só `rm` depois de conferir tamanho. Na 2ª captura: remoto = local = **124 769 B** antes do rm.
* **pcap:** `C:/Users/prs/work/capture-combat/cap_combat2.pcap` (cópia idêntica `cap_combat.pcap`) e `/home/re/work/apk/cap_combat.pcap` (WSL kingshot-re). Arquivo do sdcard removido (o `cap115.pcap` antigo do sdcard não foi tocado).
* Decodificação offline: parser laneQ (`parse.py`, uint16_BE+body) — **0 erros, resto 0, 0 gaps** (5 segmentos duplicados descartados). Scripts em `work/capture-combat/`: `census.py`, `samp.py`, `tl.py`, `pair.py`, `st2.py`, `cmp.py`, `d3.py`; tabela bruta em `census_table.md`.

## 2. Resumo da captura
* 1046 pacotes, **1 conexão TCP** (cliente :47272 → :30101, linktype SLL), duração **596 s**; **sem SYN** ⇒ captura **no meio de sessão já estabelecida** (sem handshake `55/02`/token). C→S 257 frames (21 590 B), S→C 401 frames (15 177 B) = **658 frames** (>100 ✔).
* Atividade ~35–45 frames/min em repouso; pico no **min 5–6 (t≈300–400 s)**: dezenas de `7d/02`+`3d/03` e ~60 `1d/01`/`dd/01` — janela de ação/combate. Bursts de "entrada de cena/resync" em t≈6,5 s e ≈482–485 s (frames grandes), snapshots `3d/03` 2462 B a cada ~30 s.

## 3. ACHADO PRINCIPAL — bit 0x20 em byte0 e pareamento req/resp por id
Nesta conexão **todos** os frames de requisição (C→S) e respostas (S→C kind 02/03) têm o **bit 0x20 ligado** em `byte0` em relação ao cap115: `15→35`, `1d→3d`, `55→75`, `5d→7d`. Pushes S→C kind `01` (`1d/01`, `5d/01`, `dd/01`, `55/01`) ficam **sem** o bit. Em 1.9.5 battle2 as duas formas coexistiam (15/02 e 35/02; 5d/02 e 7d/02). Hipótese (não provada): bit 5 = flag de modo sequenciado/ack (ou estado pós-login), não opcode distinto. Logo **`35/02`, `7d/02`, `3d/03`, `75/02`, `35/03` são as famílias `15/02`, `5d/02`, `1d/03`, `55/02`, `15/03` com a flag.**

Pareamento (id varint 2 B, contador C→S **par crescente, passo 2** — 189 de 192 passos = 2): a resposta repete o id.
* `35 02 2e <id16>` → `75 02 01 <id16> …` — **257/257 respostas casadas por id**, latência mediana **0,28 s** (mín 0,19; máx 0,41).
* `7d 02 <tag16> <id16> …` → `75/02` (ou `35/03`); `3d 03 <tag16> <id16> 51 06 02 04…` → `35 03 01 <id16> 51 06 02 04…` (0,24 s); `6d/02` → `65/02` (0,25 s).

## 4. Census op/byte1 — combate 1.14.27 vs cap115 vs 1.9.5 battle2
(n e len mín–máx; "0" = ausente)

| dir | op/b1 | **combate 1.14.27** | cap115 (idle/login) | 1.9.5 battle2 |
|--|--|--|--|--|
| C>S | 15/02 | 0 | 28 (4) | 24 (4) |
| C>S | 19/03 | 0 | 1 (24) | 0 |
| C>S | 1d/02 | 0 | 7 (5) | 18 (5) |
| C>S | 1d/03 | 0 (→ `3d/03`) | 3 (29–2538) | 0 |
| C>S | 25/02 | **0** | 0 | 1 (4) |
| C>S | **35/02** | **105 (5)** | 0 | 10 (5) |
| C>S | **3d/02** | **1 (6)** | 0 | 1 (6) |
| C>S | **3d/03** | **29 (16–2462)** | 0 | 0 |
| C>S | 55/02 | 0 (sem handshake) | 1 (213) | 1 (204) |
| C>S | 59/02 | 0 | 1 (51) | 5 (13–51) |
| C>S | 5d/02 | 0 | 20 (7–180) | 78 (7–1684) |
| C>S | **6d/02** | **2 (18)** | 0 | 0 |
| C>S | 79/02 | **0** | 0 | 1 (14) |
| C>S | **7d/02** | **120 (9–67)** | 0 | 14 (16–1568) |
| S>C | 0d/01 | 0 | 3 (4) | 2 (4) |
| S>C | 15/01 | 0 | 1 (38) | 1 (35) |
| S>C | 15/03 | 0 (→ `35/03`) | 4 (15–420) | 0 |
| S>C | 1d/01 | 103 (21–373) | 145 (6–3057) | 251 (6–3824) |
| S>C | **35/03** | **29 (16–264)** | 0 | 0 |
| S>C | 55/01 | 1 (12) | 0 | 0 |
| S>C | 55/02 | 0 | 57 (7–3062) | 126 (7–2047) |
| S>C | 5d/01 | 18 (6–19) | 40 (6–616) | 45 (6–654) |
| S>C | 65/02 | 2 (7) | 0 | 1 (13) |
| S>C | **75/02** | **226 (8–3063)** | 0 | 26 (8–353) |
| S>C | dd/01 | 22 (7) | 1 (10) | 3 (7–240) |

**Status dos opcodes pedidos:** `35/02` ✔ (105), `7d/02` ✔ (120), `3d/02` ✔ (1), `1d/03` ✔ como `3d/03` (flag 0x20). **`25/02`, `79/02` e `19/03` NÃO apareceram** (1 ocorrência única em 1.9.5; `19/03` só no login/idle; esta captura é mid-session). Novo vs 1.9.5: `6d/02` (+`65/02`), e o canal kind `03` em combate.

## 5. Samples anotados (controles ⟨⟩)

### 5.1 `35/02` (C→S 5 B) — keep-alive sequenciado
`35 02 ⟨2e⟩ ⟨9c 03⟩` — byte2 **sempre 0x2e** (105/105); id varint16 (`9c 03`=412), +2 por mensagem; cadência ~3–4 s (cai no pico de ações). Igual a 1.9.5 (`35 02 2e 0a 01`) e análogo ao `15 02 2c 06` do cap115. Resposta `75 02 01 ⟨id16⟩ 02 11 01 04 0f ⟨4B⟩ 96 ff 6a` (14 B, 110×) com 4 B crescentes = relógio do servidor; resposta curta `75 02 01 ⟨id⟩ 01 01 02` (8 B, 88×) = ACK vazio de `7d/02`.

### 5.2 `7d/02` (C→S) — canal de comandos; tag de 2 B identifica o comando
| tag | n | len | exemplo | em 1.9.5 |
|--|--|--|--|--|
| `6c 42` | 38 | 18–19 | `7d 02 ⟨6c 42⟩ a0 03 05 4d 08 c6 01 01 c5 02 04 25 4e 01 0f` | **igual** (19 B `… 6c 42 0c 01 05 4d 08 ac 01 01 c5 02 04 47 4e 01 0f`) |
| `e8 15` | 41 | 16 | `7d 02 ⟨e8 15⟩ 7e 04 02 13 aa 01 04 0f 33 99 ff 6a` | novo |
| `e0 9f` | **22** | 51 | `7d 02 ⟨e0 9f⟩ 5c 04 02 10 04 13 41 9c 4e 51 4a 02 04 44 40 02 11 01 36 d1 0e 02 f2 55 c4 04 c8 c8 44 0e 02 13 12 a4 04 13 c8 c8 0e 4d 02 32 f2 04 0c c8 c8` | novo |
| `de 9f` | 3 | 10 | `7d 02 de 9f 58 04 02 05 0a 04` | novo |
| `f4 15`/`e6 15`/`ea 15` | 6/1/1 | 9–10 | `7d 02 f4 15 dc 04 01 01 0a` | novo |
| `f2 15` | 2 | 42–44 | `7d 02 f2 15 a2 03 02 10 49 23 04 02 03 22 cb db 22 da d5 22 e7 e6 …` (pares `22 xx yy`) | **igual** (tag `f215`) |
| `4e 0d` | 2 | 57 | `7d 02 4e 0d a6 03 01 c4 7d 04 01 88 01 01 88 01 …` (`01 88 01` ×N) | igual |
| `50 0d` | 2 | 9 | `7d 02 50 0d e0 03 01 01 40` | novo |
| `ac 0f` | 1 | 67 | `… 01 c4 5d 04 29 99 0a 79 05 4d 99 04 …` | novo |
| `6c 22` | 1 | 17 | `7d 02 6c 22 4a 04 01 c4 09 04 91 3b 24 14 12 25 14` | novo |

**Burst `e0 9f` (22×, t=301,8→397,5 s, ~3,5 s entre ações):** payload idêntico exceto (a) id (+2..+4) e (b) contador em `04 13 ⟨41→56⟩` que sobe **+1 por ação** (22 valores 0x41…0x56). Cada um é respondido em ~0,2 s por `dd/01` (push S→C 7 B `dd 01 f6 9f 01 ⟨id⟩ 54`, 22/22; tag `f6 9f` = `e0 9f`+0x16) e `75/02 … 02 11 01 04 0f …`. Interpretação (hipótese): **ação de combate repetida** com nº de sequência de ação em `13 ⟨n⟩`; `dd/01` = confirmação/resultado push. `e8 15` (41×, 335–536 s) = comando leve paralelo com timestamp.

### 5.3 `6d/02` → `65/02` (novo vs 1.9.5)
`6d 02 ⟨6c 42⟩ 04 05 4d 04 dc 01 01 c5 02 04 b0 46 01 0f` (18 B; t=145,4 e 412,9 s) → `65 02 01 ⟨04⟩ 01 01 02` (7 B, +0,25 s). Mesma mensagem `6c 42` do `7d/02`, em op diferente (variante sem batch) com resposta em `65/02` (em 1.9.5 só a resposta `65/02` de 13 B aparecia).

### 5.4 `3d/02` (C→S 6 B) — mesmo formato de 1.9.5
`3d 02 ⟨dc 9f⟩ 54 04` (t=291,8 s, logo após o `3d/03` de 264 B de t=288,3 e ~10 s antes do burst `e0 9f`, tag `9f` compartilhada). 1.9.5: `3d 02 c0 1d 02 01`. Hipótese (1 amostra): "arma" o modo de ação.

### 5.5 `3d/03` ↔ `35/03` (= `1d/03` ↔ `15/03` do cap115) — canal kind 03 confirmado em combate
Cabeçalho: `3d 03 ⟨tag16⟩ ⟨id16⟩ 51 06 02 04 ⟨bitmask 1–2 B⟩ ⟨corpo⟩`; resposta `35 03 01 ⟨id16⟩ 51 06 02 04 ⟨bitmask⟩ ⟨corpo⟩` (`51 06 02 04` constante, idem cap115). Três famílias por tag:
1. **`74 17` — 2462 B** (7×: t≈6,7; 96,5; 126,6; 305,5; 335,5; 484,8; 574,5; ~30 s ⇒ snapshot periódico). Cap115: `1d 03 74 17 … 2538 B` (mesmo tag, +76 B). Cabeçalho `3d 03 74 17 a4 03 51 06 02 04 ⟨ff ff⟩ 1a 13 b8 24 5f bd 3d 2d 5f bd bb 24 5f bd b9 24 …` (cap115 `ff ff b6 13 ed ba bc b9`). Resposta **16 B** `35 03 01 ⟨id⟩ 51 06 02 04 3f 1a 13 b8 24 5d bd` (cap115: 15 B). Corpo = palavras de 4 B muito repetitivas (`b9 24 5f bd`: bytes 0x24 ×374, 0xbd ×368, 0xb9 ×257, 0x5f ×253 em ~2456 B; repetição de período 4 = 31%, período 8 = 25%) com blocos de 6–8 B de alta entropia e marcadores `fd b1 24 5f bd`. 1008/2462 posições variam entre os 7 snapshots (dado vivo). **Não é msgpack** e não há strings ASCII: codec binário próprio (bitmask de presença + palavras de 4 B); chave/layout não recuperável offline com 7 amostras.
2. **`0c 08` — 30 B** (1×, t=288,25): `3d 03 ⟨0c 08⟩ 4e 04 51 06 02 04 fd 20 bb 24 5f bd bd 24 ff 00 5a bd b9 24 5b d5 ce 2d 01 5d` → resposta **264 B** `35 03 01 4e 04 51 06 02 04 fd 20 ba 24 5d bd b9 24 ff 1d 5d bd 57 24 …` — mesma estrutura do par cap115 `1d 03 0c08… 29 B → 15 03 … 255 B` (resposta ~9 B maior).
3. **`f0 15` — 16 B** (21×; 17 em rajada t=351→382 s, durante as ações): `3d 03 ⟨f0 15⟩ 94 04 51 06 02 04 3d 0a b8 24 57 bd` → **27 B** `35 03 01 94 04 51 06 02 04 fd 0a bb 24 5d bd b9 24 ff 00 5b bd b9 24 ⟨ed 2a⟩ 46 4e`. O 1º byte de `⟨xx yy⟩` **decresce monotonicamente** na rajada (ed,e9,e6,e0,9f,9e,9d,9c,9b,9b,9a,96,96,96,95,92,8d) e depois `fd 25, fd 25, fa 25, f8 25` — valor LE de 2 B que cai a cada ação (recurso/contador/tempo restante?). **Hipótese**: estado consultado após cada ação.

### 5.6 `75/02` grande (S→C 3063 B, t=482,2 s) e pushes
`75 02 01 3c 05 ⟨02 31 02 72 14 d3 e2 01 06 5c 02 50 02 02 4d 02 c8 01⟩ 14 14 05 04 55 02 01 04 04 7c 95 71 cb 01 …` — contém **unidades repetidas de 14 B** `14 14 05 NN 55 02 01 NN 04 04 7c ⟨3B⟩ cb 01` com NN par crescente (04,06,08,…): são **respostas `55/02` aninhadas** (mesmo `55 02 01 NN` do cap115), seguidas de blocos `14 05 51 NN 02 01 c5 NN 04 04 ⟨4B⟩ 90 06`; termina `04 6c 0f 03 fe 6a`. É um batch de N respostas, disparado pelo trio `7d/02` `ac 0f` (67 B) + `f2 15` (42) + `4e 0d` (57) de t=481,9–484,8 — o mesmo trio de t=6,5–6,7 (⇒ entrada de cena/resync).
`1d/01` (S→C): 103 frames, 21–373 B (tags `de 0e 01`, `d2 42`), 82 distintos, 27–32/min em t=300–400 s (estado do mundo). `5d/01`: 18 (6–19 B) `5d 01 30 1a 03 ⟨2a|2c|28⟩ 10 04 1f ⟨4B relógio⟩ 96 ff 6a 04 0f ⟨4B⟩ 96 ff 6a` e `5d 01 82 15 02 04 01 02`. `55/01` (12 B, t=161,4): `55 01 42 02 01 c4 04 f5 96 03 ff 6a`.
**Campo relógio:** `… 96|98|99 ff 6a` termina muitos frames (75/02 14 B, 5d/01, 7d/02 e8 15, 55/01); os bytes antes crescem monotonicamente (timestamp do servidor).

## 6. Comparação com abril (1.9.5)
* Framing/cabeçalho **idêntico**: `uint16_BE len | op | kind | corpo`; kinds 01 (push) / 02 (req-resp) / 03 (canal "state" novo desde 1.14.x).
* Estáveis entre versões: tags `6c42`, `f215`, `4e0d`; `35/02` 5 B (`2e id`); `3d/02` 6 B.
* Novos em 1.14.27: kind `03` (`3d/03`/`35/03`, `19/03`), `6d/02`, tags `e0 9f`/`de 9f`/`e8 15`/`f4 15`/`50 0d`/`6c 22`/`ac 0f`, snapshot `74 17` periódico.
* Não exercitados: `25/02`, `79/02`, `19/03`, handshake/token.

## 7. Limitações / riscos
* Sem handshake: início do fluxo assumido em fronteira de frame (validado: 0 erros em 658 frames).
* Corpo `3d/03`/`35/03` não decodificado; interpretações de `e0 9f` (ação), `f0 15` (valor decrescente), `3d/02` (armar) e bit 0x20 são **hipóteses** apoiadas em correlação temporal (+0,2 s), contadores e repetição. Confirmar exige saber o que o operador fez nos horários 301–397 s e 351–382 s.
* A 1ª captura (perdida) não é recuperável.
* Próxima janela: reiniciar o app antes do tcpdump (handshake + `19/03`) e fazer batalha com ações variadas (para `25/02`, `79/02`).
