# Captura 1.14.27 (cap115) — tcpdump passivo, decode offline

Lane X · phone tocado SÓ via `adb + su + tcpdump` (sem frida, sem ptrace). Arquivos em `C:/Users/prs/work/laneX/`: `cap115.pcap` (cópia), `frames.txt` (timeline de todos os 312 frames), scripts `run.py dump.py an.py mp2.py st.py` (reusam `laneQ/parse.py`).
Pcap também em `/home/re/work/apk/cap115.pcap` (WSL `kingshot-re`).

## 1. Setup / captura

* `adb` só existe dentro do WSL distro `kingshot-re` (192.168.0.77:5555). `su` = root (`context=u:r:magisk:s0`).
* **tcpdump já presente em `/system/bin/tcpdump`** — nada instalado. `dumpsys package`: `versionName=1.14.27`.
* Comando: `su -c "nohup timeout 480 tcpdump -i any -s 0 -w /sdcard/cap115.pcap port 30101 &"` (janela 23:57→00:05, 8 min). Aviso de "janela aberta" enviado ao supervisor. Havia `frida-il2cpp-bridge` em /data/local/tmp (resto de abril) mas **nenhum processo frida rodando**; não toquei nele.
* O jogo rodou normalmente durante a janela (processo `com.run.tower.defense` vivo antes/depois).
* Detalhe: tcpdump bufferiza a escrita (arquivo ficou 0 B por ~3 min); o arquivo só fechou direito ao fim do `timeout` (SIGTERM). Para próximos usos: `-U`.
* Resultado: **70 187 B, 252 pacotes, 1 conexão TCP** (cliente :44014 → 3.x:30101, linktype 113 SLL), com SYN capturado ⇒ **handshake completo** (cold start do jogo). Tráfego dura **132 s** (último frame em t=131.8 s: heartbeat+resposta `55/02`); depois não há mais pacotes e nenhum FIN/RST visto (jogo provavelmente fechado/em background/rede caiu — a sessão de "play" efetiva foi ~2 min, não 3–5).

## 2. Framing

`uint16_BE(len)+body` — **0 erros**, sobra 0, 0 gaps, 0 dup (parser laneQ):

| Dir | segs TCP | bytes | frames |
|---|---|---|---|
| C→S | 133 | 6242 | 61 |
| S→C | 119 | 42737 | 251 |
| **total** | | | **312** (>100 ✔) |

Maior frame: 3062 B (`55/02` S→C), 3057 B (1º `1d/01`). Em abril: 3824 B.

## 3. Handshake — versão confirmada

`C→S 55/02` 213 B (abril: 204 B), resposta `S→C 55/02` 64 B (abril 63 B), +0,39 s.
Hex C→S (strings, controles marcados `⟨⟩`):

| Campo | 1.14.27 | April 1.9.5 |
|---|---|---|
| versão | `05 7e? "1.14.2" ⟨e3⟩ "7"` ⇒ **"1.14.27" ✔** (len 7) | "1.9.5" (len 5) |
| versão S→C | `07 fc "1.14.2" ⟨63⟩ "7"` ⇒ "1.14.27" (e3→63 = bit7 cai no S→C, mesmo padrão `7e→fc`) | "1.9.5" |
| token (bin8 `c4 33` = 51 B, abril `c4 32` = 50 B) | `5f30 ⟨ff05⟩ "5gn0p4Mi8j7SaPJwmx6XialBuAckhO0s1NO1YbdAQVr1rsQC"` (48 chars) | `3157 ⟨ff05⟩ "OEGFLbwPPabuxrSMmrqxyValDSbmQjLjOp8Ze3428BoU1rfR"` |
| user_id | `"384" ⟨7f⟩ "601255"` = **384601255** (igual) | igual |
| device / os / país / lang | `motorola moto g(8)` / `android` / `BR` / `pt` (iguais) | iguais |
| hex-32 #1 | `175aa427bbe891a766c851caedecd019` | `8c5b8051660a0e60b1b4a39716e02ba6` |
| hex-32 #2 | `12bddab7db7d820bd05763117a87ad98` | `25f42e14…db74` |
| cauda | `… 00 00 40 02 0c "BR"` | idem estrutura |

Achados:
* **Token NÃO é estático entre instalações/versões** (muda; "token estático" valia só dentro de uma versão/sessão de abril). Os 2 IDs hex-32 também mudaram (reinstalação ⇒ novos IDs de dispositivo/SDK). Prefixo de 2 bytes antes do `ff05` também mudou (`1W`→`_0`): o bin8 tem 48 chars + 2 (abril) vs 48 + 3 (novo) — a contagem do tamanho do bin vs bytes de controle ainda **não fecha** (ver §6).
* Estrutura (ordem dos campos, tags `c4` bin8, `07` str len+…) **idêntica** à de abril; só +9 B de tamanho (versão +2, token +1, controles).
* Depois do handshake: mesmo fluxo: `15/02 2c06` (hb #1), `15/01` pong (38 B, abril 35 B), rajada de ~110 frames `1d/01`/`5d/01`/`55/02` em ~0,2 s, `0d/01 342c` e `0d/01 8c1c` (**os mesmos 4 B das 5 conexões de abril**) + `0d/01 2287`.

## 4. Censo de opcodes (op/byte1) — 1.14.27 vs 1.9.5 (battle2 = sessão de 242 s)

| Dir | op/b1 | 1.14.27 (n, len min–max) | 1.9.5 battle2 (n, len) | nota |
|---|---|---|---|---|
| C→S | 55/02 | 1 (213) | 1 (204) | handshake |
| C→S | 15/02 | 28 (4) | 24 (4) | heartbeat; cadência ≈4,0 s igual; ver §5.3 |
| C→S | 1d/02 | 7 (5) | 18 (5) | igual |
| C→S | 5d/02 | 20 (7–180) | 78 (7–1684) | nesta sessão sem batalha: sem 5d grandes |
| C→S | 59/02 | 1 (51) | 5 (13–51) | só o longo (HMAC base64 `XU-HUgqAjPEGW32wGooCQRhbr0CVEnigY09w==`, p/ 27 B) em t=18,2 s; sem ACKs curtos de 13 B |
| C→S | **1d/03** | **3 (29, 2538, 2538)** | — | **NOVO byte1=03** |
| C→S | **19/03** | **1 (24)** | — | **NOVO opcode 0x19** |
| C→S | 35/02, 7d/02, 25/02, 3d/02, 79/02 | 0 | 10, 14, 1,1,1 | ausentes (eram específicos da sessão de batalha) |
| S→C | 55/02 | 57 (7–3062) | 126 (7–2047) | idem, canal de resposta (`55 02 01 NN 01 01 02`, NN par crescente: 06,08,…,`78`,`7a`,`7c`) |
| S→C | 1d/01 | 145 (6–3057) | 251 (6–3824) | 1º state-sync 3057 B (abril 2714/2721) |
| S→C | 5d/01 | 40 (6–616) | 45 (6–654) | |
| S→C | 0d/01 | 3 (4) | 2 (4) | +`0d01 2287` |
| S→C | 15/01 | 1 (38) | 1 (35) | pong |
| S→C | dd/01 | 1 (10) | 3 | |
| S→C | **15/03** | **4 (15, 15, 255, 420)** | — | **NOVO**: resposta às `1d/03`/`19/03` |
| S→C | 65/02, 75/02 | 0 | 1, 26 | ausentes (batalha) |

Opcodes novos nesta versão: **`19`** e **byte1 = `03`** (`1d/03`, `19/03`, `15/03`). Nenhum opcode de abril mudou de formato visível; os ausentes não foram exercitados (sessão sem batalha em tempo real). Nenhum opcode novo além desses.

### 4.1 Canal `03` (req/resp novo)
Pares observados (t em s):

| t | C→S | S→C resposta |
|---|---|---|
| 4,24 | `1d 03 0c08 24 51 06 02 04 fd 20 ef ba be b9 ec ba…` (29 B) | 4,43: `15 03 01 24 51 06 02 04 fd 20 ef ba be b9 ec ba ff 1c…` (255 B) |
| 7,97 | `1d 03 7417 2a 51 06 02 04 ff ff b6 13 ed ba bc b9…` (**2538 B**) | 8,17: `15 03 01 2a 51 06 02 04 3f b6 13 ed ba be b9` (15 B) |
| 17,78 | `1d 03 7417 34 51 06 02 04 ff ff b6 13 ed ba bc b9…` (2538 B) | 17,97: `15 03 01 34 …` (15 B) |
| 44,84 | `19 03 08 48 51 06 02 04 fd 1c ed ba bc b9 e9…` (24 B) | 45,10: `15 03 01 48 51 06 02 04 fd 1c ef ba be b9 ec ba ff 31…` (420 B) |

* O campo logo após o seq (`24, 2a, 34, 48`) é o **mesmo na req e resp** ⇒ id de correlação, e cresce ~1 unidade/s (t=4,2→44,8 s ⇒ 0x24→0x48): é um tick de relógio.
* Payload não é msgpack: repete tripletas `ba bc b9`/`ba be b9` (req) → `ba be b9` (resp, +2 no byte do meio) — parece lista de inteiros com codificação própria (valores ×2/zigzag?). Os 2538 B C→S são **um upload do cliente** quase idêntico duas vezes (7,97 s e 17,78 s); não analisado a fundo.

## 5. Decode de amostras

### 5.1 MessagePack — o que é (e não é)
* **Confirmado**: strings/chaves em msgpack padrão (fixstr `a1–bf`, `ce` uint32, `cd` uint16, `91` fixarray, `c4` bin8) aparecem em `1d/01` e no handshake. O `msgpack.Unpacker` decodifica os valores logo após cada chave.
* **Mas o fluxo NÃO é msgpack puro**: bytes de controle (`ff NN`, `f1 NN`, `e3`, `7f`, `3f`, `1f`, `f9 00 00 22…`) são **inseridos no meio** de chaves/valores (`battl ⟨ff17⟩ e_type`, `"102" ⟨ff01⟩ "3856436397712"`), então um `Unpacker` direto sobre o frame falha (testei decode de mapas `8d…` em todos os frames: 0 mapas completos). Fora dos 1d de relatório, a maior parte dos `1d/01`/`5d/01` é binário compacto não-msgpack (`1d 01 a021 02 4c70 02 16 04 02 71 04 f6 22 …`). Camada abaixo (provavelmente a mesma de abril) **continua não decifrada**.
* Decode tolerante (localizar cada chave exata, parsear o valor seguinte) funciona.

### 5.2 Frame `55/02` S→C #254 (703 B) = relatório de batalha — **mesmas chaves de abril, mesma estrutura**
Mapa de 13 chaves (ordem varia entre registros): `atk_abbr, def_abbr, atk_uid, def_kid, atk_kid, def_uid, side, atk_uids, def_uids, def_nickName, atk_nickName, result, battle_type`. 3 registros:

```
{atk_nickName:"The\xa0Fallen\xa0Jr" (nbsp=c2 a0), atk_abbr:"SPE", atk_uid:42277632, atk_kid:931, atk_uids:[42277632],
 def_nickName:"zerado", def_abbr:"spa", def_uid:40444746, def_kid:931, def_uids:[40444746], side:2, result:1, battle_type:7}
{… mesmo atk, def_uids:[40444746] …}
{atk_nickName:"lordicus", atk_abbr:"kHr", atk_uid:34190746, atk_kid:931 …  def_uid 40444746, result 1}
```
(def_uids corrompido por controle em 2 casos: `40444899`, `520251683` ⇒ efeito dos bytes inseridos.) Cada registro é precedido por uma **string-id de 16 dígitos** (`"1023856436397712"`, `…09`) + bloco binário.

Diferenças vs abril (1.9.5, frame 1d de 1720 B): lá o tipo era **`1d/01`**; aqui o relatório veio num **`55/02`** S→C (703 B) — único frame com as chaves nesta captura (3 registros). Chaves **idênticas** (atk_uid/def_uid/atk_uids/def_uids/atk_kid/def_kid/nickName/abbr/battle_type/result/side); defensor é o mesmo jogador (`zerado`/`spa`, uid 40444746 = game_user_id, kid **931**). **Reino 931 aparece como `cd 03 a3`** (uint16 931) em `atk_kid`/`def_kid` — resolve a divergência de §4 #15 do walkthrough ("931 ausente do handshake": está nos relatórios, não no handshake).
Nicks: atacantes novos ("The Fallen Jr", "lordicus"), `SPARTAN…`, `Exosphere`, `Citizen`, `al fam…`.

### 5.3 Heartbeat
`15 02 2e MM`, byte[2] fixo `2e` (1º = `2c 06`), byte[3]: 30,32,3a,3e,40,42,46,4a,4e,50,52,54,58,5a,5e,60,62,64,66,68,6a,6c,72,74,76,7a,7c — crescente, **não +1**, par sempre; 0x7c-0x30 = 76 em 119 s (~0,64/s) mas intervalos irregulares ⇒ ainda tick de tempo parcial. Cadência 4,0 s (3,9–4,2) em todos os 28. O pong `15/01` (38 B) vem 1× e começa `15 01 44 07 04 02 10 04 1e 95 fb 5f …` — compare abril `15 01 44 06 04 02 84 04 95 c7 fb 5f`: mesmo prefixo `15 01 44 0x 04 02` e terminação `fb 5f` nos campos de tempo (semântica ainda não resolvida).

### 5.4 Strings JSON no handshake S→C (flags)
`{"12":true,…"22":true}` e `{"p_giftid":4000751,"device_lvl":2,"fp_countrycode":"BR"}` — **idênticos** a abril (p_giftid inalterado), `["en","arab","zh_cn",…,"pl"…]` lista de línguas (também), host `c02-rtm-intl-frontgate.ilivedata.com:13321` (igual).

## 6. Achados estruturais (resumo)

1. **Framing 0 erros**; formato `uint16_BE(len)+op+byte1` inalterado de 1.9.5 → 1.14.27.
2. **Versão 1.14.27 confirmada** no handshake C→S e S→C (`"1.14.2"+ctrl+"7"`).
3. Handshake idêntico em estrutura; **token e IDs hex-32 diferem** (novo install) ⇒ token estático é só por sessão/instalação.
4. **Novo**: byte1=`03` e opcodes `19/03`, `1d/03`, `15/03` = pares requisição/resposta com id de correlação (tick) — incluindo upload cliente 2538 B repetido. Ausentes em 1.9.5.
5. Relatórios de batalha com as **mesmas chaves msgpack** (atk_uid/def_uid/atk_uids/def_uids/…); kid 931 via `cd 03a3`.
6. Camada de **bytes de controle intercalados persiste**; sem ela msgpack decodificaria direto. Observação: nos testes, `ctrl` tipo `ff NN`/`f1 NN` aparece entre campos e dentro de strings; o bin8 do token declara 51 B para 2+48 chars + `ff05`(=4 bytes ⇒ 52) em 1.14.27 e 50 para 52 em abril ⇒ ctrl bytes são **contados às vezes e outras não** (ou prefixo "5f30"/"3157" é parte do ctrl). Não resolvido.
7. Sem batalha/RTS na sessão ⇒ opcodes 35/7d/25/3d/79/65/75 não exercitados; precisa nova captura com combate para comparar.

## 7. Resíduos / riscos
* Sessão só 132 s, 1 conexão, sem combate — cobertura de opcodes parcial.
* O fim abrupto (sem FIN/RST) sugere jogo fechado ou rede perdida; verificar se o jogo reconectou (não há 2ª conexão).
* Tcpdump sem `-U` só grava no fim; arquivo `/sdcard/cap115.pcap` ficou no phone (root-only), `/data/local/tmp/td.log` também.
* Decode "msgpack" depende de ignorar controles; valores numéricos próximos a ctrl podem estar corrompidos (ex.: def_uids).
