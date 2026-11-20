# Teste de mesa do protocolo gateway (porta 30101) — pcaps originais do estudo 1.9.5

Lane Q · tudo offline · parser próprio em `C:/Users/prs/work/laneQ/` (`parse.py`, `tl.py`, `an2.py`, `an3.py`; cópia dos scripts antigos + saídas em `old/`). Nenhum arquivo do repositório foi alterado.

## 0. Resumo executivo

* **Framing `uint16_BE(len)+body`: CONFIRMADO, 0 erros** nas 6 direções/streams TCP (battle: 2 conexões; battle2: 1): 100% dos bytes reassemblados são consumidos em frames (sobra 0, 0 gaps, 0 retransmissões).
* Handshake, heartbeat, opcodes principais, classes de tamanho e IDs: **confirmados**. Scripts antigos reproduzem exatamente os números documentados (§5).
* **Divergências relevantes da doc** (§4): (a) "byte[1] = direção" falha para `0x55` (o servidor responde com `55 02`, ~46–126 frames/sessão), `0x75`/`0x65` S→C e `0xdd`; (b) as "coordenadas ASCII85" são, com alta probabilidade, **falso-positivo**: os `…@` são o byte alto (0x40) de doubles IEEE-754 e os `…Vl$` são um campo de 4 B em registros `5d/01`; (c) **kingdom 931 não está no handshake** (só em `"int farm alliance call 931!"`) e `931!`→"reino 2" é lixo; (d) "93 frames 5d C→S por sessão" não ocorre (26/33/78).
* **Descoberta que a doc perdeu: o payload dos frames `0x1d`/`0x5d` é MessagePack** (`a8 "atk_uids"`, `91 ce 02 69 23 4a` = `[40444746]`, `b2 "The\xa0Fallen\xa0Angel"`), com bytes de controle (`ff 00`, `1f`, `fc`, `f1 09`, `3f`…) **intercalados no meio de strings/valores** — explica as strings "partidas" (`tansFarm`, `3846?01255`, `k_kid`). Não é JSON/protobuf nem varint puro.
* Capturas **truncadas**: battle.pcap = 114688 B (0x1C000), battle2.pcap = 131072 B (0x20000); último registro pcap cortado (7 e 50 B sobrando). battle2 tem **759** registros completos + 1 truncado (doc diz 760).

## 1. Método

1. Parser pcap próprio (LE, linktype 113 = Linux SLL; IP/TCP à mão), filtro porta 30101, reassembly por seq TCP (descarta duplicados, conta gaps).
2. Split `uint16_BE`; erro = frame que ultrapassa o buffer ou sobra ≠ 0.
3. Cross-check com `scripts-sample/analysis/*.py` (rodados em cópia dos pcaps).
4. Busca de strings/IDs em 4 codificações (texto, varint, LE32, BE32).

## 2. Framing — resultado

| Stream (porta cliente) | segs TCP | bytes | frames | erros | sobra | gaps |
|---|---|---|---|---|---|---|
| battle #1 C→S (46864) | 82 | 2699 | 48 | 0 | 0 | 0 |
| battle #1 S→C | 90 | 39225 | 202 | 0 | 0 | 0 |
| battle #2 C→S (47026) | 96 | 2805 | 50 | 0 | 0 | 0 |
| battle #2 S→C | 92 | 39656 | 205 | 0 | 0 | 0 |
| battle2 C→S (37088) | 406 | 8352 | 153 | 0 | 0 | 0 |
| battle2 S→C | 353 | 58874 | 455 | 0 | 0 | 0 |

Frames chegam a 3824 B (> MTU) e o reassembly funciona; todos têm len ≥ 4. Cliente 192.168.0.65, servidor 3.33.245.139. As duas streams de battle.pcap são **duas conexões consecutivas** com handshake idêntico.

### Tabela op/byte1 observada (battle2.pcap)

| Dir | op/b1 | n | Comentário |
|---|---|---|---|
| C→S | 15/02 | 24 | heartbeat |
| C→S | 1d/02 | 18 | doc diz "S→C dominante": existem C→S (9–18 por sessão, sempre 5 B) |
| C→S | 55/02 | 1 | handshake 204 B |
| C→S | 59/02 | 5 | 4×13 B + 1×51 B |
| C→S | 5d/02 | 78 | 26 e 33 em battle.pcap |
| C→S | 7d/02 | 14 | desconhecido (doc ✓ 14) |
| C→S | 35/02 | 10 | desconhecido (doc ✓ 10), sempre 5 B `35 02 2e NN 01` |
| C→S | 25/02, 3d/02, 79/02 | 1 cada | **não documentados** |
| S→C | 1d/01 | 251 | |
| S→C | 55/**02** | 126 | byte[1]=02 em S→C; 7–13 B na maioria; 63 B o 1º (resposta do handshake); até 2047 B |
| S→C | 5d/01 | 45 | |
| S→C | 75/02 | 26 | **não documentado** |
| S→C | 65/02 | 1 | **não documentado** (13 B) |
| S→C | dd/01 | 3 | **não documentado**; `dd 01` = varint de 2 B? (ver §4.2) |
| S→C | 0d/01 | 2 | 4 B `0d 01 34 2c` e `0d 01 8c 1c` idênticos nas 5 conexões |
| S→C | 15/01 | 1 | pong 35 B |

## 3. Timeline de uma sessão (battle2.pcap, porta 37088, 608 frames em 242,5 s)

Ordem por nº de pacote (C→S e S→C intercalados); `t` = tempo do segmento que completa o frame.

| # | pkt | t (s) | dir | op/b1 | len | primeiros bytes (hex) | nota |
|--|--|--|--|--|--|--|--|
| 0 | 4 | 0.000 | C→S | 55/02 | 204 | `5502040411100115010204040151` | handshake C→S |
| 1 | 6 | 0.374 | S→C | 55/02 | 63 | `55020104121d0248070155020203` | resposta do handshake (S→C usa 55/**02**) |
| 2 | 8 | 0.851 | C→S | 15/02 | 4 | `15022c06` | heartbeat, contador 2c |
| 3 | 10 | 1.075 | S→C | 15/01 | 35 | `150144060402840495c7fb5f0435` | pong 35B (timestamps) |
| 4 | 14 | 1.076 | S→C | 1d/01 | 2721 | `1d01d0420714768e3101f00ad118` | 1º state-sync (2721B; 2714B em battle.pcap) |
| 5 | 16 | 1.077 | S→C | 1d/01 | 14 | `1d015c3408450201021401020000` |  |
| 6 | 18 | 1.077 | S→C | 5d/01 | 13 | `5d01cc32022ac4048797030969` |  |
| 7 | 20 | 1.077 | S→C | 1d/01 | 395 | `1d017020024c6c02067402c20f08` |  |
| 8 | 22 | 1.078 | S→C | 1d/01 | 64 | `1d01da510245046c0e140204d104` |  |
| 9 | 24 | 1.078 | S→C | 1d/01 | 411 | `1d01662204f43024010a02440e02` |  |
| 10 | 26 | 1.079 | S→C | 1d/01 | 212 | `1d015e44011392012e0503047104` |  |
| 11 | 28 | 1.079 | S→C | 1d/01 | 117 | `1d01e80c0111b8031402a8d11803` |  |
| 12 | 30 | 1.346 | S→C | 1d/01 | 38 | `1d01f8470111360e450204047cf1` |  |
| 13 | 30 | 1.346 | S→C | 1d/01 | 205 | `1d01f40a01133c011a3d06a8015a` |  |
| 14 | 30 | 1.346 | S→C | 1d/01 | 208 | `1d010e1701137401424106064004` |  |
| 15 | 30 | 1.346 | S→C | 1d/01 | 31 | `1d01763801112a260506cc540402` |  |
| 16 | 30 | 1.346 | S→C | 5d/01 | 33 | `5d01c024050a53c202040411240e` |  |
| 17 | 32 | 1.350 | S→C | 1d/01 | 1172 | `1d019843024c9e061c1405824505` |  |
| 18 | 32 | 1.350 | S→C | 1d/01 | 35 | `1d01b65701113e0600c404fc4085` |  |
| 19 | 32 | 1.350 | S→C | 1d/01 | 46 | `1d0182520111540a4004500204c4` |  |
| 20 | 32 | 1.350 | S→C | 1d/01 | 30 | `1d01b657011136064002c4040a41` |  |
| 21 | 32 | 1.350 | S→C | 1d/01 | 46 | `1d016e4801114e09501cb6100271` |  |
| 22 | 32 | 1.350 | S→C | 1d/01 | 75 | `1d01825201118a0a4002500202c4` |  |
| 23 | 32 | 1.350 | S→C | 1d/01 | 34 | `1d01aa5901113805007104ca4826` |  |
| 24 | 32 | 1.350 | S→C | 1d/01 | 45 | `1d0154500111530700142604170d` |  |
| 25 | 32 | 1.350 | S→C | 1d/01 | 97 | `1d017c690111a014005502021604` |  |
| 26 | 32 | 1.350 | S→C | 1d/01 | 10 | `1d018e6901e1046ebf68` |  |
| 27 | 32 | 1.350 | S→C | 5d/01 | 7 | `5d016c5b020100` |  |
| 28 | 32 | 1.350 | S→C | 1d/01 | 6 | `1d013e4a0100` |  |
| 29 | 32 | 1.350 | S→C | 1d/01 | 6 | `1d0134110100` |  |
| 30 | 32 | 1.350 | S→C | 1d/01 | 12 | `1d015a5601110a0615020404` |  |
| 31 | 32 | 1.350 | S→C | 1d/01 | 115 | `1d01fc1102449e0340824406021f` |  |
| 32 | 32 | 1.350 | S→C | 1d/01 | 212 | `1d01e6071e05040237480704d407` |  |
| 33 | 32 | 1.350 | S→C | 1d/01 | 82 | `1d012c0a0111860e4502d8045cf9` |  |
| 34 | 32 | 1.350 | S→C | 5d/01 | 26 | `5d01c01b0310101d230401022203` |  |
| 35 | 34 | 1.350 | S→C | 1d/01 | 364 | `1d01dc0e01132a020e4502d4044c` |  |
| 36 | 34 | 1.350 | S→C | 1d/01 | 726 | `1d0148160604044d043404205407` |  |
| 37 | 34 | 1.350 | S→C | 1d/01 | 23 | `1d014e1601111a161d06de010455` |  |
| 38 | 34 | 1.350 | S→C | 1d/01 | 6 | `1d01d8490100` |  |
| 39 | 36 | 1.350 | S→C | 1d/01 | 1210 | `1d019c080113ee080e510212045c` |  |
| 40 | 36 | 1.350 | S→C | 1d/01 | 7 | `1d01a021020000` |  |
| 41 | 36 | 1.350 | S→C | 1d/01 | 153 | `1d01984b031015670454c35cc366` |  |
| 42 | 36 | 1.350 | S→C | 1d/01 | 173 | `1d01441f030011f0065d02b24fe0` |  |
| 43 | 36 | 1.350 | S→C | 5d/01 | 8 | `5d013c1802600170` |  |
| 44 | 36 | 1.350 | S→C | 1d/01 | 73 | `1d01e01e051102031064d10602dc` |  |
| 45 | 38 | 1.350 | S→C | 1d/01 | 1134 | `1d01140e01139c085a5107040141` |  |
| 46 | 40 | 1.350 | S→C | 1d/01 | 2538 | `1d017e150113e112f84d027802ee` |  |
| 47 | 40 | 1.350 | S→C | 1d/01 | 381 | `1d01d420031024010331049df8f1` |  |
| 48 | 40 | 1.350 | S→C | 0d/01 | 4 | `0d01342c` |  |
| 49 | 41 | 1.351 | S→C | 1d/01 | 729 | `1d0152260504fc1334050e510204` |  |

### Estatística dos frames 50–607

| Dir/op | n | | Dir/op | n |
|---|---|---|---|---|
| S→C 1d | 211 | | C→S 7d | 14 |
| S→C 55 | 125 | | C→S 35 | 10 |
| C→S 5d | 78 | | C→S 59 | 5 |
| S→C 5d | 40 | | S→C dd | 3 |
| S→C 75 | 26 | | 0d, 65, 25, 3d, 79 | 1 cada |
| C→S 15 | 23 | | C→S 1d | 18 |

### Handshake

Sequência: `C→S 55/02 204 B` → `S→C 55/02 63 B` (+0,37 s) → `C→S 15/02` (hb #1, +0,85 s) → `S→C 15/01 35 B` (pong) → rajada ~50 frames `1d/01`+`5d/01`+`55/02` em ~35 ms (1º `1d` = 2721 B; 2714 B em battle.pcap) com um `0d/01` de 4 B no início da rajada.
O handshake C→S é **byte-idêntico nas 3 conexões** (204 B): token estático (✓ FLOW), sem nonce/timestamp. A resposta S→C (63 B) difere só nos últimos varints (tempo/nonce do servidor).

Conteúdo (strings, controles removidos):

| Campo | Valor | Doc |
|---|---|---|
| token (48 chars) | `OEGFLbwPPabuxrSMmrqxyValDSbmQjLjOp8Ze3428BoU1rfR` | ✅ |
| user_id | `3846`+`3f`+`01255` → **384601255** (9 dígitos; `0x3f` é byte de controle) | ✅ (doc mostrava `3846?01255`) |
| versão | `1.9.5` (`05 7e` antes) | ✅ |
| device | `motorola moto g(8)` (len 0x12=18; partida em `motoro`/`ff 00`/`la moto `/`1f`/`g(8)`) | ✅ |
| os | `android` (len 7) | ✅ |
| país | `BR` (len 2) | ➕ novo |
| lang | `pt` | ✅ |
| hex-32 #1 | `8c5b805`+`1660a0e60b1b4a39716e02ba`+`6` = `8c5b8051660a0e60b1b4a39716e02ba6` (len 0x20) | ✅ = sdk_id do FLOW; GATEWAY_PROTOCOL tinha só fragmentos ("hash1/hash2") |
| hex-32 #2 | `25f42`+`e1458e920db92bce7c199b3d`+`b74` = `25f42e1458e920db92bce7c199b3db74` | ➕ ID sem rótulo ("hash3/hash4" eram fragmentos) |
| kingdom 931 | **ausente** (sem `931`, sem varint `a3 07`) | ❌ |

Padrão: `len` + (byte de controle) + chars, com bytes extras no meio (`ff 00`, `ff 02`, `ff 05`, `e3`, `1f`, `f1 09`, `3f`). Versão: C→S `05 7e "1.9.5"`, S→C `05 fc "1.9.5"` (`0xfc = 0x7e<<1`).

### Heartbeat (C→S `15 02 NN MM`)

* 1º sempre `15 02 2c 06`; depois `15 02 2e MM` — **byte[2] é `2c`/`2e` (quase constante) e o contador é byte[3]**, que cresce com o tempo (`2c,34,36,3a,3e,40,44,46,4c,50,52,56,7c,8a,b0,…,f4`) mas **não +1** (parece tick de tempo, 1 byte truncado de um varint); a doc ("2c,2e,30 seq incremental") olhou o byte errado. Hipótese a validar.
* Cadência: modal **~4,0 s** (3,97–4,25), com intervalos de 7–25 s durante tráfego intenso (battle2: 6.9, 9.8, 4.0, 4.0, 4.2, 3.7, 5.0, 4.0, 4.1, 6.9, 4.3, 4.0, 17.1, 11.0, 23.0, …). "~4 s" ✅ como mínimo.
* Pong `15 01 44 06 04 02 84 04 …` 35 B: **só 1 por sessão** (respondendo ao 1º hb); prefixo idêntico nas 3 sessões. Os hb seguintes não têm `15/01` visível.
* Timestamps: `a7 b4 df 69` → LE32 0x69dfb4a7 = 2026-04-15 15:54:15 UTC, mas o pcap começa 2026-04-15 20:29:40 UTC (**não bate** como epoch direto; encoding não resolvido).

## 4. Matriz de verificação

✅ confirmado · ⚠️ parcial · ❌ divergente · ➕ novo

| # | Afirmação documentada | Observado | |
|---|---|---|---|
| 1 | Framing `uint16_BE(len)` sem incluir a si mesmo | 0 erros em ~1,7 k frames, sobra 0 | ✅ |
| 2 | Mensagens >1400 B remontadas do TCP | frames até 3824 B | ✅ |
| 3 | body[0]=opcode, body[1]=direção (01 S→C / 02 C→S) | vale p/ 15,1d,59,5d,7d,35,0d,25,3d,79. **Falha**: `55`, `75`, `65` em S→C têm `02`; `dd 01` | ⚠️ |
| 4 | Opcodes 55,5d,1d,15,59 + desconhecidos 7d,35,0d | todos observados; **além**: 25,3d,79 (C→S), 65,75,dd (S→C) | ✅ ➕ |
| 5 | `0x55` = handshake | C→S 1× 204 B é o handshake; S→C `55/02` ocorre 46–48× (battle) / 126× (battle2), maioria 7–13 B (`55 02 01 NN 01 01 02`, NN par crescente 06,08,0a,0c…) ⇒ canal de resposta/RPC | ⚠️ |
| 6 | 1d "S→C dominante" | S→C 121–251; C→S 9–18 (5 B) | ✅ |
| 7 | 1d (battle2): ≤30:112, 31–200:99, >200:40 (=251) | **112/99/40 exato** | ✅ |
| 8 | maior frame 3824 B | 3824 B (2× battle, 1× battle2) | ✅ |
| 9 | 1º state sync 2714 B | 2714 (battle) / 2721 (battle2) | ✅ |
| 10 | Handshake C→S 204 B, S→C 63 B | 204 / 63 | ✅ |
| 11 | token `OEGFL…rfR` estático | idêntico nas 3 conexões | ✅ |
| 12 | 1.9.5 / motorola moto g(8) / android / pt | todos | ✅ |
| 13 | user_id 384601255 | presente (texto, 1 byte de controle no meio) | ✅ |
| 14 | sdk_id 8c5b8051660a0e60b1b4a39716e02ba6 | reconstruído = igual | ✅ |
| 15 | **kingdom 931 no handshake** | ausente; 931 só em `"int farm alliance call 931!"` (5 ocorr. S→C) | ❌ |
| 16 | game_user_id 40444746 | msgpack `ce 02 69 23 4a` em **14 posições** de 1 frame 1d (def_uid/def_uids); LE32 em outros frames (5–7 S→C, 1 C→S) | ✅ |
| 17 | campos atk_uid/def_uid/atk_uids/def_uids/atk_nickName/atk_abbr/atk_kid/battle_type/result | todos num frame 1d de 1720 B (S→C #164 battle2), ~8 registros | ✅ |
| 18 | "Bellona", "SpartansFarm" | `Bellona` 4× ✅; `SpartansFarm` só partido (`tansFarm`) pelos controles | ⚠️ |
| 19 | `c02-rtm-intl-frontgate.ilivedata.com` | 1× S→C | ✅ |
| 20 | JSON flags `{"12":true…"22":true}` e `{"p_giftid":4000751,"device_lvl":2,"fp_countrycode":"BR"}` | strings presentes em 1 frame S→C (fragmentos) | ✅ |
| 21 | Heartbeat `15 02 2c 06` ~4 s | 1º `15022c06`; cadência modal 4,0 s; contador é byte[3], não +1 | ⚠️ |
| 22 | Pong `15 01 44 06 …` 35 B | idêntico, 1 por sessão | ✅ |
| 23 | `0x59` "2 ocorrências" (GATEWAY_PROTOCOL) | battle: 1 por stream; battle2: **5** (FLOW/CLAUDE "some frames" ok) | ⚠️ |
| 24 | 0x59 longo: HMAC 27 B `Yuoo0N3p7nDUsi8hmNhCUW6UAO6mHsoxoeNg==` | frame 51 B: `59 02 6c 64 01 c4 28 · 77 72 ff 04 · <36 chars base64> · 3d 3d · 00 00`. 36 chars → **27 B** `62ea28d0dde9ee70d4b22f2198d842516e9400eea61eca31a1e360`; o `==` é padding excedente (base64 estrito rejeita). Blob `c4 28` = 40 B = 4 B prefixo + 36 chars; `3d3d0000` fora do blob. **No fio vai base64 ASCII, 27 B é o decode.** Só em battle2 | ✅ valor / ⚠️ descrição |
| 25 | 0x59 curtos = ACK com seq incremental | 13 B `59 02 08 NN 01 c4 05 04 xx xx xx xx TT`; NN = `48,78,b4,e8` (battle: `52`,`2a`) cresce como o tick do hb; blob `c4 05` de 5 B + 1 B final (01/02/03) | ⚠️ |
| 26 | 5d C→S "93 frames/sessão" | 26 e 33 (battle), 78 (battle2) | ❌ |
| 27 | 5d C→S grande ~1763 B | battle: 1763 B ✅; battle2: 1684 e 1610 B | ✅ |
| 28 | padrão `5d 02 f0 15 seq 01 03 val` | não reproduzido (5d C→S curtos 6–13 B sem prefixo fixo `f0 15`) | ❌ |
| 29 | **Coordenadas ASCII85 4 chars, reino=high16/pos=low16** | aritmética reproduz, mas semanticamente falso-positivo (§4.1) | ❌ |
| 30 | `931!` = reino | vem do texto `…alliance call 931!` | ❌ |
| 31 | `@` global / `$` sub-objeto | `@`=0x40 byte alto de float/double; `$`=0x24 fim de token de 4 B | ❌ |
| 32 | payload "varint-like, não protobuf" | é **msgpack** + controles intercalados | ➕ |
| 33 | `0x0d` S→C 4 B ×2 | 2×/stream, constantes | ✅ |
| 34 | plaintext/sem TLS | strings legíveis | ✅ |

### 4.1 Por que as "coordenadas ASCII85" são falso-positivo

* `ZdsX@`/`dsX@` aparecem como `… ca ab 1c 5a 64 73 58 40 …` (com `1f`/`c7`/`7f` inseridos no meio). Lido LE, `ca ab 1c 5a 64 73 58 40` é um **double ≈ 97,7** (`@`=0x40 é o byte de expoente). Posição em float é o esperado num jogo tower-defense, não "reino+pos".
* `kVl$`, `vVl$`, `wVl$`, `cVl$`… ocorrem em `5d/01` (654 B, 550 B) como `0c 11 01 04 17 XX 56 6c 24 51 04 …`: XX varia em 0x63–0x77 e `56 6c 24` é constante ⇒ campo de ID de 4 B, não coordenada.
* Reinos "decodificados" (541, 636, 699, 802, 811…) nunca são 931 nem plausíveis; 45 ocorr./26 distintos em battle2, 19/17 em battle.
* O decoder "funciona" só porque 85⁴ ≈ 52 M < 2³²: qualquer 4-char imprimível decodifica.
* Recomendação: rebaixar a seção "Coordinate Encoding" (CLAUDE.md, FLOW.md, deep_analysis.py) a hipótese refutada até validar contra um mapa conhecido.

### 4.2 Estrutura do payload (achados novos)

Frame 1d S→C 1720 B (#164 do S→C de battle2):

```
a8 "atk_uids"      91 ce 02 09 63 0a   -> [34169610]
a8 "def_uids"      91 ce 02 69 23 4a   -> [40444746]   (game_user_id)
ac "atk_nickName"  b2 "The\xc2\xa0Fallen\xc2\xa0Angel"
a8 "def_abbr"      a3 "spa"
ab "battle_type"   07
a8 "atk_abbr"      a3 "WAR"
a7 "def_uid"       ce 02 69 23 4a
a6 "result" ...
```

⇒ atacante "The Fallen Angel" [WAR] (uid 34169610), defensor 40444746 [spa]; ~8 registros de relatório de batalha (nicks `Bellona`, `zerado`, `Awee8`…). Mapa msgpack com chaves `atk_kid,side,atk_uids,def_uids,atk_nickName,def_abbr,battle_type,atk_abbr,def_uid,result,def_kid,atk_uid,def_nickName`.
Controles aparecem **dentro** de chaves (`atk_kid` → `at`+`ff 15`+`k_kid`). Mecanismo desconhecido (escape/LZ-like) — camada abaixo do msgpack a decifrar.

Hipótese não testada para byte0: tag estilo protobuf (`op>>3`, wiretype `op&7`): 0x55→10/wt5, 0x5d→11/wt5, 0x1d→3/wt5, 0x15→2, 0x0d→1, 0x59→11/wt1; `0xdd` = byte com MSB=1 ⇒ varint de 2 B (`dd 01` = 221 → campo 27), o que explicaria por que `dd` não tem "dir". Encaixa, mas sem teste.

### 4.3 Outros achados

* `35/02` C→S: sempre `35 02 2e NN 01`, NN par crescente (0a,0e,10,18,24,28,2c,2e,30,34) ⇒ mesmo tick do heartbeat; provável heartbeat/sync de batalha.
* `7d/02` C→S (14): 16–42 B, com sequências `22 cb db 22 da d5 22 e7 e6…` e 1 timestamp `bb f6 df 69` ⇒ lotes de ações em tempo real.
* Handshake S→C 63 B contém `1.9.5` e `827` (provável versão de protocolo/ID), idêntico nas 3 sessões exceto últimos varints.
* `deep_analysis.py` "frame# 48 len=51" = índice no C→S, coincide com meu `n=48`.
* `pframes()` do `deep_analysis.py` faz resync `i+=1` se len inválido — nunca acionado aqui (0 erros).
* Capturas truncadas em múltiplos de 16 KiB (provável corte da cópia); battle2 (242 s) termina abruptamente.

## 5. Regressão dos scripts antigos (re-executados)

| Script | Resultado |
|---|---|
| `analyze_gateway.py battle.pcap` | 360 pkts, 2 streams; C→S `{93:26,29:17,21:3,85:1,89:1}` e `{93:33,29:9,21:6,85:1,89:1}`; S→C `{29:121,85:48,93:30,13:2,21:1}` e `{29:125,85:46,93:31,13:2,21:1}` — **idêntico ao meu parser** |
| `analyze_gateway.py battle2.pcap` | 760 pkts (759 com payload TCP), 1 stream, strings (token, 1.9.5, ZdsX@, p_giftid…) ✔ |
| `decode_1d_v2.py` | roda sem erro (581 linhas; frame 3824 B) ✔ |
| `deep_analysis.py` | tabela de "coordenadas" idêntica à doc (`ZdsX@`×5, `931!`…); 0x59: 5 frames; base64 `Yuoo…` → 27 B ✔ — reproduz, mas o resultado é o falso-positivo de §4.1 |

`deep_analysis.py`/`decode_1d_v2.py` abrem `battle2.pcap` do cwd (copiei os pcaps para `old/`).

## 6. Resíduo (não fechado)

* Mecanismo dos bytes de controle intercalados.
* Semântica do contador do heartbeat/0x35/0x59 (byte[3]) e dos timestamps (pong ≠ epoch do pcap).
* Prefixo `77 72 ff 04` do blob do 0x59 longo e `==` residual.
* Padrão `f0 15 seq 01 03` dos 5d curtos.
* `SpartansFarm` completo e UID 384601255 em binário não localizados.
