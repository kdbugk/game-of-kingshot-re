# RELATÓRIO — LANE KIND03-CODEC (canal `kind 03`, Kingshot 1.14.27)

Análise offline de `cap_combat2.pcap` (captura própria). Nada dinâmico, nada escrito no repo.
Arquivos desta pasta: `ex.py` (extrai frames+timestamps → `frames.pkl`, `frames03.txt` hex bruto dos 58 frames kind 03), `kind03dec.py` (decoder experimental), `validate.py` (re-encode + invariantes), `samples_decoded.json`, `a1..a9.py` (explorações).

## 1. Resultado em uma frase
O canal kind 03 **não é msgpack nem compressão: é um serializador binário little-endian (estilo BinaryWriter: `u32 len + bytes`, doubles IEEE-754) ofuscado por XOR com chave periódica de 4 bytes `b9 24 5f bd`** (fase 0 = primeiro byte depois do prefixo), com um "token" de 2 bytes não-XOR inserido às vezes. Decodificado de ponta a ponta nos 7 snapshots (31 registros × 5 doubles cada) e parcialmente nos pequenos.

## 2. Como cheguei (evidência)
* O corpo dos snapshots tem blocos periódicos de 4 B `b9 24 5f bd` (e variantes de 1 bit: `b1`, `bb`, `57`…) → "zeros" XOR chave. `plain = cipher ^ key[i%4]` produz imediatamente `01 00 00 00 | 84 09 00 00 | 02 00 00 00 …` e doubles `e7 5c 8f c2 f5 70 52 40` = 73.765.
* A mesma chave vale para todas as 58 mensagens kind 03 da captura (C→S e S→C). (Na cap115/1.9.5 a chave visível era outra, `ef ba be b9`/`ed ba bc b9` — chave por sessão/versão, não derivada do id; **não** investigado de onde vem.)
* Resposta ao `3d 03 f0 15 …` traz o **unix time do servidor** (`b2 97 ff 6a` = 1795135410 ≈ nov/2026), crescendo ~1,003 s/s em relação ao relógio da captura (21 respostas) — mesmo `ff 6a` final que o `7d/02 e8 15 …33 99 ff 6a`.

## 3. Formato proposto

### 3.1 Envelope (já conhecido)
```
C→S  3d 03 <tag16> <id16LE> 51 06 02 04 <corpo>
S→C  35 03 01 <id16LE> 51 06 02 04 <corpo>        (id = mesmo da requisição; pares 29/29)
```
`tag16`: `74 17` = snapshot, `f0 15` = consulta de entidade, `0c 08` = consulta de perfil. (id par, +2 — já documentado.)

### 3.2 Prefixo do corpo (NÃO xor)
| prefixo | onde |
|--|--|
| `ff ff 1a 13` | snapshot C→S (2462 B) |
| `3f 1a 13` | ACK do snapshot S→C (16 B) |
| `3d 0a` / `fd 0a` | consulta de entidade req / resp |
| `fd 20` | consulta de perfil req (30 B) / resp (264 B) |

Leitura: o 2º byte (`0a`, `20`, `1a 13`) é **idêntico em req e resp** ⇒ id do sub-comando (0x0a=entidade, 0x20=perfil, 0x131a=snapshot); o 1º byte (`3d`/`fd`/`3f`/`ff`) é flags (req/resp diferem em `3d→fd`, `ff ff→3f`) — significado dos bits **não decifrado**.

### 3.3 Corpo = stream XOR
`plain[i] = body[pre+i] ^ KEY[i % 4]`, KEY=`b9 24 5f bd`, com **tokens de 2 B em claro** (não-XOR, não avançam a fase) em posições: `ff 00` no offset 6 do stream nos frames `fd 20`/`fd 0a` (req perfil, resp perfil `ff 1d`, resp entidade `ff 00`) e `xx 64` no offset ~2044 do snapshot (antes do registro 26; `xx` = `fd,fb,f8,86` varia entre snapshots, `64` fixo). Natureza dos tokens **pendente** (ver §6); no snapshot eles entram na contagem de `declen`.

### 3.4 Snapshot C→S (2462 B)
```
u32 ver=1 | u32 declen=2436 | u32 cnt=2 | 00 00
u32 4 + 4B campo (3b 17 23 01 = 0x0123173b, igual nos 7 snapshots; = id de jogador/conta?)
u32 reclen=2418 (=31×78)
31 × REGISTRO:
   u32 74 | u16 type=6 | u32 idx (par) | 8 B zeros | 5 × ( u32 8 | f64 )
2 B de tail (=0) , + token (§3.3)
```
* `idx` ∈ {4,6,8,10,14,408,412,414,418,426,428,436,438,440,442,444,446,448,450,452,454,460,462,464,466,468,470,472,474,476,478}: **mesmo conjunto e mesma ordem nos 7 snapshots**.
* Os 5 doubles ficam em **[0, 100]** (`80.487`, `100.0`, `0.0` dominam) → 5 medidores percentuais por entidade (HP/energia/etc. — rótulo não provado). Evolução: no 1º snapshot (t=6,7) reg0 = 73,8/80,5/79,2/0/0; em t=305–335 = 100/100/100/~30/0; em t=485 (após a janela de combate 300–400 s) cai para 77,7/80,7/80,7/0/0 — i.e. **o estado muda de forma coerente com o combate** e recupera (574 s: 89/100/100). Todos os 31 registros diferem entre snapshots (nenhum é "só um campo": é estado completo reenviado, não diff).
* Snapshots em t = 6,7 · 96,5 · 126,6 · 305,5 · 335,5 · 484,8 · 574,5 s (intervalos 90/30/179/30/149/90 — "a cada ~30 s" só em parte; surgem em rajadas; sem snapshot 156–305).
* Resposta `3f 1a 13 …` (16 B) = ACK: `u16 1 | u16 2`.

### 3.5 Consulta de entidade `f0 15` (C→S 16 B → S→C 27 B)
```
C→S  3d 0a | 01 00 | <u16 idx>             (idx = um dos ids do snapshot; sempre PAR)
S→C  fd 0a | 02 00 02 00 00 00 | [ff 00] | 04 00 00 00 | <u32 unix_time_servidor>
```
Os 21 pedidos têm `idx` ∈ conjunto de ids dos snapshots (21/21) — são consultas por entidade do snapshot; ids pedidos: 8,440,462,412,436,470,6,428,444,408,414,466,464,446,438,460,452,8,426,440,462. A resposta só traz o relógio do servidor (o ACK; os dados por entidade chegam por outro canal ou não há).

### 3.6 Consulta de perfil `0c 08` (t=288) — 30 B req / 264 B resp
Resposta decodificada (strings UTF-8 com `u32 len`): `幸运就是我7945` (19 B), `YES`, `开心玩`, `zh_tw`, uid `0x02097768`, timestamps (`5b 46 ff 6a` → mesmo relógio), `ff ff ff ff`, vários `u32` de tamanho. É um **perfil de jogador** (nome, idioma, avatar…). Decodificado só até ~offset 230; o fim da resposta sai quebrado (outro token não localizado).

## 4. Correlações temporais
* `e0 9f` (22 cmds, t=302…397 s) × `dd/01` (22 pushes, atraso 0,2–0,6 s): 1:1 como já sabido; **não** há 3d/03 pareado a cada e09f: os 17 `f0 15` de 351–382 s caem dentro da janela e09f (350–386), mas são 17 vs 11 (e09f naquela janela) ⇒ correlação **de janela, não 1:1**. O burst de 4 `f0 15` em 590–595 ocorre sem nenhum e09f (acabaram em 397) ⇒ consulta de entidade é independente do comando de combate (provável: UI abrindo a lista de heróis/entidades).
* Os snapshots 2462 B não correlacionam com e09f (305 e 335 s ficam no começo da janela e o 484 s depois; o estado mudou entre 335→485).

## 5. Validação (≥3 invariantes — atendido; re-encode 100%)
Rodar `python validate.py`:
1. **Re-encode**: 58/58 frames kind 03 reproduzidos byte a byte (7 snapshots, 50 pequenos, 1 de 264 B). Ressalva honesta: nos pequenos/264 o "re-encode" é só XOR inverso + tokens (decodificação sem schema, quase circular); nos snapshots é re-encode **de campos tipados** (ver/declen/cnt/registros/doubles) — esse é o teste forte.
2. `declen + 12 == len(corpo após prefixo de 4B)` em 7/7 snapshots (2436+12=2448).
3. `reclen == 78 × nº de registros` e nº = 31, e **cada** registro tem `u32=74`, `type=6`, 5 × (`u32=8`+f64) — 217 sub-campos `len==8` confirmados em 7×31 registros (decoder levanta erro de sync se falha; 0 erros).
4. `idx` sempre par, mesma lista/ordem nos 7 snapshots; todos os 21 pedidos `f0 15` referenciam `idx` válido e par.
5. Doubles ∈ [0,100] em todos os snapshots; unix time do servidor monotônico crescente, slope 1,003.
6. 264 B: strings UTF-8 válidas (`幸运就是我`), `u32 len` coerentes (0x13=19 ✓).

## 6. Pendente / dúvidas (stop honesta)
* **Tokens de 2 B** (`ff 00`, `ff 1d`, `fb 64`…): inserção em claro; regra de posição inferida só por caso (offset 6 nos pequenos, ~2044 no snapshot). Não sei se são terminadores/checksum/jitter. Decoder usa `expect()` com re-sync de 2 B nas fronteiras de registro — frágil fora desses casos.
* **Prefixo flags** (`3d/fd/3f/ff ff`) e o id `1a 13` / `0a` / `20`: semântica de bits.
* **Origem da chave** `b9 24 5f bd` (derivada da sessão? do token de login 55/02? constante do cliente?) — em cap115 era `ef ba be b9`. Sem handshake nesta captura (mid-session), não dá para derivar aqui.
* Significado dos 5 medidores e dos `idx` (31 entidades; 4–14 vs 408–478: dois grupos? provavelmente slots/heróis/tropas); campo `0x0123173b`; `cnt=2`.
* Corpo restante do perfil (264 B) além do offset ~230 e o pedido de perfil de 30 B (`05 00 00 00 04 68 77 09 5e e0` → provável `u32 len5 | u8 04 | u32 uid`+ trailer).
* Provável que os "bytes de controle" intercalados nos canais msgpack (`ff 00`, `fd 20`, `3f`, `1f`…) sejam **o mesmo mecanismo** (tokens `flag,nn` em claro) — hipótese não testada, vale testar remover tokens + XOR nos outros canais.
* Só 1 conexão/captura; 58 frames kind 03; generalização para outras versões não testada.

## 7. Uso
```
cd C:/Users/prs/work/kind03
python ex.py          # frames.pkl (lê cap_combat2.pcap via parse.py do capture-combat)
python kind03dec.py   # decodifica todos os frames kind 03
python validate.py    # re-encode + invariantes
```
