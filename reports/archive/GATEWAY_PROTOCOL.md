# Protocolo Gateway — com.run.tower.defense porta 30101

Análise baseada em 2 sessões TCP capturadas (360 pacotes, ~118KB de payload).

---

## Framing

```
[ uint16_BE : length ][ body : length bytes ]
```

Cada mensagem começa com 2 bytes big-endian que indicam o tamanho do corpo.
Exemplo: `00 cc` = 204 bytes de body + 2B de header = 206B no fio.

Mensagens grandes fragmentam em segmentos TCP de 1400B (MTU); a montagem
é responsabilidade do receptor — o length header abrange o frame completo.

---

## Header de Mensagem

Primeiros 2 bytes do `body` são o header da mensagem:

```
byte[0] = tipo / opcode
byte[1] = direção  (0x01 = S->C,  0x02 = C->S)
```

Os bytes seguintes são o payload específico do tipo.

### Tipos identificados

| Opcode | Hex | Direção | Descrição |
|--------|-----|---------|-----------|
| `0x55` | 85 | ambos  | Handshake / sessão |
| `0x5d` | 93 | C->S (02) / S->C (01) | Mensagens de jogo |
| `0x1d` | 29 | S->C dominante | Estado / eventos de batalha |
| `0x15` | 21 | ambos  | Heartbeat / ping-pong |
| `0x59` | 89 | C->S   | Tipo específico (2 ocorrências) |
| `0x0d` | 13 | S->C   | Mensagem pequena (4B body, 2 ocorrências) |

---

## Fluxo de Sessão

```
C->S  [55 02]  204B  Handshake: versão, token, device, OS, kingdom
S->C  [55 02]   63B  Auth response: versão confirmada, parâmetros de sessão

S->C  [1d 01] 2714B  State sync: estado inicial completo da batalha
S->C  [1d 01]  ...   Eventos subsequentes (lote de ~20 mensagens em ~6ms)

C->S  [15 02]    4B  Heartbeat (a cada ~4s): `15 02 2c 06`
S->C  [15 01]   35B  Pong: `15 01 44 06 ...` (contém timestamps)

C->S  [5d 02] 1763B  Game update (estado C->S maior, ~1 por batalha)
S->C  [1d 01]  ...   Game events em resposta
```

---

## Handshake C->S (`55 02`, 204 bytes)

Contém em texto semi-legível dentro de codificação varint-like:

```
versao:    1.9.5
kingdom:   931
device:    motorola moto g(8)
plataforma: android
token1:    OEGFLbwPPabuxrSMmrqxyValDSbmQjLjOp8Ze3428BoU1rfR  (48B, base62?)
token2:    3846?01255  (ID de conta ou build)
hash1:     8c5b805
hash2:     1660a0e60b1b4a39716e02ba  (24 hex chars)
hash3:     25f42
hash4:     e1458e920db92bce7c199b3d  (24 hex chars)
locale:    pt
```

O token `OEGFLbwPP...` é o token de sessão/auth principal (varia entre conexões?).

---

## Heartbeat

```
C->S:  00 04  15 02 2c 06        (6B total, body=4B)
S->C:  00 23  15 01 44 06 04 02 84 04 ...   (37B total, body=35B com timestamps)
```

O heartbeat C->S incrementa um campo (o `2c`, `2e` nos frames subsequentes — parece ser um contador de sequência).

---

## Mensagens de Estado / Eventos (`0x1d` S->C)

São as mais frequentes (121+ frames por sessão). Contêm campo names em JSON/protobuf:

```
atk_uid, def_uid, atk_uids, def_uids
atk_nickName, def_nickName
atk_abbr, def_abbr
atk_kid, def_kid
battle_type
result
```

Também contêm nomes de recursos do jogo:
```
"int farm alliance call 931!"
"SpartansFarm"
"Bellona"
"teleport olal"
"c02-rtm-intl-frontgate.ilivedata.com"  ← servidor de live data
```

---

## Mensagens de Jogo (`0x5d`)

**C->S `5d 02`** (93 frames por sessão):
- Maioria são pequenas (5-9B): posição ou ação do jogador
- Uma mensagem grande (~1763B): sync completo de estado do cliente
- Contêm coordenadas, IDs de unidades, ações

Padrão repetitivo nos frames C->S pequenos:
```
5d 02 f0 15 [seq_byte] 01 03 [valor]
```
→ possivelmente atualizações de posição de unidades com ID+valor

---

## Encoding interno

O payload das mensagens usa um encoding similar a protobuf (varint), mas
o framing externo é proprietário. Não é protobuf padrão puro.

Evidências:
- Campos com comprimento prefixado (bytes `fc`, `ff`) antes de strings
- Varints de tamanho variável (1-4 bytes)
- Ausência de delimitadores de campo fixos

---

## Observações de Segurança

| Item | Status |
|------|--------|
| TLS / criptografia | Não — protocolo binário em plaintext |
| Tokens de auth | Presentes no handshake — não replayáveis sem análise |
| Certificate pinning | Irrelevante (porta 30101 não é HTTPS) |
| Validação server-side | Desconhecida — não testada |

---

## Próximos Passos

1. **Replay de handshake**: capturar token e tentar conectar manualmente com Python
2. **Identificar codificação dos campos**: comparar frames com o dump do IL2CPP (strings em `libil2cpp.so`)
3. **Mapear opcodes no Ghidra**: buscar `0x551d` / `0x5d02` / `0x1d01` como constantes em `libil2cpp.so`
4. **Decodificar heartbeat counter**: confirmar se `2c`, `2e`, `30` são seq_num incrementais
