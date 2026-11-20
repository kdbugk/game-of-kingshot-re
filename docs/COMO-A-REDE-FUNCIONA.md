# Como a rede funciona — o protocolo do gateway (5 min)

> TL;DR: TCP bruto com moldura `uint16` + **sproto (skynet) com 0-pack**. Login entrega uma
> `secret_key` EM CLARO que vira XOR de 4 bytes nos corpos grandes. Cada pedido tem
> `session` sequencial; a resposta ecoa. Pushes chegam sozinhos (`notify_*`).

## 1. A moldura (o envelope)

```
[TCP] [uint16_BE: tamanho] [frame sproto]
```
Simples, sem mágica. 1.771 frames analisados, zero erros de enquadramento.

## 2. O sproto por dentro (a carta)

sproto é o formato do ecossistema **skynet** (servidor de jogos chinês famoso). Cada frame:

```
header: { msgId (qual mensagem), session (nº sequencial do pedido), ud (extra) }
corpo:  struct tipada pelo schema (.sproto)
```

O tal "0-pack": os primeiros bytes são **bitmaps** dizendo quais grupos de 8 bytes têm
campos — por isso os primeiros bytes "pareciam opcodes" (era o bitmap!) e mudavam sozinhos.

**O pareamento**: cliente manda session=1, 2, 3...; a resposta volta com o MESMO session.
É assim que se casa pedido↔resposta num canal com pushes no meio.
*(é o que o cmd_console.py faz: scripts/cmd_console.py mock list)*

## 3. O ciclo de uma sessão

```
1. loginauth  ──►  {code, uid, serverid, secret_key}     ← A CHAVE VEM AQUI, EM CLARO
2. req_loaddata ──►  ~176 pushes notify_* (seu mundo)
3. loop: req_heartbeat (4s) + ações req_* ↔ respostas + pushes
```

## 4. As camadas de "segredo" (e por que são ofuscação, não sigilo)

| Camada | O que é | Quem resolve |
|---|---|---|
| `secret_key` (login) | chave XOR de 4 bytes, repetida, nos corpos grandes | entregue na própria resposta |
| `crypt_method` | 1=XOR, 2=RC4 — escolhido no login | idem |
| Bloco 0 dos bundles | CRC→RC4-mod→classes XOR (nos ARQUIVOS, não na rede) | reproduzido offline 119/119 |

Ou seja: na rede, quem ouve o login ouve a chave. É anti-script-kiddie, não criptografia.
*(detalhes: reports/spec_server.md §1, luapkg.md, block0k_decoded.md)*

## 5. O catálogo (o dicionário da língua)

- `protocols/game_proto_c2s.sproto` — 1.888 pedidos, com comentários dos devs
- `protocols/game_proto_s2c.sproto` — 1.005 notificações
- `protocols/catalog.json` — 58 com payload real capturado
- `protocols/errcodes.json` — 3.045 códigos de erro (ex.: 16807 = fase já passada)

## Onde se aprofundar
- Descoberta do sproto (corrige a leitura antiga de "opcode+kind"): `reports/spec_server.md`
- Decoder byte-exato: `protocols/sproto_py.py` + `sproto_lib.py` (312/312)
- Mensagens decodificadas ao vivo: `reports/spec_blueprint.md`, `kind03_codec.md`
