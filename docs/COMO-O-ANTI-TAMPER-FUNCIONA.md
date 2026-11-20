# Como o anti-tamper funciona — a defesa do cliente (5 min)

> TL;DR: o jogo vem **empacotado** (código nativo cifrado que se auto-decifra na memória ao
> iniciar), e carrega um **motor de vigilância** (libnesec) que observa o processo: debugger
> attachado, emulador, root. Um veredito em **níveis 1-4** decide entre "só telemetria" e
> `exit_group(0)` — o fechamento limpo que você viu.

## 1. O packer (a caixa-forte)

Duas variantes da mesma família (HTProtect):
- **libunity/libil2cpp**: a maior — payload cifrado (`.gnu.fragment`), um *stub* visível
  que roda na inicialização, decifra a imagem na memória e executa
- **libnesec**: a menor — mesmo esquema com algoritmo mais simples (XOR de byte único +
  `mprotect`)

Ambas reproduzidas offline com emulador (Unicorn): `scripts/analysis/emu_unpack_nesec.py`.
*(detalhes: reports/nesec_unpack.md)*

## 2. A cadeia de boot (3 construtores)

```
init_array: [ctor0: autoexame do ambiente] → [ctor1: decifra tabelas + stage-2]
            → [ctor2: localiza o próprio arquivo, monta o contexto]
```
Detalhe curioso: os construtores têm "checks de integridade" espalhados que são
**predicados opacos** — funções vazias e `(a%4096)²`. Teatro de confusão.
*(detalhes: reports/nesec_unpack.md, detect_logic.md)*

## 3. O motor de vigilância (o que o payload faz)

Depois de decifrado, o libnesec vira um **grador de risco**:

| Vigia | Como |
|---|---|
| Debugger | lê `/proc/<pid>/task/<tid>/status` **de cada thread**, procura `TracerPid:` |
| Emulador | strings de VMs (vbox, nox, goldfish, qemu, genymotion...) |
| Root | `su`, magisk, paths de binário |
| Integridade | canaries de stack em cada nível da cadeia de decisão |

O **orquestrador** (0xa2fa0) lê uma *policy* de config (flags: `+0xb5`=sair, `+0xb1`=vigiar
SDKs parceiros...) e chama módulos; o **veredito** (0xa08f4) escreve o nível 1-4 num global;
se passa do limite: `exit_group(0)` — limpo, sem crash, sem mensagem. E há uma saída
" dura" (jumptable em .bss) para canary violado.
*(detalhes: reports/detect_logic.md, nes_static.md, nes_follow.md)*

## 4. O que ele NÃO é

- Não é anti-`tcpdump`: **captura passiva de rede é invisível** pra ele (provado 2×)
- Não é infalível: desempacota offline, a policy é mutável em .data, e as strings de
  detecção estão em XOR fraco (&0x7f)

## 5. Contraponto interessante

O próprio jogo **reescreve `TracerPid: 0`** em buffers de status que ele mesmo lê (spoof
interno) — a técnica que um atacante usaria, usada pela defesa pra proteger os SDKs
parceiros (libsgmain/Alibaba).

## Onde se aprofundar
- Desempacotamento + emulador: `reports/nesec_unpack.md`, `nes_emu2.md`
- Motor por dentro (endereços e snippets): `reports/detect_logic.md`, `nes_static.md`
- Histórico da caçada (era frida): `reports/archive/`
