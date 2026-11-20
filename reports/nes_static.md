# NES-STATIC — Análise estática do payload desempacotado do libnesec (1.14.27)

**Lane coberta pelo pai** (safeguard derrubou a task-1 no 1º turno). Ghidra raw import
(`ghidra_nesimg/nimg`, base 0) + scans capstone. Decompile: `decomp/` (18 funções).

## Mapa das funções-chave

| Função | Papel |
|---|---|
| **0xa2fa0** | **ORQUESTRADOR** do motor de detecção |
| 0xa6f14 | singleton de CONFIG (0x1d8 B, vtables em 0xdcd88/0xdce38, global em 0xe37c8) |
| 0xa07f8 | gate inicial (bit 0 habilita o motor) |
| **0x8b494** | **CHECK TracerPid real** (por thread!) |
| 0x8a6c0 | spoof: reescreve "TracerPid:\t0" em buffers de status |
| 0x8afcc | montador da lista de SDKs parceiros |
| 0xca894 | loop de módulos + telemetria (12 KB) |
| 0xcb004 | saída via syscall 94 (status 0/1/2) + probe kill(pid,0) |
| **0xd3c90** | terminador "does not return" (dispatch via jumptable DAT_0dd740) |

## O check TracerPid (0x8b494)

```
para cada thread (loop /proc/%d/task/%d/status — fmt @0x121e1):
    lê status (fgets via vtable)
    procura "State:" (@0x11b4f) depois "TracerPid:" (@0x11600)
    se acha TracerPid → parse do valor (0xcc6a4 → 0x7e4a4 compara)
canary de stack: se extraout_x8_00 != local_68 → thunk_0xd3c90 (não retorna!)
reporta resultado: 0xcb770(bVar4)
```

**Decisão por thread, não só do processo** — attach em qualquer thread é detectado.

## O orquestrador (0xa2fa0)

```
cfg = FUN_000a6f14()  (flags byte a byte na struct de 0x1d8)
se cfg[0xb5]&1: FUN_000cb004()            ← SAÍDA DIRETA (exit_group 0/1/2)
FUN_000ca894(cfg[0xca])                   ← loop módulos + telemetria
se cfg[0xff]&1: ... FUN_000af334(param,5) ← módulo de detecção "5"
se cfg[0xce]&1: ... FUN_00090a6c(...)
se cfg[0xb1]&1 && !FUN_000b3408(): FUN_0008afcc(cfg, …)  ← monitor SDKs
se cfg[0xb2]&1: 0x8a3f4(...)
bVar2 = FUN_000a08f4(...)                  ← veredito final
se !(bVar2&1): FUN_0009c7c0(&DAT_0e4850); thunk_0xd3c90()  ← SAÍDA DURA
```

As flags +0xb5 (exit), +0xb1 (SDK monitor), +0xb2, +0xce, +0xd1, +0xd2, +0xdc, +0xe5,
+0xff, +0x110 formam a **POLICY** — alimentada pelo stub (o ctor0 do stub grava
nível 4 no global 0x2020e0) e/ou pelo servidor.

## Lista de SDKs (deobfuscada em runtime — loop XOR &0x7f @0x8b008)

`libalicomphonenumberauthsdk,libsgmain,libBaiduMapSDK_map`
(tabela @0x18d6c, 57 B; máscara-8 em 0x1400c) — módulos parceiros vigidos pelo
motor (libsgmain = Alibaba SecurityGuard).

## Coletores /proc (contexto)

- /proc/self/status: reader @0xb2dc8 (ref @0xb31bc)
- /proc/self/task: @0x8f0d0 (ref @0x8f42c)
- /proc/self/maps: 4 usuários — 0xa68fc, 0xad66c, 0xb07dc (+1 sem função delimitada @0xd2f24)
- syscall wrappers: 19 em 0x2d4e8–0x2d698 (exit_group@0x2d530, kill@0x2d590 sem caller BL — indireto)

## Cadeia de terminação (consolidada)

```
boot stub (3 ctors) → payload decriptado
motor: 0xa2fa0 (policy cfg) ─┬─ flag 0xb5 → 0xcb004 → syscall 94 (0/1/2)  [exit "limpo"]
                              ├─ veredito !ok → 0xd3c90 (jumptable runtime) [abort duro]
                              └─ canary de stack violado (0x8b494, 0xca894) → 0xd3c90
```

**Candidato #1 ao exit(0) limpo ao attach**: path flag-0xb5 → 0xcb004 (status 0),
gatilho = TracerPid != 0 detectado por 0x8b494 (por thread).

## Próximos passos

1. Decompile de 0xa08f4 (veredito) e dos módulos 0x8f0d0/0xb2dc8 completos.
2. Onde DAT_0dd740 (jumptable do 0xd3c90) é preenchido → mapa dos handlers de término.
3. Origem da policy cfg (stub 0x2020e0? servidor? comparar byte a byte entre runs).
