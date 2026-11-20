# NES-FOLLOW — Fechamento da cadeia decisão→saída (sessão 20/11 manhã)

**Lane coberta pelo pai** (safeguard derrubou a task-3 no 1º turno). Decompile novo:
`nes-static/decomp/F_a08f4.c` (29 KB) + scans BL/STR.

## Veredito — FUN_000a08f4 (29 KB)

Agregador em cascata de checks (via FUN_000cbbcc) que **classifica o ambiente em níveis**:

```
DAT_000e38f8 = 3  |  DAT_000e38f8 = 4  |  (via FUN_000cc6a4 = o parse de valor)
DAT_000e38f8 = 2  |  DAT_000e38f8 = 1  |  ... cascatas aninhadas
gate: DAT_000e48a0._1_1_ != 0 (flag master)
```

`DAT_000e38f8` = **o detection-level runtime** (equivalente ao `0x0f54c` de abril, que era
"level"; aqui 1-4). É o número que a função de saída (0xcb004 → syscall 94, status
0/1/2) e a telemetria reportam. A gradação explica por que às vezes o jogo só "estracha"
telemetria e às vezes sai: nível ≥ threshold = saída.

## Lacunas honestas (o que NÃO fechou)

1. **Chamadores do orquestrador 0xa2fa0: 0 via BL** — chamada indireta (fn-ptr/thread),
   consistente com o padrão pthread do stub (F_1f1f08 registra entry e dispara). Para achar
   quem registra: caçar ponteiros-para-0xa2fa0 em .data/bss da imagem + no stub emulado.
2. **DAT_000dd740 (alvo do dispatch 0xd3c90): vive em .bss** (0xdd740 > filesz 0xd8000,
   dentro do gap NOBITS até 0xec000) — preenchido em runtime; não há STR estático.
   Caminho: rodar o emulador (emu_unpack_nesec.py) até o pós-init e dumpar o .bss.
3. fnstart(0xd2f24) não achou prólogo em ±4 KB — site de maps-user sem função delimitada
   (provavelmente mid-function ou thunk); fica pendente.

## Cadeia consolidada (estado do conhecimento)

```
[trigger indireto: fn-ptr/thread] → 0xa2fa0 (orquestrador, policy 0x1d8B)
    → módulos de detecção (TracerPid por thread 0x8b494, /proc readers, SDK monitor)
    → 0xa08f4 (veredito: DAT_000e38f8 = nível 1..4)
    → se nível >= gate: 0xcb004 (probe kill(pid,0) + exit_group(0|1|2))
                        ou 0xd3c90 (dispatch jumptable .bss — abort duro)
canary de stack em cada nível → 0xd3c90 em caso de violação
```

## Artefatos

- `nes-static/decomp/F_a08f4.c` (veredito completo, 29 KB)
- Scans: neste relatório (BL/STR) — scripts em nes-static/xref.py (modelo)
