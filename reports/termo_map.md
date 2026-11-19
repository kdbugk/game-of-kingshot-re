# TERMO-MAP — Mapa de terminação (Kingshot 1.14.27)

**Lane coberta pelo pai** (safeguard). Ferramenta: `termo_scan.py` (ELF: dynsym→GOT→PLT→BL;
raw: wrappers svc). Prioridade dada ao alvo #6 (libnesec desempacotado) por depender da lane 1.

## Resultado central — libnesec DESempacotado (nesec_image.bin)

19 wrappers de syscall (`mov x8,#nr; svc #0`) em 0x2d4e8–0x2d698. Terminação:

| Site | O quê | Wrapper | Chamadores (BL) |
|---|---|---|---|
| **0xcb098** | **exit_group(0) — o "exit limpo"** | exit_group(94)@0x2d530 | função @~0xcb004 |
| 0xcb070 | exit_group(1) | idem | idem |
| 0xcb0a0 | exit_group(2) | idem | idem |
| 0x2d590 | wrapper kill(129) | — sem BL direto (chamada **indireta**, via fn-ptr/vtable) | — |

**Cadeia de terminação**: `0xa3094 → função 0xcb004 → exit_group(0|1|2)`.
A função 0xcb004: probe `kill(pid,0)` via 0xced4c; se -1 → exit_group(1); confere pid via
0x7e2cc; grava detection-level antes (`w0=4` → slot via 0xd0ea4, `str w20`), tag 4 bytes,
depois exit_group(0). Bate com o comportamento observado (exit(0) limpo ao attach).

Ranqueio de candidatos ao exit(0) limpo:
1. **0xa3094→0xcb004→exit_group(0)** — confiança ALTA (assinatura probe+status 0).
2. kill(129)@0x2d590 via ponteiro — confiança MÉDIA (call site indireto, precisa decompile).
3. Coletores /proc (cluster 0xaf614–0xb2450: openat/read/readlink/close) — alimentam os checks;
   não terminam, mas são o gatilho upstream (TracerPid parser).

## Outros binários (scan padrão)

| Binário | Resultado |
|---|---|
| libil2cpp_114_full.so | **sem PT_DYNAMIC** (imagem reconstruída pela aplicação de RELA) → scan bruto: 0 wrappers svc. Terminação via imports no original packed — re-scan quando houver dump com dynamic. |
| libNetHTProtect_114.so / libNetHTProtect (config) | importa exit/kill (GOT existe) mas **sem PLT stub** — chamadas inline (no-PLT: adrp+ldr+blr). Precisa pass de xrefs Ghidra. |
| libxt3.1.2_a64.so | idem — GOT presente, chamadas inline. |
| libsigner.so | **nenhum** GOT de terminação (não importa exit/kill). |
| libnesec-x86.so / libtolua.so / libhtpcrash.so | GOT presente, sem PLT stub — inline (mesma pendência). |
| unity_image.bin (raw) | **0** wrappers svc de terminação; strings TracerPid/maps SEM xref de código (ADRP+ADD scan 14 sites = tabela de nomes de subsistemas Unity, não detecção). Legado morto. |

## Comparação com abril (1.9.5)

Abril: kill@0x3a6168 e detection-level@0x0f54c (offsets do nesec de abril).
Agora: 0x0f54c = zeros (`udf`) — layout mudou entre versões. Equivalentes novos:
exit_group@0x2d530 (caller 0xcb004), kill@0x2d590, detection via slot de 0xd0ea4.

## Próximos passos

1. Reimportar `nesec_image.bin` no Ghidra (raw, AARCH64, base 0) e decompilar 0xa3094, 0xcb004,
   cluster 0xaf6–0xb2d (coletores), e achar o dono do fn-ptr que usa kill@0x2d590.
2. Para os libs com chamadas inline-GOT: script xref (adrp+ldr+blr do GOT de exit/kill) no Ghidra.
3. Cross-check do byte de detection-level com o global 0x2020e0 do stub (ctor0).
