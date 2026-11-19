# DETECT-LOGIC — Lógica de detecção (Kingshot 1.14.27)

**Lane coberta pelo pai** (safeguard). Conclusão por evidência + eliminação, com o payload
do libnesec DESempacotado (cortesia da lane NES-UNPACK desta sessão).

## Veredito

**Toda a detecção anti-debug/anti-frida/anti-emulador/anti-root vive no payload do
libnesec.so** (nesec_image.bin, fragment decriptado). Os indícios anteriores no
libunity/libil2cpp eram falsos positivos/legado:

1. **libil2cpp_114_full.so: a string 'frida' NÃO existe** — busca byte-a-byte case-insensitive
   retorna só `Friday` (dias da semana ×2 + wordlists HTML embutidas). O "frida ×1" da sessão
   anterior era substring de "Friday"/HTML. `/proc/self/maps` ×2 = 1 literal sem xref + 1 dentro
   de string do GC Boehm ("GC Warning: Unexpected asynchronous /proc/self/maps growth") — benigno.
   `/data/local/tmp` @0xc295c6 sem xref. Scan via Ghidra (defined strings): **0 funções referenciam**.
2. **unity_image.bin: strings TracerPid/status/maps SEM referência de código** — scan ADRP+ADD
   completo do arquivo (todas as combinações de página): nenhum ADD bate nos offsets das strings;
   14 sites ADRP na página = tabela de nomes de subsistemas Unity (interface lookup @0x1362460).
   Sem ponteiros absolutos 8-byte nem RVA 4-byte para elas. Legado morto do libunity.
3. **libnesec desempacotado: a superfície real** —
   - `TracerPid:` ×3 (0x10ec7, 0x11600, 0x11b42 — este último com `State:` ao lado = parser de
     /proc/self/status comparando os dois campos);
   - `/proc/self/status` @0x109b0, `/proc/self/maps` @0x129c3, `/proc/self/task` @0x131b7;
   - root: `magisk`, `/system/bin/su`, `/system/xbin/su`, `/vendor/xbin/su`, `su ` ×27, `/sbin/` ×3;
   - emulador: `vbox` ×23, `nox` ×6, `goldfish` ×4, `qemu` ×2, `ro.genym*` (genymotion), `bst` (BlueStacks),
     `/data/data/com.androVM.vmconfig`, `/data/data/com.microvirt.market`, `/system/lib/libnoxspeedup.so`, `com.gionee.`;
   - toolkit: `popen`, `readlinkat`, `unlinkat`, `execve`, `readlink`, `fopen` (syscall wrappers @0x2d4e8–0x2d698).
4. **Boot & stub**: o stub (`.gnu.draft`) tem o próprio check de ambiente no ctor0 (@0xed534):
   mmap RWX → varre /proc/self/maps → exige a região RWX com 'x' → detection-level global
   0x2020e0 = 4 (senão 0). O check de attach do debugger (exit(0) limpo) está no payload:
   cadeia `0xa3094 → 0xcb004 → exit_group(0)` (ver TERMO-MAP).
5. Anti-análise do stub: predicados opacos (F_1f7a04=a+b, F_1f7a14=a−b, F_1f7a24=(a%0x1000)²,
   F_1ef2f4=função vazia) — os "checks" intercalados nos ctors são no-ops de confusão.

## Fluxo detecção→terminação (estado atual)

```
boot → init_array[ctor0 self-check maps; ctor1 decripta tabelas+stage2; ctor2 self-locate+ctx]
     → payload (decriptado in-place, fragment 0–0xd8000)
     → coletores /proc (0xaf614–0xb2450): status→TracerPid!=0? maps→scan; task→threads
     → (gatilho) → 0xa3094 → 0xcb004: kill(pid,0) probe, detection-level, exit_group(0)
```

## Próximos passos

1. Decompile (Ghidra raw import de nesec_image.bin) das funções que referenciam 0x109b0/0x129c3/0x131b7
   e das strings de emulador — achar o branch exato `TracerPid != 0` e como chega ao exit.
2. Caller-tree de 0xa3094 (quem decide).
3. Confirmar se o token por-install (handshake) nutre a telemetria de detecção.
