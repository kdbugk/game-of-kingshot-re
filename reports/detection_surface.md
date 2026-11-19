# Lane U (interim) — Superfície de detecção anti-análise (1.14.27)

*Varredura string-nível nos binários limpos; decompile dos hits = próximo passo.*

## Resultado da varredura

| Binário | Achados | Leitura |
|---|---|---|
| **libunity (desempacotado)** | `TracerPid` ×1, `/proc/self/status` ×1, `/proc/self/maps` ×1, `status` ×9 | **a tríade anti-debug clássica** — detecção de ptrace/frida mora aqui (parcialmente) |
| libil2cpp_full | `/proc/self/maps` ×2, `/data/local/tmp` ×1, **`frida` ×1**, `status` ×5 | referência direta a frida — ver contexto |
| libNetHTProtect | `/proc/self/maps` ×1 | checagem de mapa |
| libxt 3.1.2 | `/proc/self/maps` ×2 | o SDK de PLT-hook também escaneia maps |
| libnesec | **PACKED** (`.gnu.fragment` 864K ent 8.00, stub 72K, packer versão diferente: 3 ctors em 0xed534/0xed5e4/0xedd38; CRYPT fuzzy 37/64 vs unity) | desempacotar = próxima sessão (análise própria dos ctors) |
| libsigner | (arquivo fora do path esperado — re-extrair) | pendente |

## Interpretação do quadro geral

- A detecção que derruba o jogo no attach do frida provavelmente combina: **TracerPid check (libunity) + port/maps scan** — o `exit(0)` limpo casa com uma terminação deliberada, não crash.
- O libnesec (o killer de 58s de abril) segue packed — os dois sites conhecidos de abril (`0x3a6168` kill, `0x0f54c` detection) são offsets do runtime desempacotado; para a 1.14.27 precisamos desempacotar primeiro.

## Próximos passos (T+U consolidados)

1. Desempacotar libnesec: decompilar os 3 ctors (Ghidra), achar driver/CRYPT próprios, adaptar emulador
2. Decompile em volta de: `TracerPid` no unity_image, `frida` no libil2cpp_full — documentar a lógica do check
3. Com o nesec aberto: mapa completo de terminação (lane T) vs os 2 sites de abril
4. libsigner: re-extrair e escanear
