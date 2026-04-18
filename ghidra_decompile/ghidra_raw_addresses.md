# Ghidra Raw Addresses — libil2cpp `output_dump.bin`

## Bases corretas

```text
Runtime base (Frida):                 0x71e63ca000
Delta do import raw antigo no Ghidra: 0x2530
Ghidra raw base ajustada:             0x71e63c7ad0
```

## Regra

Para um reimport correto de `output_dump.bin` no Ghidra como `Raw Binary`:

```text
VA_ghidra_raw = 0x71e63c7ad0 + RVA
```

Se voce carregar com essa base, o endereco calculado abaixo deve cair no ponto certo sem precisar somar `0x2530` manualmente.

## Funcoes para teste

| Funcao | RVA | VA ghidra raw |
|--------|-----|---------------|
| `NetSecProtect.safeCommToServerV30` | `0x19e6324` | `0x71e7daddf4` |
| `GameMainLoop.GetBattleResult` | `0x2407d0c` | `0x71e87cf7dc` |
| `CheckGameEndSystem.Execute` | `0x24a3aa0` | `0x71e886b570` |
| `BattleLog.Save` | `0x1a286cc` | `0x71e7df019c` |

## Endereco para validar agora

Use este primeiro:

```text
NetSecProtect.safeCommToServerV30
RVA:            0x19e6324
VA ghidra raw:  0x71e7daddf4
```

## Como testar no Ghidra

1. Importe `output_dump.bin` como `Raw Binary`
2. Language: `AARCH64 v8A 64 little default`
3. Base Address: `0x71e63c7ad0`
4. Va para `0x71e7daddf4`

Se isso bater, a conversao correta passa a ser sempre `base_ajustada + RVA`.

## Observacao

O projeto antigo do Ghidra carregado com base `0x71e63ca000` continua deslocado em `+0x2530`.
Nesse projeto antigo, a mesma funcao apareceria em:

```text
0x71e7db0324
```

ou seja:

```text
VA_projeto_antigo = VA_ghidra_raw + 0x2530
```
