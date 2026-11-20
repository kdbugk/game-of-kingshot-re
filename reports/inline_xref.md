# INLINE-XREF — Chamadas no-PLT de imports terminais nos libs pequenos

**Lane coberta pelo pai** (safeguard, task-4). Scanner: `inline_scan.py`
(ADRP+LDR(+ADD)+BLR contra GOTs de exit/_exit/abort/kill/pthread_kill/raise/tgkill).

## Resultado: 0 sites nos 4 alvos

| Binário | GOTs-alvo | Sites no-PLT |
|---|---|---|
| libNetHTProtect.so (config.apk) | presentes | **0** |
| libNetHTProtect_114.so | presentes | **0** |
| libtolua.so | presentes | **0** |
| libhtpcrash.so | presentes | **0** |

## Interpretação (honesto)

1. Os imports existem (o linker os resolve) mas **não há call sites no padrão
   ADRP+LDR+BLR** — ou são imports mortos (comum em libs de proteção que declaram
   API "por garantia"), ou usam variante não coberta (registrador intermediário,
   carga via GOT absolute relocations + BLR com reg diferente do ADRP, ou chamada
   via função helper exportada).
2. Conclusão prática para TERMO-MAP: a superfície de terminação destes libs é
   nula/inacessível por padrão direto — **toda a terminação relevante continua no
   libnesec** (cadeia mapeada em nes-static/RELATORIO.md).
3. libnesec-x86.so ficou de fora (arquitetura diferente; se necessário, scan
   específico com padrão RIP-relative).

## Artefatos

- `inline_scan.py` (reutilizável; args = caminhos dos ELFs)
- Próximo passo se necessário: xref no Ghidra (importar libNetHTProtect, criar
  funções, getReferencesTo no símbolo externo) — só se algum dia importar.
