# Lane F — Recuperação de keystream do bloco 0 (parcial, sessão 3)

## Método

Análise por moda/consenso sobre os 119 bundles coletados (`/tmp/b0.pkl`, schema do
`laneC/collect.py`): se o plaintext for zero-dominante numa posição, a moda dos
ciphers naquela posição aproxima a keystream.

## Resultados

1. **Confirmação do colapso em 81+**: concordância por posição cai de 0.47 (bytes 0-49) para 0.06 (bytes 81-130) — a keystream é efetivamente por-bundle a partir do byte ~81, corroborando a lane C.
2. **Moda dos ciphers [0..80]** = `16 00 01 00 16 16 0b 00 22 02 f1 08 ...` — o prólogo LZ4 mais comum + janela 0xA6 visível no fim.
3. **Par (4,6) idêntico**: dois bundles com ciphers IDÊNTICOS em todos os 300 bytes analisados (219/219 zeros no XOR) — mesma keystream E mesmo plaintext (duplicação de conteúdo, provável .32/.64 ou asset duplicado). Não revela a chave, mas confirma: mesma entrada → mesma saída (sem nonce aleatória).
4. **Keystream candidata global [81..131]** ( moda, fraca — concordância 6%): `a6263aa6de409e19ee17c28d29666ee9...` — contém bytes 0xA6 recorrentes; hipótese: extensão da janela 0xA6 com pequenas variações por posição, ou a moda está capturando lixo (veredicto: lixo, dado 0.06).

## Próximos passos (para a sessão seguinte)

- Derivar a chave por-bundle dos campos do header: `csz`, `usz`, hash do sufixo hex do nome do CAB, posição do bloco. Constraints firmes: `key[0..48]=0`, `key[49..80]=0xA6`.
- Usar pares same-typetree da lane C (3544/3744, 3676/4092) com plaintexts previstos pela estrutura do type tree compartilhado para recuperar keystreams completas e então inverter a derivação.
- Testar geradores: CRC32C (poly 0x1EDC6F41, init 0x8f6e37a0 — o mesmo do unpacker!), LCG, xorshift — semeados por cada campo candidato.
