# BLOCK0-K — Gen, continuação (RELATORIO_GEN2)

## TL;DR
**Bloco 0 dos bundles DECIFRADO: 119/119 (100%) dos bundles do corpus (60 da 1.9.5 + 59 da 1.14.27) viram LZ4 válido (tamanho usz exato) e o SerializedFile v22 decodificado traz a string `2022.3.62f1` em 119/119.** Controle (stream sem decifrar): 0/119 decompressam.
Não existe "gerador de 4096 B" separado: **o próprio `F_01412580` (vaddr 0x1412580) é o decifrador do bloco 0** — a keystream é derivada dentro dele a partir de bytes do próprio stream (nenhum segredo externo/por-bundle).
Método: emulação direta da função real com unicorn (`gen/emu_blk.py`). Port em Python puro ainda NÃO feito (parte do corpo >0xA0 cai em jump table que o Ghidra não decompilou) — ver next-steps.

## Convenção de endereços (corrigida de novo — importante)
- `F_01412580`/`F_01444a50` dos `gen/dec2/*.c` usam **vaddr do .so** (não +0x100000). file = vaddr − 0x13e0000 + 0x1288000 para vaddr ≥ 0x13e0000 (seg2 do ELF: off 0x1288000 → va 0x13e0000). Ex.: movk `#0x82d6,lsl16` em file 0x12ba99c = va 0x141299c, dentro de F_1412580. POLY em va 0x13ee328 (file 0x1296328).
- No projeto Ghidra `unity` (+0x100000) o endereço 0x1512580 é OUTRA coisa (stub de stack-check); 0x1412580 e 0x1447040 "FAILED" lá. Os dec2 vieram do projeto `img`. Não re-decompilar via `unity`+0x152580 (o endereço do enunciado não existe: é 0x1412580 vaddr). Re-decompile novo não foi necessário — o dec2 já é a função completa (946 linhas); só o miolo de jump table (br em 0x14131bc, tabela 0x14131c0) ficou ilegível.

## 1. Análise do "validador" F_01412580 (na verdade: sniffer + decifrador de header/bloco 0)
Assinatura: `ulong f(byte* buf, ulong size)`, size>=0x30, cap 0x1000. Retorna o comprimento processado (0x1000 ou o csz se menor: 1418, 2153…). Modifica o buffer in-place.

Fase A — detecção de formato (as "3 rotas de magic"):
- `*(i32*)buf` ∈ {0xA6A6A6FB (−0x59595905), 0xA6A9A6A6, 0xA6B7A6A6, 0xAEA6A6FB} (e o mesmo em offsets +1..+11): rotas LAB_0141287c/01412900/01412910 = **apenas varrem o buffer atrás da string literal "UnityFS"** (posição → comprimento a decifrar, uVar60/uVar49); sem "UnityFS": comprimento = size. Não decifram nada nessas rotas; só definem (offset do header, tamanho) e caem na Fase B (LAB_01412920).
- Rota principal p/ bundle (a do corpus): varre os primeiros 0x48 bytes por `EE DD <u16>` com u16 ∈ {0x6000,0x7000,0x8000,0x9000, 0x2017-0x2019, 0x2020-0x2028} (o `ee dd 22 20` do LaneC). Reescreve a string de versão (`22 20`→"2022", `.`, `3`, `.`, `62`, `f`, `1` — daí `2022.3.62f1` aparecer), extrai o comprimento do trecho cifrado de (XX<<4)+YY (nibbles `csz>>4`,`csz&0xF`; `aa/bb` ⇒ 0x1000) e o deslocamento do header (byte ZZ + 0xB; 0x30/0x40 mínimo) ⇒ `p0` 43..50 do LaneC. Também existe rota "HTP8" (`'HTP'+'8'` → patch 0x5d + XOR 0x5959… de 7 qwords) para outro formato.

Fase B — decifração (LAB_01412920), `hdr = buf+offset`, `L` = comprimento (≤0x1000):
1. `w0..w4` = 20 bytes LE em `hdr+0..0x13`. **K = CRC32-variante sobre (w3, w1, w4, L, w2)** (4 bytes LE cada, nessa ordem): init 0xFFFFFFFF, tabela poly 0x04C11EB7 reflexa, passo `crc=(T[(crc^b)&0xFF]^(crc>>8))+0x10`, final `K = 0x82D63B78 + ~crc` — **idêntico ao `key_from_len` do htpx_decrypt.py**, só muda a entrada.
2. K9/words auxiliares: `(u32@hdr+0x14 + 0x1985)^K`, `K^(L+0x2013)`, `(u32@hdr+0x1c+0x1981)^K`, `(u32@hdr+0x18 + 0x2018)^K`.
3. `hdr[0:32] ^= 0xA6` (o "XOR 0xA6" constante do LaneC achado #3).
4. RC4 (S0 = identidade; tabela em 0x13eb520.. confere: são 16 blocos identidade 00..ff), chave = K (4 bytes LE), saída `ror8(k,2)+0x3a` XOR dado (mesmo `rc4_stream` do HTPX). Se L<0xA0: decifra `L−0x20` bytes a partir de `hdr+0x20` com essa keystream. Se L≥0xA0: decifra 0x80 bytes (header H) e o resto vai para o laço em blocos de 0x80 com classes (A–D, índice `words[i&3] % 9`, 9 words) — mesma família do `block_ks` do HTPX (jump table, não portado).
- Não é validação: nunca recusa nada; magic errado só sai sem alterar (retorna 0).

## 2. Caça ao gerador 4096 B (resultado)
- Não há gerador separado de 4096. A "janela 4096" = `if (0xfff < size) size = 0x1000` no início do F_01412580. Alocações 0x400 vistas = tabela CRC; nenhuma alloc 0x1000 necessária.
- Constante 0x82D63B78: 13 `movk #0x82d6,lsl16` no .so (file 0x12ba99c, 0x12bbf50, 0x12bc6c0, 0x12eca58, 0x12eceac, 0x12ed328, 0x12ed4d4, 0x12ee3c4, 0x12ef10c, 0x12ef9c0, 0x12f02a0, 0x12f0aa4, 0x12f3228) ⇒ 13 variantes da família CRC/RC4 na região (candidatas para outros formatos: HTPX meta=0x1447040, crypt de bundle 0x1444a50 etc.). Só a de 0x12ba99c (=F_1412580) foi usada aqui.
- Callers (scan de BL/B em todo o .so mapeado): `F_01412580` ← só recursão em 0x14138b8; `F_01444a50` ← `0x8ae758` (seg1); `F_01447040` e `F_014479b8` ← nenhum direto (chamados por ponteiro/vtable). Quem chama F_01412580 em runtime é indireto (provável ponteiro em tabela) — não resolvido.

## 3. Reprodução e validação
- `gen/emu_blk.py`: carrega segmentos do libunity_114.so em unicorn (WSL `kingshot-re`), stubs: vtable+0x160 (alloc), +0x188 (memcpy), strlen/malloc/memcpy/free, `tpidr_el0`; chama `0x1412580(buf, min(csz,0x1000))` e devolve o buffer decifrado. Cada chamada ≈ ms.
- `gen/val_blk.py` (corpus `/tmp/b0.pkl` do laneC/collect.py, 119 bundles; 106 com ret=0x1000, 13 com csz<4096 ret=csz):
  - LZ4 válido com usz exato após decifrar: **119/119 (100%)** (critério ≥95% ✔; "UnityFS pós-LZ4" não se aplica ao bloco 0 — o plaintext é SerializedFile, validado por versão `2022.3.62f1` em 119/119 e prólogo `00*11 16` v22 correto).
  - Controle sem decifrar: 0/119.
  - Observação: cache_crypt_payload.bin (68 MB) NÃO foi testado — fora do escopo do corpus de bundles.

## Candidatos / evidência
| vaddr | papel | evidência |
|---|---|---|
| 0x1412580 | decifrador bloco 0 de bundle (CRC→RC4→classes) | 119/119 |
| 0x1444a50 | crypt de bundle (magics HTPX/0xFAB11BAF), caller 0x8ae758 | dec2 |
| 0x1447040 | HTPX metadata (global-metadata) | laneL |
| 13 movk 0x82d6 acima | outras variantes da família | scan estático |

## Next-steps honestos
1. **Port Python puro** (sem unicorn): fase A (offset/L) + K (CRC) + RC4 já estão claros; falta o laço de blocos 0x80 (L≥0xA0, jump table em 0x14131c0 e fallback `%9`). Obter via `capstone` o trecho 0x14131bc..0x1413300 ou rodar o emulador com hooks para extrair `K9/T4` e comparar com `block_ks` de htpx_decrypt.py (constantes diferentes: 0x1985/0x2013/0x1981/0x2018). Atenção: bundles com csz>0x1000 só têm os 4096 primeiros cifrados.
2. Para uso prático (extrair assets) o emulador já basta: decifra os 4096 B → LZ4 do bloco 0 → montar nós/CAB; blocos 1..n não são cifrados (LaneC #5).
3. Resolver o caller indireto de F_01412580 (ponteiro em tabela) para confirmar parâmetros (size = min(csz,0x1000) assumido e validado empiricamente).
4. Rodar todo game_asset.apk (não só 119 amostras) e o cache_crypt_payload.

## Arquivos
`gen/emu_blk.py`, `gen/val_blk.py`, `gen/findmov.py`, `gen/dec3/` (dumps vazios/inúteis do projeto errado — ignorar), `dumpv.cmd/log`.
