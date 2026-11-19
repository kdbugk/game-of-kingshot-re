# Lane L — Gerador do keystream HTPX (QUEBRADO, validado byte a byte nos 2 arquivos)

## TL;DR
- A decifragem do `global-metadata.dat` (HTPX) **não está no payload do libil2cpp**: está no **`libunity.so`** (loader de metadata), função em **vaddr 0x1447040** (sítios `mov #0x5448; movk #0x5850,lsl16` = "HTPX" em 0x1444a10/0x1444e64/0x1447088; irmã 0x1446e18 trata "HTPY"; 0x144792c trata magic `HNUP`). Achado por varredura estática do encoding da constante — sem precisar do emulador.
- Algoritmo completo reimplementado em `htpx_decrypt.py` e **reproduz exatamente os 1152 B** de `key1152_114.hex` e `key1152_195.hex` (9 blocos, inclusive a classe "D" que só aparece no 195). Também decifra o arquivo inteiro (cabeçalho + corpo + cauda).
- Saídas: `global-metadata_114_decrypted.dat` (12.492.132 B) e `global-metadata_195_decrypted.dat` (11.610.640 B), com `AF1BB1FA` + versão 24 nos 8 primeiros bytes. Cabeçalho il2cpp tem 31 pares (offset,size) = 0x100 B; as seções são contíguas e a última termina exatamente em `len(arquivo)` nos dois; string heap começa em `Assembly-CSharp\0Assembly-CSharp.dll\0<Module>`; cauda são ints plausíveis.
  - ⚠ A versão (dword em +4) é escrita pelo loader a partir de um campo de runtime (`*(global+0x70)`); coloquei 24 (v24 confirmado em outras lanes). Não vem do arquivo.
  - ⚠ `global_metadata_114_v24.dat`/`rebuilt*.dat` das lanes anteriores **não batem** com esta saída no cabeçalho (usam cabeçalho 0x110 reconstruído) nem na cauda de 92 B; o corpo no meio é idêntico (deslocado 8 B). Esta saída é a do próprio decryptor do jogo → preferir.

## Algoritmo (n = len(arquivo) − 8; raw = arquivo cifrado; tudo u32 LE, mod 2^32)
Constantes (libunity .rodata 0x13ee328 + imediato): `POLY=0x04C11EB7`, `P1=0x10`, `P2=0x82D63B78`. S-box inicial do RC4 = identidade (16 `q` loads de 0x13eb520.. formam 0..255 em ordem).

1. **Tabela CRC** T[256] reflexa com POLY (laço de 8 passos padrão).
2. **w26 = chave por tamanho** (só depende de n):
   ```
   w = (T[~n & 0xFF] ^ 0xFFFFFF) + P1
   w = (T[(w ^ (n>>8))  & 0xFF] ^ (w>>8)) + P1
   w = (T[(w ^ (n>>16)) & 0xFF] ^ (w>>8)) + P1
   w = (T[((w&0xFF) ^ (n>>24)) & 0xFF] ^ (w>>8)) + P1
   w26 = P2 + ~w
   ```
   (por isso as chaves são "por arquivo, disjuntas": dependem do tamanho.)
3. **RC4 modificado** (KSA com chave de 4 B little-endian, PRGA padrão; byte de saída = `(ror8(K,2) + 0x3A) & 0xFF`, K = S[(S[i]+S[j])&255]).
4. **H** (128 B) = raw[8:136] XOR RC4(chave = `u32(raw,0x20) ^ w26`). (cópia de trabalho do cabeçalho)
5. **Cabeçalho real**: `corpo[0:128] = raw[8:136] XOR RC4(chave = w26)` (é o cabeçalho il2cpp de 0x100 B incl. 8 B de sanity/versão que o loader escreve por cima do "HTPX"+len).
6. **Material de 9+4 palavras** (h(o)=u32(H,o); w8=u32(raw,0x20), w9=w8^w26):
   ```
   t13 = (u32(raw,0x54)+0x75568)   ^ w9
   t14 = (h(0x3C)+0xA7498D)        ^ w9
   t15 = (h(0x2C)+0x3482A5)        ^ w26
   t12 = (u32(raw,0x28)+0x8195E)   ^ w26
   T4  = [t12, t13, t15, t14]                      # T4[0..3]
   a   = t14 ^ 0x0034E00E ; w17 = h(0x0C) ^ 0x03914F13 ; b = a ^ t15
   c   = t13 ^ 0x00836E4C ; d = c ^ t12
   K9  = [w17, a, h(0x1C)^w17, h(0x20)^b, d, c, u32(raw,0x18)^0x031BB9B1, b, d ^ w8]
   ```
   (somas de imediato `add #imm, lsl #12` somadas: 0x75000+0x568 etc.)
7. **Blocos de 128 B** a partir de corpo+128 (arquivo+136), bloco b = 0,1,2,… ; classe = `K9[b % 9] & 3` → tabela de saltos `{0:A, 1:D, 2:B, 3:C}`; para cada palavra i=0..31 (Hi = u32(H,4i), q = i % 9):
   - A: `out = blk ^ i ^ Hi ^ T4[Hi&3]`
   - B: `out = blk ^ (0x20−i) ^ Hi ^ K9[q]`
   - C: `out = blk ^ Hi ^ T4[Hi&3]`
   - D: `out = blk ^ i ^ Hi ^ T4[K9[q]&3]`
   Todas XOR com constante ⇒ keystream periódico de 9 blocos = **1152 B** (período 9 vem de `b % 9`, 128 do bloco). Explica "bloco3⊕bloco0 = índice da palavra" (classes A vs C no 114: K9 = C,B,A,C,A,B,C,C,C).
8. **Cauda** (n & 0x7F bytes finais, começa em corpo+(n&~0x7F)): para k: `q=T4[k&3]%9; w=K9[q]; v=raw^k^H[k]; out = v ^ ((w + (w*0x80808081>>39)) & 0xFF)` (byte baixo).
9. Loader então grava `0xFAB11BAF` em +0 e o dword de versão em +4.
Se n ≤ 0x80 existe um ramo mais simples (só RC4 direto) — irrelevante aqui.

## Validação
| arquivo | n | w26 | classes dos 9 blocos | keystream 1152 B vs `key1152_*.hex` |
|---|---|---|---|---|
| 114 | 12492124 | 7bee42b4 | C B A C A B C C C | **idêntico** (9/9 blocos) |
| 195 | 11610632 | 8265bfe3 | B D A A D B B A A | **idêntico** (9/9 blocos) |
Reprodução: `wsl -d kingshot-re -u re -- python3 htpx_decrypt.py in.dat out.dat` (ver `htpx_decrypt.py`; ele não escreve sanity/versão — acrescentar `AF1BB1FA`,`18 00 00 00`).
Pendência menor: os 8 B iniciais (+0..+7) não vêm do arquivo (sanity fixo; versão de runtime).

## Emulador semeado (item 1–2 da tarefa)
`emu_seeded.py` (cópia também em `/home/re/work/apk/`): hooks de código **estreitos** (hook global em todas as instruções era o gargalo real junto da cifra), cifra FUN_04949e48 pulada escrevendo os `crypt_out_*` no dst e `X0=srcsz`, e `uncompress` (FUN_04957a9c, ≙ zlib `uncompress(dest,&destLen,src,srcLen)`) executado no host com `zlib`. Resultado: a cadeia ctor→driver→cifra→inflate→relocação/mprotect/memmove das seções→resolução de imports (dlsym/dladdr) roda em **~6 s** (antes >120 s sem sequer sair da cifra).
Marcos (run em `run3.log`): ctors 0–3 ok → ctor 4 (0x48bc354) chama o driver (é a execução real; o "driver" explícito depois é redundante e quebra, pois a imagem já foi sobrescrita — fica atrás de `DRV2=1`) → `[SEED]` parte B e payload → `[DECOMP-HOST] in=0x1116c8f out=0x45ea908` → memmove das seções RX (0x43c1000, 0x4109000…) → `dlsym/dladdr/strstr` (checagem de libs/hooks) → `pthread_key_create/dlopen/dlsym(pthread_create)/pthread_getspecific` (init anti-hook) → **bloqueio novo**: o `pthread_getspecific` stub devolve 0 (JNIEnv/estado inexistente), o init cai num landing-pad `…bl _Unwind_Resume-like (0x4103570)` que nunca retorna, e o stub RET_MAGIC retorna ao LR criando laço apertado em pc=0x1af0a8c (diagnóstico com ring de blocos + `STEP=1`). Para ir além: fazer `pthread_getspecific` devolver um ponteiro com a tabela JNI falsa ([env+0x260]→tabela 0x1f0) ou pular o hook de pthread. **Não é mais necessário para o objetivo**: o gerador foi achado no libunity.

## Arquivos
- `htpx_decrypt.py` — implementação + validação (funções `derive`, `block_ks`, `keystream1152`, `decrypt`).
- `global-metadata_114_decrypted.dat`, `global-metadata_195_decrypted.dat` — metadata v24 em claro.
- `emu_seeded.py`, `run1..4.log` — emulação semeada e diagnósticos. `unity_loader.asm`, `unity_loader2.asm` — disassembly de 0x144720c.. e 0x144784c.. (libunity).
- `disa.py`, `dis2.py` — helpers de disassembly (capstone).
