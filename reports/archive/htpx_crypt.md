# HTPX global-metadata.dat — criptoanálise estatística (PT-BR)

Status: **PARCIALMENTE QUEBRADO.** O corpo NÃO é comprimido: é metadata il2cpp em claro **XOR keystream periódico de 1152 bytes (= 9×128)**. Recuperei o keystream de 1152 B de cada arquivo (estatístico, sem chave/código) e ~98% do corpo decifra para strings/tabelas il2cpp reais. Falta: (1) os primeiros 128 bytes do corpo (cabeçalho: sanity/versão/primeiros pares) usam outra transformação; (2) a **regra de derivação** do keystream (só temos a tabela de 1152 B por arquivo).

Arquivos: `195` = xapk195 (tamanho real **11.610.640** B — o enunciado dizia 11.608.080), `114` = xapk (12.492.132 B). Scripts: `s1..s16.py` nesta pasta (rodar via `wsl.exe -d kingshot-re -u re -- python3 ...`; os `/tmp/*.npy` são gerados por s6/s11). Chaves: `key1152_195.hex`, `key1152_114.hex` (1152 B, indexadas por **offset de corpo** = offset do arquivo − 8, módulo 1152).

## 1. Mapa de estrutura (ambos)
| Região | Fato (testado nos 2 arquivos) |
|---|---|
| 0..3 | `48 54 50 58` "HTPX" |
| 4..7 | u32 LE = **tamanho TOTAL do arquivo** (11610640 / 12492132, igual a `len`; não `len-8`) |
| 8..135 (corpo 0..127) | **não** decifra com o keystream de 1152 B (nenhuma das 1152 rotações dá estrutura; s13) — cabeçalho il2cpp tratado à parte |
| 136.. (corpo 128..) | decifra: em 114 corpo+128 = pares (offset,size) `0x99b140,0x3834 | 0x99e974,0x76610 | 0xa14f84,0x15b68 ...` com offset[i+1]=offset[i]+size[i] ✓; em 195 `0x8e2818,0x3054 | 0x8e586c,0x71a58 | 0x9572c4,0x14728` ✓ (contíguos) |
| resto | string heap legível: `mscorlib`, `System.Security.Cryptography.AesCryptoServiceProvider`, `UnityEngine` (12158× em 195, 12406× em 114), `.ctor`, `Assembly-CSharp`, `<Module>`; bytes zero 28,9% / 28,6%; só ~2% das linhas de 128 B ficam "ruins" e esses blocos são dados binários, não falhas de chave (clusters em linhas ~6000 e ~54000 em 195; ~6500, ~58900 em 114, = tabelas binárias) |
| sanity `AF 1B B1 FA` | **0 ocorrências** no corpo decifrado (está nos 128 B não decifrados) |

Entropia: janelas de 4 KB ≈ 7,6 (195) / 7,45 (114), sem queda em nenhum ponto (min 7,39 / 7,17, max 7,96) — **não há “cliff” de 4096** como nos bundles. A entropia alta NÃO era compressão: XOR com chave periódica preserva o histograma, e o histograma de byte é muito enviesado (bytes mais comuns 0,87% / 1,3% vs 0,39% uniforme). Sem zlib/LZ4.

## 2. Evidências da periodicidade
- Auto-igualdade por lag (primeiros 2 MB): lag 128/512/640/384/768/1024 = 4,3–5,2% (195) e 6,2–8,4% (114) vs base 0,4%; lag 256 e 896 baixos em 195. Não é período 128 simples.
- Índice de coincidência por coluna, varredura de períodos 8..1400 (passo 8)+potências: **1152 vence nos dois arquivos** (0,0393/0,0390 vs mediana 0,006); divisores 384/576/768/1536/3072 em segundo.
- Estimativa por moda + EM (distribuição de plaintext reestimada; converge em 3 iterações): com período 128 → zeros 15,1% / 22,3%; com **1152 → 28,9% / 28,6%**, e strings completas.
- Mesmo sem EM, `UnityEngine` aparece 6683× em 114 com período 128.

## 3. Estrutura do keystream de 1152 B (S[n], n = palavra u32 LE, 288 palavras)
Evidência byte-a-byte nos dois arquivos:
- Em 195 há só **88** palavras distintas em 288; em 114 só **95**. Nenhuma palavra do keystream é compartilhada entre os dois arquivos (chaves por-arquivo, independentes).
- Os 9 blocos de 128 B são de poucas "classes": 195: blocos {0,3,4,8} idênticos; {2,5} idênticos entre si (32 B iguais ao bloco 0); {1,6,7} idênticos entre si (2 B iguais ao 0). 114: {0,1,4,7,8} idênticos; {3,5} idênticos (97 B iguais ao 0); {2,6} idênticos (3 B iguais).
- **114, bloco 3 (e 5) ⊕ bloco 0 = índice da palavra dentro do bloco** (`00000000 00000001 00000002 ... 0000001f`, nas 32 palavras) — uma contagem aparece no keystream. Mesmo padrão não visto em 195 (lá os diffs são um pequeno conjunto de constantes: 0, 9d9477de, 37abad4d, c4303634, aa3fda93).
- Em 195, 114 as palavras ⊕ aos pares repetem muito (`S[n]^S[n+1]` igual 35×) → a sequência tem estrutura aditiva/tabela pequena, **mas não é afim em GF(2) sobre o índice** (s16: 1,4k/68k e 2,2k/68k de consistência; falso) e não há periodicidade de palavra além de 32/96/128.
- Padrão de 9 = (bloco mod 9) sugere chave de 128 B × seletor de 9 estados (ou duas chaves de períodos 128 e 9 blocos combinadas por outra operação que não XOR simples; XOR simples de K128 e K9 foi refutado pela contagem de blocos).

## 4. Matriz de hipóteses
| # | Hipótese | Resultado | Evidência |
|---|---|---|---|
| a | XOR 0xA6 em janela inicial (como bundles) | **Refutada** | corpo+0..7 ⊕ 0xA6 não dá sanity; o byte mais comum por coluna não é A6; a chave aqui é 1152 B variada |
| b | só os primeiros N bytes cifrados | **Refutada** (para o corpo) | decifra até o fim; entropia/lag sem cliff em 4096. **Confirmada só para o cabeçalho**: corpo 0..127 tem outra transformação |
| c | stream cipher whole-body por-arquivo | **CONFIRMADA** | keystream periódico 1152 B por arquivo (chaves disjuntas); strings/tabelas il2cpp após XOR nos 2 arquivos |
| c' | período 128 | Parcial | decifra ~metade; 1152 é o real (IC + zeros +13 pts) |
| d | compressão só em partes | **Refutada** | nada de zlib/LZ4 nem região de entropia 8; entropia alta = histograma enviesado |
| e | cifra de bloco do packer (FUN_04949e48) | já descartada pelo operador; aqui nenhum teste necessário | keystream com 88–95 palavras distintas e contador visível não parece saída de bloco cifrado |
| f | cabeçalho (corpo 0..127) = mesmo keystream rotacionado | **Refutada** | 1152 rotações × 2 arquivos: melhor score 4/64 bytes-altos-zero (acaso) |
| g | keystream afim em GF(2) no índice | **Refutada** | s16 |

## 5. Restrições para qualquer derivação de chave
1. K(p) com p = offset do corpo (offset arquivo − 8) mod 1152; K = 1152 B por arquivo, K(p+1152)=K(p). Tabelas em `key1152_*.hex` (início do arquivo: corpo[0]=offset 8). Dentro de cada arquivo: 9 blocos de 128 B, apenas 3 classes de bloco (padrões acima); 88 (195) / 95 (114) palavras de 32 bits distintas.
2. 114: K[96+i] ⊕ K[i] = i (palavra i do bloco, i=0..31) e idem para bloco 5; K[bloco1]=K[bloco0]=K[4]=K[7]=K[8]. Para 195: K[0]=K[3]=K[4]=K[8]; K[2]=K[5]; K[1]=K[6]=K[7]. A função deve reproduzir esses padrões de igualdade e de contagem (provável: bloco b → classe(b), e dentro da classe uma operação com o índice de palavra).
3. Chaves distintas entre arquivos (0 palavras iguais): depende de algo por-versão (hash do binário? tamanho do arquivo 11610640/12492132? `libil2cpp` build id?). Teste não feito.
4. Cabeçalho: corpo[0..127] ≠ keystream; corpo[128..] válido. Plaintext esperado nos primeiros 8 bytes: `AF 1B B1 FA` + versão (24–31); K'[0..3]=C^AF1BB1FA = 4352fdb4 (195) / 366d8a89 (114) *se* o cabeçalho for XOR com chave (não validado). Pares (offset,size) devem ser contíguos (offset[i+1]=offset[i]+size[i]) e o primeiro offset = tamanho do cabeçalho (≈0x100–0x110) — usar isso como crib para recuperar os 128 B (dá ~16 pares conhecidos por restrição aritmética: com pares ainda desconhecidos mas contíguos e com os 8 B finais conhecidos de corpo+128, cada par vem de offset[i]=offset[i+1]−size[i]).
5. Qualquer algoritmo que não gere o contador ("⊕i") e as classes de blocos acima está errado.

## 6. Próximos passos baratos
- Recuperar corpo[0..127] por aritmética de contiguidade: os offsets do 1º pair (corpo+128 → 0x99b140 em 114) permitem derivar os pares anteriores se soubermos seus sizes (tamanhos = diferença entre offsets sucessivos, e todos exceto o último são determinados pela tabela decifrada ⇒ a restrição "offset[i]+size[i] = offset[i+1]" dá sizes). Isso dá plaintext conhecido para a chave do cabeçalho (acha K'[0..127] e pode revelar a relação com K1152).
- Com o plaintext do cabeçalho, ver se K' = K1152 com outro seletor de bloco (ex.: bloco “−1”) ou se é a mesma geração com contador diferente.
- Procurar no libNetHTProtect/libil2cpp_114_full.so a constante de 1152/0x480 ou 288/0x120 e laço com contagem u32 — a rotina de leitura do metadata (loader hookado) é onde está a regra.

Não toquei no celular nem no repo.
