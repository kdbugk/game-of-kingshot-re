# Block 0 — análise estatística (known-plaintext / diferencial), sem Ghidra

Status: **NÃO crackeado**, mas o problema foi reduzido de forma importante (ver "Achados"). Dados: 119 bundles (60 da 1.9.5 + 59 da 1.14.27, aleatórios), coletados por `collect.py` (pickle em /tmp do WSL: `/tmp/b0.pkl`). Scripts de apoio: `t1..t20.py` nesta pasta.

## Achados (todos com evidência byte-a-byte em >=5 bundles)

1. **O prólogo de 8 bytes NÃO é cabeçalho custom: são 2 tokens LZ4 normais.**
   `16 00 01 00 | 15/16 16 0a/0b 00` = (lit=1 `00`, off=1, ml=10) + (lit=1 `16`, off=10/11, ml=9/10) → 21 bytes `00*11 16 00*9`,
   i.e. o início do SerializedFile v22 (campos legados zerados, `m_Version=0x16`). Idem para os tokens seguintes (`32 02 5b f9 08 00 22 c4 ef 08 00 24 5c 30 1b 00 f0 ..`):
   o stream é LZ4 padrão **nos primeiros ~49 bytes** e decodifica em: `metadataSize`(u32 BE) `fileSize`(u64 BE; o `04 4b 79 78` do exemplo é literal LZ4 legítimo = tamanho do nó) `dataOffset`(u64) `0(u64)`.
   Logo, hipótese (a) (cabeçalho custom + LZ4 deslocado) e (b) (dicionário/preset) são falsas: o início já é LZ4 válido sem offset.
2. **A "string de versão" é ruído por-bundle, não `2022.3.62f1`.** Literais `ee dd 22 20 XX 33 YY 36 32 ZZ 31 00`:
   `XX,YY` = (csz>>4, csz&0xF) do bloco em bundles de bloco único (ex.: csz=1418=0x58a → `58 .. 0a`; 1443=0x5a3 → `5a .. 03`; 1427=0x593 → `59..03`; 1503=0x5df → `5d..0f`: 4/4 bundles). Em bundles multibloco `XX,YY=aa,bb` fixos. Ou seja, o encoder reescreve bytes da versão com metadados — o plaintext real da string está perdido/transformado (não é recuperável por simples crib).
   Em seguida `0d 00 00 00` (platform=13 Android) `01` (enableTypeTree) `NN 00 00 00` (typeCount, LE) aparecem em claro e com a string `31 00`.
3. **Região mascarada com XOR constante 0xA6 logo após o 1º match "longo" (p0 = 43..50, imediatamente após o literal-run `f0 xx` + offset).**
   Em 102/119 bundles, `stream[p0:p0+~24..32] ^ 0xA6` produz tokens LZ4 válidos e conteúdo de typetree coerente: `ff ff` (scriptTypeIndex=-1) aparece sempre no lugar certo (`f3 0c ff ff ..`, `f3 04 ff ff 48 6b a4 e1 ..`, vistos em >=25 bundles); o hash MD4 do tipo (16 bytes) é idêntico entre bundles de mesma classe (3544/3744 e 3676/4092: iguais até p0+32 e diferem depois) e `a6 a6 a6`→`00 00 00`, `e9 a5 a6`→`4f 03 00`. A decodificação lenient passa de 70 para 116–282 bytes.
4. **Depois de ~32 bytes (cerca de pos 81) a chave deixa de ser 0xA6 e passa a ser POR-BUNDLE.** Dois bundles com mesmo typetree (3544 vs 3744; 3676 vs 4092) têm XOR de cifras = `00` até pos 80 e **aleatório** a partir de 81 (`84 c6 cd ad 4d 23 a0 e8 c9 4b ..`, `e5 f3 3f a4 97 ae f7 00 1b ..`). XOR com constante única em janelas de 1..60 bytes, qualquer k∈[0,255], não estende o decode além de 116 (4 bundles testados) → a chave não é um byte constante por bloco.
5. **Só os primeiros 4096 bytes comprimidos do bloco 0 estão cifrados.** Distintos/64B e correlação lag-5 caem de forma abrupta **exatamente em 4096** (bundles idx 1,12,17,20,66: `58 57 58 53 | 18 18 17 19`, lag-5 ~0–2% antes, 40–70% depois). Depois de 4096 o stream tem redundância normal de LZ4 (sem máscara); bundles com csz<4096 (típicos pequenos, 1.4–4 KB) são cifrados inteiros a partir de p0.
6. **Periodicidade 128:** na região cifrada de 4 bundles pequenos, `C[i]==C[i+N]` tem pico em N=128/256/384 (1.0–2.3% vs 0.39% de base, em 4/4). Compatível com keystream periódico de 128 bytes (por-bundle), mas fraco (P não é zero-heavy).
7. Cabeçalho UnityFS (bytes brutos do arquivo, 144 B nos pequenos): `UnityFS\0 | 00 00 00 08 | 5.x.x | 2022.3.62f1 | size(8) cs(4) us(4) flags | blocksInfo LZ4 | 'CAB-<32 hex>'`; o blocksInfo traz usz/csz BE (`00 00 0d d8 00 00 05 8a 00 03`) — **os mesmos números aparecem (csz) embutidos na "versão" do bloco 0** (achado 2). A chave por-bundle pode ser derivada de algo desse cabeçalho (nome CAB de 32 hex = 32 bytes? csz/usz/size) — NÃO testado além do 128-periodicity.

## Matriz de hipóteses
| # | Hipótese | Resultado | Evidência |
|---|---|---|---|
| a | prólogo = header custom + LZ4 em +8 | **Eliminada** | prólogo = 2 tokens LZ4 válidos (21 bytes `00..16..00`); decode em +8 quebra offsets |
| b | preset dictionary (8 bytes = id) | **Eliminada** | idem; matches do início só referenciam saída gerada (offset 1/10/11/8/26) |
| c1 | XOR de byte único em todo o bloco | **Eliminada** | varredura k∈[0,255]×p0∈[40,60] (4 bundles): melhor 116–371 bytes, sem sentido |
| c2 | XOR const. 0xA6 em [p0,p0+32) | **Confirmada parcial** | `ff ff`, `00 00 00`, hash idêntico entre bundles; 102/119 |
| c3 | XOR const. por bloco de 32/N bytes além de 81 | **Eliminada** | k∈[0,255]×L∈[1,59] em 81..: nenhum estende decode (4 bundles) |
| c4 | autokey/CBC/feedback (chave depende de bytes anteriores do mesmo bundle) | **Improvável** | chave 0xA6 idêntica em bundles com bytes anteriores distintos (versão-noise, sizes) |
| c5 | keystream periódico de 128 B por bundle | **Indicado, não validado** | pico N=128/256/384 em 4/4 |
| d | LZ4 frame / zlib / miniz | **Eliminada** | stream é LZ4 block puro (tokens válidos nos primeiros 49 B), sem magic |
| e | permutação de blocos de 16 B (m_FileSize em +16 cru) | **Eliminada** | `04 4b 79 78` é literal LZ4 normal; a ordem dos campos bate com SerializedFile v22 legado zerado |
| f | cifra cobre o bloco inteiro | **Eliminada** | só os 4096 primeiros bytes (entropia/lag-5, 5 bundles); resto é LZ4 plain |
| g | lenient-fail em ~70 B = limite de "região criptografada" | **Confirmada** | falha em offset inválido logo após p0 (achado 3) |

## Estado e próximos passos (curtos)
- Para decifrar: falta a chave por-bundle de ~4096 bytes (provável período 128). Duas rotas baratas ainda não testadas:
  (1) derivar chave de campos do cabeçalho do arquivo (CAB name 32 hex, csz, usz, size) – testar `K[j]=f(...)` usando que K[49..80]=0xA6 e K[0..48]=0 como constrangimentos fortes (K[0..48]=0 sugere que a chave é uma *máscara* aplicada só a partir de uma posição);
  (2) resolver K[81..127] por-bundle via two-time-pad: bundles de mesma classe (mesmo typetree) dão `C_a^C_b = K_a^K_b` onde P coincide — mas P diverge cedo; use bundles multibloco cujo plaintext do bloco 0 é conhecido por outro caminho (ex.: o mesmo CAB em 1.9.5 vs 1.14.27 com conteúdo idêntico) para ter `P` completo.
- Consequência prática: depois da chave, descomprimir exige o decoder LZ4 padrão sobre o stream decifrado (+ o fato de que a "versão" foi sobrescrita por metadados, o SerializedFile só será parseável se esses bytes forem restaurados — ou se o engine ignora a string).

## Reprodução
`MSYS_NO_PATHCONV=1 wsl.exe -d kingshot-re -u re -- python3 /mnt/c/Users/prs/work/laneC/collect.py` → /tmp/b0.pkl; depois `t8/t9/t12/t17/t18/t19.py`. Nada tocado no celular nem no repo.
