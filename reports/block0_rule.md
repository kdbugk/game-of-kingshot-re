# Lane M — Regra do keystream do bloco 0 (Kingshot UnityFS)

Status: **regra de geração NÃO encontrada, mas a premissa da lane C/F está REFUTADA: o keystream NÃO é por-bundle — é GLOBAL (mesmo K[i] para todos os bundles e para as duas versões 1.9.5 / 1.14.27).** Isso muda o problema: não há "seed por bundle" a derivar; basta recuperar UMA tabela K[0..4095] (uma única vez, via plaintext conhecido de 1 bundle — ex.: dump em runtime — ou por cribs).

Dados: `/tmp/b0.pkl` (119 bundles; 105 com csz>4200). Scripts: `a3..a9.py` nesta pasta (rodar com `MSYS_NO_PATHCONV=1 wsl.exe -d kingshot-re -u re -- python3 /mnt/c/Users/prs/work/laneM/aN.py`).

## 1. Evidência principal: keystream global (byte-a-byte)
1. **Re-convergência após divergência local** (a4.py): bundles 80/85 (`...versionconfig2611/2610_scenedata_td_activity_level_04_cell`, csz 53037/53036, usz 94312): cipher IDÊNTICO em 0..1500 exceto uma janela de 8 bytes em ~934..941 e uma de ~25 bytes em 995; depois volta a coincidir. Isso é incompatível com autokey/CBC/feedback (um erro propagaria) e prova keystream **posicional** idêntico nos dois bundles (diferença = só plaintext).
2. **Runs idênticos longos entre bundles sem nada em comum** (a9.py; 44/5460 pares com run ≥100 B a partir da pos 81):
   | run | início | versões | usz | csz | nomes/CAB |
   |---|---|---|---|---|---|
   | **1959 B** | 81 | 1.9.5 / 1.9.5 | 131072/131072 | 24464/25163 | `ui_panel_city_fx_steamengine630…` vs `towerdefense_effect_lod_fx_50007…` |
   | 1688 B | 81 | 1.9.5 / 1.9.5 | 131072 | 24996/25163 | outros nomes/CAB |
   | **1367 B** | 81 | **1.9.5 / 1.14.27** | **28092 / 20924** | 8092/6289 | `…_01_a655…` vs `…sawmill_09_e771…` |
   | 767 B | 81 | 1.9.5 / 1.14.27 | 131072/94312 | 40912/53037 | idem |
   Dos 44 pares, 15 cruzam versões e 15 diferem em usz+csz+versão+nome+CAB simultaneamente. ⇒ K independe de csz, usz, nome, CAB, versão do jogo.
3. **Perfil por posição** (a8.py): nos melhores pares, igualdade 98–100% por blocos de 256 B desde 81 até onde o type tree diverge (≈2040), depois 2–3% (≈ colisão de plaintext, vs 0,4% de ruído) — ou seja o plaintext (lista de types / typetree compartilhada) é o que diverge, não a chave. Média sobre todos os pares: 0,5% (base 0,39%), com 9,3% em 0..255 (prólogo comum).
4. Interpretação da "string de versão" (lane C, achado 2): `ee dd 22 20 XX 33 YY 36 32 ZZ 31 00` é **plaintext real do SerializedFile do bundle** (XX/YY derivados de csz) — não precisa ser cifra. Primeiro type = classID literal no byte 46: `0x8e`=142 AssetBundle, `0x31`=49 TextAsset… (ids reais Unity) → plaintext pós-81 é lista de types previsível.
5. Entropia do trecho cifrado = 7,999 bits (histograma plano): K é pseudoaleatório de boa qualidade (ex.: não é XOR com tabela pequena). Não há tabela estática: varredura de runs `A6{12,}` em `unity_image.bin`, `libunity_114.so`, `unity_unpack/*` = 0 ocorrências ⇒ K é **gerado em runtime**.

## 2. Matriz de hipóteses (testes com ≥10 bundles)
| # | Hipótese | Resultado | Evidência |
|---|---|---|---|
| a | K = mesmo gerador do HTPX (período 128, classes de blocos) | **Não testável sem K[81..]** (nenhum byte de K além 0..80 recuperado de forma absoluta) | — |
| b | seed = f(csz, usz, hash/nome, CAB, versão) | **ELIMINADA** | runs idênticos de até 1959 B entre bundles com todos esses campos diferentes (44 pares, 15 cross-versão) |
| c | gerador CRC32C (0x1EDC6F41, init 0x8f6e37a0) seeded por campo do bundle | **Eliminada na forma "por-bundle"**; forma global não testável sem K | idem |
| d | LCG/xorshift seeded por arquivo | **Eliminada na forma "por-arquivo"** | idem |
| e | autokey / CBC / dependência do plaintext anterior | **ELIMINADA** | re-convergência exata após divergência de plaintext (a4.py, 80/85) |
| f | K por-bundle de 128 B periódico | **REFUTADA** | o "pico em 128" da lane C era ruído de plaintext compartilhado; K idêntico em runs de ~2000 B entre bundles |
| g | K global posicional de 4096 B, pseudoaleatório | **CONFIRMADA (parcial: ≥[81,2040) provado idêntico; ver ressalva)** | itens 1–3 |
| h | região A6 | K[49..80]=A6 vale p/ todos (102/119), logo é parte da mesma tabela global | — |

Ressalva: a identidade de K só é *provada* onde existe run de cipher igual (81..~2040 em pelo menos um par). Para 2040..4095 não há par com plaintext igual, mas a entropia/cliff exato em 4096 e a ausência de variação por-bundle em tudo que foi testado tornam K global a hipótese de trabalho (testar com 1 bundle decifrado).

## 3. Por que não recuperei K (limitação honesta)
Com K global, cada bundle dá C[i]=P[i]^K[i] e P só é conhecido nos 81 primeiros bytes. Para o resto: plaintext = LZ4 de SerializedFile typetree; os literais (hashes de 16 B, strings) não têm restrição de parse. Tentativa de decode por beam/DFS exige prior de conteúdo e esbarra em bytes literais aleatórios (hash MD4 dos types) — não concluída no orçamento. Moda por posição (lane F) é fraca porque o plaintext varia entre classes.

## 4. Caminhos concretos (ordem de custo)
1. **Runtime (mais barato agora que K é global):** pegar em runtime o buffer do bloco 0 *depois* do XOR (hook na rotina de decrypt do libunity — a que roda sobre os primeiros 4096 B do bloco comprimido — ou dump do input do LZ4 decompress) para **um** bundle com csz ≥ 4096; K = C ^ P_dump para 4096 B, validável nos 105 bundles (decode LZ4 completo + SerializedFile v22 válido). `block0_decode.py key.bin bundle` já faz a validação. Depois, com os 4096 B de K, atacar gerador (CRC32C / família HTPX) offline.
2. **Offline puro:** two-time-pad entre bundles em posições deslocadas (mesmo plaintext literal — hashes/strings de types — em posições p≠q ⇒ C1[p]^C2[q]=K[p]^K[q]) + âncora em K[49..80]=A6 e zeros; ou reconstruir o typetree do AssetBundle (cluster classID 142, 1959 B idênticos) com lz4 HC e confrontar.
3. **Estático:** localizar no libunity (`stage2.bin`/`unpacked_payload.bin`) a função que XORa 4096 B antes do LZ4 e ler o gerador diretamente.

## 5. Arquivos
`a3.py` (colisões por campo), `a4.py` (perfil de igualdade 80/85), `a5/a6.py` (matriz de similaridade e pares), `a8.py` (perfil por posição), `a9.py` (runs idênticos), `block0_decode.py` (decoder para K global; aguarda K).
