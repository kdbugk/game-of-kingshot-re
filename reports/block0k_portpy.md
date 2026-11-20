# PORT-PY — decifrador do bloco 0 em Python puro

**Resultado: 119/119 bundles (corpus /tmp/b0.pkl) → LZ4 válido com usz exato, e saída BYTE-A-BYTE idêntica à do emulador unicorn (119/119, retorno `ret` idêntico 119/119).**
Script: `C:/Users/prs/work/luapkg/dec_block0.py` (sem unicorn; só `struct`). Validador: `luapkg/pp/val.py` (rodar no WSL `kingshot-re`, onde está /tmp/b0.pkl e lz4).

## Algoritmo (F_01412580 @ vaddr 0x1412580; size=min(csz,0x1000))
```
Fase A (localizar):  p = 1ª posição < 0x48 com  b[p]=EE b[p+1]=DD u16=LE(b[p+2:p+4]) ∈ {0x2017-19, 0x2020-28, 0x6000,0x7000,0x8000,0x9000}
  L = 0 se b[p+4]=='.' ou b[p+6]=='.';  0x1000 se (b[p+4],b[p+6])==(AA,BB);  senão b[p+6]+16*b[p+4]
  reescreve versão: b[p..p+3] = nibbles de u16 + 0x30 ("2022"); 
  se b[p+9]∈{31,32}: z=b[p+8]; b[p+8]='f' senão z=0;  se b[p+10]∈{31,32}: z=b[p+9]; b[p+9]='f'
  a=z+0xB; (z==p ou z==0): off=shift=max(a, 0x30 se p<0x20 senão 0x40)
           senão: a=max(a, 0x30 se z<0x20 senão 0x40); se p<z: off=a-z+p, shift=a; senão off=shift=a
  b[p+4]=b[p+6]='.'
  L = size se (L==size ou L==0 ou L>0x1000); L=min(L,0x1000);  L' = L - shift
Fase B (decifrar, hdr=b+off):
  w0..w4 = u32 LE de hdr[0:0x14]
  K = CRC32v(w3,w1,w4,L',w2)      # init FFFFFFFF, poly 04C11EB7 reflexa, passo (T[(c^b)&FF]^(c>>8))+0x10, final 0x82D63B78+~c
  T4 = [ (u32(hdr+0x14)+0x1985)^K, (u32(hdr+0x1c)+0x1981)^K, K^(L'+0x2013), (u32(hdr+0x18)+0x2018)^K ]
  hdr[0:0x20] ^= 0xA6
  RC4(chave=K LE 4B, S identidade; saída ror8(k,2)+0x3a):
    L'<0xA0 : hdr[0x20:L'] ^= ks
    L'>=0xA0: enc=hdr[0x20:0xA0]; hdr[0x20:0xA0] ^= RC4(K)         # in-place
              H = enc ^ RC4(chave=T4[2])                           # 2ª passada: chave DIFERENTE (ver abaixo)
              K9 = [0x571,T4[3],0x892,0x750,T4[0],T4[1],0x746,T4[2],0x568]
              para cada bloco n de 0x80 B a partir de hdr+0xA0 (r=L'-0xA0, nb=r>>7):
                 cls = K9[n%9]&3 ; para cada word i<32 (c=word cifrada, Hi=H[i], m=i%9):
                   cls0: c ^ (0x20-i) ^ Hi ^ K9[m]        cls1: c ^ Hi ^ T4[Hi&3]
                   cls2: c ^ i ^ Hi ^ T4[Hi&3]            cls3: c ^ Hi ^ i ^ T4[K9[m]&3]
              cauda (r&0x7f bytes): b[k] ^= Hbytes[k] ^ k ^ low8(w+(w*0x80808081>>39)),  w=K9[T4[k&3]%9]
```

## Como o "ilegível" foi resolvido (capstone, sem heurística)
- O `br x1` em 0x14131bc usa a tabela de bytes em 0x13eeef0 = `00 37 14 22` → alvos 0x14131c0 + 4*{0x00,0x37,0x14,0x22}: quatro corpos (0x14131c0 cls0, 0x141329c cls1, 0x1413210 cls2, 0x1413248 cls3). Disassemblados: os 4 corpos são as classes A–D do HTPX **com mapeamento de jump table diferente** (aqui 0→"B",1→"C",2→"A",3→"D" nos nomes de htpx_decrypt.py). Índice do bloco = `n%9` (mul 0x38e38e39), classe = `K9[n%9]&3`.
- Constantes 0x1985/0x2013/0x1981/0x2018 = os 4 words T4 (saídas do relatório anterior). K9 tem 5 constantes + 4 T4.
- Armadilhas do Ghidra corrigidas com o emulador (hook em 0x14131bc lendo a stack): (1) o decompile mostrava o 2º RC4 com a mesma chave K; na verdade a chave é **T4[2]** (`local_22c`), logo H usado nos blocos/cauda ≠ o plaintext do header (é `enc ^ RC4(T4[2])`); (2) K9 real = constantes 0x892/0x750/0x746 (do decompile), NÃO as lidas pelo meu 1º disassembly de `ldp q0,q1,[0x13eeef4]` (ali parte é sobrescrita por stp – confirmei por dump da stack do emulador).
- Fase A: `FUN_01412300(0x14a0d70)` não foi analisada; assumi retorno −1 (ramo p+9/p+10). Confirmado empiricamente (119/119 idêntico).

## Validação
| teste | resultado |
|---|---|
| LZ4 válido + usz exato (Python puro) | 119/119 |
| saída idêntica ao emulador (bytes dos 4096 B) | 119/119; ret idêntico 119/119 |
| distribuição: off/shift observados | shift 48 ou 64; off 42..58; todos L'≥0xA0, todos com ≥1 bloco e cauda ≠0 |
| tempo | Python puro **0,46 ms/bundle**; unicorn **0,95 ms/bundle** (+0,2 s de carga do .so, +dependência) → ~2x mais rápido, sem .so |

## Gaps / não coberto (honesto)
1. **Ramo curto L'<0xA0 não exercitado** pelo corpus (nenhum bundle caiu nele; mesmo os 13 com csz<4096 têm L'≥0xA0). Implementado a partir do decompile (RC4 com K, `L'-0x20` bytes) mas **sem teste real** — pode conter o mesmo tipo de erro de chave.
2. Rotas não portadas: magics 0xA6A6A6FB/0xA6A9A6A6/0xA6B7A6A6/0xAEA6A6FB (varrem "UnityFS", nada decifram — função só retorna), rota HTP8 (patch + XOR 0x59 de 7 qwords) e o caso `FUN_01412300 != -1`. Sem o magic EE DD o script devolve (0, buf) sem alterar.
3. Classes 0–3 todas exercitadas na prática (31 blocos × 119), mas só com o corpus de 119 bundles da 1.9.5/1.14.27; bundles com csz>0x1000 só têm os 4096 primeiros decifrados (resto copiar cru).

## Uso
`python3 dec_block0.py in.bin out.bin` ou `ret, out = decrypt_block0(stream[:0x1000], min(len(stream),0x1000))`; depois `lz4.block.decompress((out+stream[0x1000:])[:csz], usz)`.
