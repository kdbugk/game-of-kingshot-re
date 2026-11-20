# Como os assets funcionam — os arquivos cifrados do jogo (4 min)

> TL;DR: os assets (texturas, áudio, a LÓGICA LUA) viajam em bundles Unity **envelopados**
> por uma capa proprietária com cifra própria por arquivo (bloco 0) — tudo reproduzido
> offline neste projeto: 119/119 bundles abrem.

## 1. A cebola de camadas

```
.arquivo .htp (bundle)
 └─ capa HTProtect: header 0x20B + cifra do BLOCO 0 (primeiros 4096 B)
     └─ dentro: UnityFS padrão (LZ4) — o bundle Unity de verdade
         └─ dentro: SerializedFile → TextAssets (e o luapackage de ~100 MB)
```

O truque: **só o primeiro bloco de 4 KB é cifrado com a capa proprietária**; o resto é
LZ4 comum. Quem decifra o bloco 0, decifra o arquivo.

## 2. A cifra do bloco 0 (a receita)

1. Chave derivada do PRÓPRIO header (CRC32 variante: poly 0x04C11EB7, soma 0x10 por
   passo, final `0x82D63B78 + ~crc`) sobre os primeiros 20 bytes
2. Header: XOR 0xA6 · Corpo: RC4 modificado (S identidade, saída `ror8(k,2)+0x3a`)
3. Blocos de 0x80 com classes A-D (índice `n%9`, escolhidas por `K9[n%9]&3`)

O arquivo `global-metadata.dat` (o "dicionário" do IL2CPP) usa a mesma família, com
keystream de 1152 B — ambos reproduzidos em Python puro.
*(detalhes: reports/block0k_decoded.md, block0k_portpy.md; código: scripts/dec_block0.py,
work/laneL/htpx_decrypt.py)*

## 3. O que tem dentro (o tesouro)

- **luapackage**: 8.333 módulos LuaJIT — dentro deles, como string, os **schemas sproto
  completos** do protocolo (docs/REDE) e as 1.389 tabelas de balanceamento
- Assets comuns de Unity + `toluaout` (bindings tolua#)

## 4. Por que essa cifra existe (e o limite dela)

É **cifra de distribuição**: impede ferramentas genéricas de lerem/alterarem assets
(mod, rip, private-server fácil). Não resiste a análise dedicada — a chave deriva do
próprio arquivo (self-contained). O mesmo padrão aparece na metadata IL2CPP.

## Onde se aprofundar
- Decifração completa + validação 119/119: `reports/block0k_decoded.md`
- Port Python (constantes derivadas): `reports/block0k_portpy.md`
- A caçada ao gerador (histórico): `reports/block0k_gen.md`
- Extração do luapackage: `reports/luapkg.md`
