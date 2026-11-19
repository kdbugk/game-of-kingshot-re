#!/usr/bin/env python3
"""Lane F (pai): keystream recovery + hypothesis tests on block-0 data.
Schema do pkl (collect.py linha 32): (v, n, usz, csz, bf, nodes, block0bytes, nblocks, start, filesize, header)"""
import pickle, struct, sys
from collections import defaultdict

d = pickle.load(open('/tmp/b0.pkl', 'rb'))
print(f"{len(d)} bundles")
print("exemplo campos:", d[0][0], "usz", d[0][2], "csz", d[0][3], "nblocks", d[0][7], "nodes", [n[3][:20] for n in d[0][5][:2]])

# 1) keystream recovery parcial: para cada bundle, keystream = cipher XOR plaintext
# plaintext inicial conhecido até ~49 (LZ4 válido) + janela 0xA6 [50..80]
# recuperação bytes 81+: só onde plaintext é previsível (zeros do header v22)
# → heurística: bundles cujo usz pequeno e tipo tree simples têm header altamente zero
# na prática: recuperamos key[i] = c[i] ^ p[i] quando sabemos p[i]

# 2) TESTE PRINCIPAL: a keystream é GLOBAL (mesma p/ todos os bundles)?
# teste indireto: para pares de bundles, XOR dos ciphers além do byte 80
# se keystream global: xor = xor dos plaintexts; plaintexts de headers v22 são
# similares (zeros + versão) → xor teria MUITOS zeros além dos já conhecidos
import itertools
pairs = list(itertools.combinations(range(min(len(d), 40)), 2))[:300]
zero_runs_beyond80 = []
for i, j in pairs:
    a, b = d[i][6], d[j][6]
    n = min(len(a), len(b), 300)
    x = bytes(p ^ q for p, q in zip(a[:n], b[:n]))
    # zeros além do byte 80
    z = x[81:n].count(0)
    zero_runs_beyond80.append((z, i, j))
zero_runs_beyond80.sort(reverse=True)
print("\ntop pares por zeros além do byte 80:")
for z, i, j in zero_runs_beyond80[:8]:
    print(f"  par({i},{j}): {z} zeros em {min(len(d[i][6]),len(d[j][6]),300)-81} bytes")

# 3) se keystream global → chave completa recuperável por maioria de votos:
# assumir plaintext-zero em posições onde a maioria dos ciphers tem o MESMO byte
# (se p=0 na maioria, c=k na maioria → moda ≈ keystream!)
from collections import Counter
maxn = 300
cols = list(zip(*[b[6][:maxn] for b in d if len(b[6]) >= maxn]))
mode_stream = bytes(Counter(col).most_common(1)[0][0] for col in cols)
agree = [Counter(col).most_common(1)[0][1] / len(col) for col in cols]
print("\nmoda dos ciphers (candidata a keystream se plaintext=0 dominante):")
print("  ", mode_stream[:80].hex())
print("concordância por posição: média", sum(agree)/len(agree))
print("  concordância[0..49]:", round(sum(agree[:50])/50, 2))
print("  concordância[50..80]:", round(sum(agree[50:81])/31, 2))
print("  concordância[81..130]:", round(sum(agree[81:131])/50, 2))
print("  keystream candidata [81..131]:", mode_stream[81:131].hex())
