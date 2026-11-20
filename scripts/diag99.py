#!/usr/bin/env python3
"""Diagnóstico do 99%: compara a sequência de requests do cliente na sessão do mock
vs a sequência gravada (transcript cap115), e o que cada um respondeu."""
import pickle, re, glob, collections

frames = pickle.load(open('/home/re/work/apk/gw_transcript115.pkl', 'rb'))
C2S = [(t, f) for t, d, f in frames if d == 'C>S']
S2C = [(t, f) for t, d, f in frames if d == 'S>C']

def tag(f):
    """(op, b1, tag16-hex) — tag = bytes 2-3 quando parece tag fixa"""
    if len(f) >= 4:
        return (f[0], f[1], f[2:4].hex())
    return (f[0], f[1] if len(f) > 1 else 0, '')

print('=== TRANSCRIPT cap115: primeiros 40 C2S (t, op/b1, tag) ===')
for t, f in C2S[:40]:
    print('  %7.2f  %02x/%02x  %s  len=%d' % (t, f[0], f[1] if len(f) > 1 else 0, tag(f)[2], len(f)))

# respostas reais aos 5d/02 com tag 6c42 (o polling do 99%)
print('\n=== TRANSCRIPT: 5d/02 tag 6c42 (n=%d) e as respostas S2C que seguiram (janela 2s) ===' %
      sum(1 for t, f in C2S if f[0] == 0x5d and f[2:4].hex() == '6c42'))
for i, (t, f) in enumerate(C2S):
    if f[0] == 0x5d and len(f) > 3 and f[2:4].hex() == '6c42':
        nxt = [(t2, f2) for t2, d2, f2 in frames if d2 == 'S>C' and t <= t2 <= t + 2.0]
        s = ' | '.join('%02x/%02x %s len=%d' % (f2[0], f2[1], f2[2:4].hex(), len(f2)) for t2, f2 in nxt[:3])
        print('  t=%7.2f req b1=%02x body=%s -> resp: %s' % (t, f[1], f[:12].hex(), s))

# sessão do mock: sequência RX
for sess in sorted(glob.glob('/home/re/work/apk/mock_sessions/sess_*.txt')):
    print('\n=== SESSÃO MOCK %s ===' % sess.split('/')[-1])
    rxs = re.findall(r'^\[RX\] ([0-9a-f]+)', open(sess).read(), re.M)
    print('total RX:', len(rxs))
    seq = []
    for h in rxs:
        f = bytes.fromhex(h)
        seq.append((f[0], f[1] if len(f) > 1 else 0, f[2:4].hex() if len(f) > 3 else '', len(f)))
    c = collections.Counter((a, b, t2) for a, b, t2, _ in seq)
    print('censo (op,b1,tag):')
    for k, v in c.most_common(15):
        print('   %02x/%02x %-6s x%d' % (k[0], k[1], k[2], v))
    print('sequência (primeiros 30):')
    for a, b, t2, l in seq[:30]:
        print('   %02x/%02x %s len=%d' % (a, b, t2, l))
