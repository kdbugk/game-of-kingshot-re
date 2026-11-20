#!/usr/bin/env python3
"""build_catalog.py — destila o catálogo de comandos reais das capturas:
transcript115 (login) + frames.pkl (combate) + mock_live.log (gameplay no mock).
Saída: catalog.json {comando: {args: {...}, n: observacoes, fonte}}"""
import sys, os, json, pickle, re
sys.path.insert(0, '/home/re/work/apk')
import sproto_lib as L

S = L.default_schema()
cat = {}

def add(name, obj, fonte):
    e = cat.setdefault(name, {"args": obj, "n": 0, "fonte": fonte})
    e["n"] += 1

# 1) transcript do login (cap115)
P = L.Peer(S)
for t, d, raw in pickle.load(open('/home/re/work/apk/gw_transcript115.pkl', 'rb')):
    if d != 'C>S': continue
    try: m = P.parse(raw, d)
    except Exception: continue
    add(m['name'], m['obj'], 'cap115')

# 2) sessao de combate (cap_combat2 via kind03/frames.pkl)
P2 = L.Peer(S)
for t, d, raw in pickle.load(open('/mnt/c/Users/prs/work/kind03/frames.pkl', 'rb')):
    if d != 'C>S': continue
    try: m = P2.parse(raw, d)
    except Exception: continue
    add(m['name'], m['obj'], 'combat')

# 3) gameplay no mock (log com nome + payload)
for ln in open('/home/re/work/apk/mock_live.log', encoding='utf8', errors='replace'):
    m = re.match(r'\[RX #\d+\] (\S+) s=\d+ (\{.*)', ln.strip())
    if not m: continue
    name, j = m.group(1), m.group(2)
    try: obj = json.loads(j)
    except Exception: continue
    add(name, obj, 'mock_live')

json.dump(cat, open('/home/re/work/apk/catalog.json', 'w', encoding='utf8'), ensure_ascii=False, indent=1)
print('catalogo:', len(cat), 'comandos distintos')
top = sorted(cat.items(), key=lambda kv: -kv[1]['n'])[:20]
for n, e in top:
    print('  %-42s n=%-3d fonte=%s' % (n, e['n'], e['fonte']))
