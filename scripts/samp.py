import sys,collections
from parse import *
def hexa(b,n=96): return b[:n].hex(' ')
lt,n,S=streams('cap_combat2.pcap')
allf=[]
for k,segs in S.items():
    buf,ts,_,_=reasm(segs);F,_,_=frames(buf)
    d='C>S' if k[3]==30101 else 'S>C'
    for o,f in F: allf.append((d,o,f))
want=collections.OrderedDict()
for d,o,f in allf: want.setdefault((d,f[0],f[1]),[]).append(f)
for k,L in want.items():
    print('==%s %02x/%02x n=%d'%(k[0],k[1],k[2],len(L)))
    seen=set()
    for f in L[:3]+sorted(L,key=len)[-1:]:
        if f in seen: continue
        seen.add(f); print('  len',len(f),hexa(f))
    print('  distinct',len(set(L)))
