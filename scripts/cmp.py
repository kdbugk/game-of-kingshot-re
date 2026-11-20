import collections,bisect
from parse import *
def load(p):
    lt,n,S=streams(p);ev=[]
    for k,segs in S.items():
        d='C>S' if k[3]==30101 else 'S>C'
        buf,ta,_,_=reasm(segs);F,_,_=frames(buf);offs=[a[0] for a in ta]
        for o,f in F:
            i=bisect.bisect_right(offs,o+len(f)+1)-1; ev.append((ta[max(i,0)][1],d,f))
    ev.sort(key=lambda x:x[0]);return ev
old=load('C:/Users/prs/projects/game-of-kingshot-re/captures/battle2.pcap'); t0=old[0][0]
print('== 1.9.5 battle2 samples')
for want in [(0x35,2),(0x3d,2),(0x25,2),(0x79,2),(0x65,2),(0x6d,2)]:
    L=[(t,d,f) for t,d,f in old if (f[0],f[1])==want]
    print('%02x/%02x n=%d'%(want[0],want[1],len(L)))
    for t,d,f in L[:4]: print('  t=%.1f %s len %d %s'%(t-t0,d,len(f),f[:40].hex(' ')))
L=[(t,d,f) for t,d,f in old if (f[0],f[1])==(0x7d,2)]
print('7d/02 n',len(L))
for t,d,f in L[:6]: print('  t=%.1f len %d %s'%(t-t0,len(f),f[:40].hex(' ')))
new=load('cap_combat2.pcap'); n0=new[0][0]
print('== new: 7d/02 time-ordered with len & head')
for t,d,f in new:
    if (f[0],f[1])==(0x7d,2) and len(f)>40: print('  t=%.1f len %d %s'%(t-n0,len(f),f.hex(' ')[:190]))
print('big 75/02 t=',[round(t-n0,1) for t,d,f in new if len(f)>1000])
print('dd/01 t:',[round(t-n0,1) for t,d,f in new if f[0]==0xdd][:30])
print('first dd/01', [f.hex(' ') for t,d,f in new if f[0]==0xdd][:6])
print('== cmd tags')
by=collections.defaultdict(list)
for t,d,f in new:
    if d=='C>S' and (f[0],f[1])==(0x7d,2): by[f[2:4].hex()].append((round(t-n0,1),f))
for k,L in by.items():
    print(k,len(L),'t',L[0][0],'..',L[-1][0],'lens',sorted(set(len(f) for t,f in L)))
    for t,f in L[:2]: print('   ',f.hex(' '))
print('old tags',collections.Counter(f[2:4].hex() for t,d,f in old if d=='C>S' and (f[0],f[1])==(0x7d,2)))
# response for e815 / 6c42 
