import collections
from parse import *
lt,n,S=streams('cap_combat2.pcap')
fr=collections.defaultdict(list)
for k,segs in S.items():
    d='C>S' if k[3]==30101 else 'S>C'
    buf,_,_,_=reasm(segs);F,_,_=frames(buf)
    for o,f in F: fr[(d,f[0],f[1])].append(f)
B=fr[('C>S',0x3d,3)]; big=[f for f in B if len(f)==2462]; sm=[f for f in B if len(f)==16]; mid=[f for f in B if len(f)==30]
print('big',len(big),'16B',len(sm),'30B',len(mid))
a,b=big[0],big[1]
dif=[i for i in range(len(a)) if a[i]!=b[i]]; print('diff positions big0 vs big1:',len(dif),dif[:40])
allb=big; var=[i for i in range(2462) if len(set(f[i] for f in allb))>1]; print('variable positions across',len(big),':',len(var),var[:50])
print('big0 head 64:',a[:64].hex(' ')); print('big0 tail 64:',a[-64:].hex(' '))
print('byte hist top',collections.Counter(a[6:]).most_common(8))
# 4-byte period?
for p in (4,5,6,8):
    print('period',p,'repeat frac',sum(a[i]==a[i+p] for i in range(6,len(a)-p))/(len(a)-6-p))
print('16B frames:'); [print(' ',f.hex(' ')) for f in sm[:4]]
R=fr[('S>C',0x35,3)]
print('27B resp:'); [print(' ',f.hex(' ')) for f in R if len(f)==27][:3] ; print([f.hex(' ') for f in R if len(f)==27][:3])
print('30B req:',mid[0].hex(' ')); print('264B resp:',[f for f in R if len(f)==264][0].hex(' '))
print('16B resp(for big):',[f for f in R if len(f)==16][0].hex(' '))
cap=lambda f:bytes(c if 32<=c<127 else 46 for c in f)
print(cap(big[0][:200]).decode())
