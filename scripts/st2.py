import collections
from parse import *
lt,n,S=streams('cap_combat2.pcap')
fr=collections.defaultdict(list)
for k,segs in S.items():
    d='C>S' if k[3]==30101 else 'S>C'
    buf,_,_,_=reasm(segs);F,_,_=frames(buf)
    for o,f in F: fr[(d,f[0],f[1])].append(f)
for k in [('C>S',0x35,2)]:
    print('35/02 byte2 hist',collections.Counter(f[2] for f in fr[k]))
    print('35/02 id (varint16) sample',[ (f[3]|f[4]<<7) for f in fr[k][:12]])
for k in [('C>S',0x7d,2)]:
    L=fr[k]; print('7d/02 bytes2-3',collections.Counter(f[2:4].hex() for f in L).most_common(5)); print('len hist',sorted(collections.Counter(len(f) for f in L).items())[:25])
    print('byte6..8 (cmd?)',collections.Counter(f[6:8].hex() for f in L).most_common(12))
    print('last 4 bytes',collections.Counter(f[-4:].hex() for f in L).most_common(8))
L=fr[('S>C',0x75,2)]; print('75/02 len hist',sorted(collections.Counter(len(f) for f in L).items()))
print('75/02 byte5+ small kinds',collections.Counter(f[5:8].hex() for f in L if len(f)<40).most_common(15))
big=[f for f in L if len(f)>500]; print('big count',len(big),[len(f) for f in big][:20])
f=big[0]
import re
# split on embedded '55 02 01 NN' envelopes
print([ (m.start(),f[m.start()+3]) for m in re.finditer(b'\x55\x02\x01',f)][:12])
print(f[:120].hex(' '))
print(f[3000:3063].hex(' '))
