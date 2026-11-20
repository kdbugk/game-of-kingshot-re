import sys,collections
from parse import *
def getall(p):
    lt,n,S=streams(p);out=[]
    for k,segs in S.items():
        d='C>S' if k[3]==30101 else 'S>C'
        t0=segs[0][0]
        buf,ts,_,_=reasm(segs);F,_,_=frames(buf)
        out.append((d,k,segs[0][2],segs[0][1],t0,F,segs))
    return out
for d,k,fl,seq,t0,F,segs in getall('cap_combat2.pcap'):
    print(d,k[1],k[3],'firstflags',fl,'nsegs',len(segs),'t',round(segs[0][0],2),round(segs[-1][0],2),'first frame',F[0][1][:8].hex(' '))
