import sys,collections
from parse import *
def load(p):
    lt,n,S=streams(p);out=[]
    for k,segs in S.items():
        buf,_,_,_=reasm(segs);F,err,rest=frames(buf)
        d='C>S' if k[3]==30101 else 'S>C'
        out+=[(d,f) for o,f in F]
        print(p,k,'frames',len(F),'err',err,'rest',rest,file=sys.stderr)
    return out
def census(fr):
    c=collections.defaultdict(list)
    for d,f in fr: c[(d,f[0],f[1])].append(len(f))
    return c
if __name__=='__main__':
    cur=census(load(sys.argv[1])); base=census(load('../laneX/cap115.pcap')); old=census(load('C:/Users/prs/projects/game-of-kingshot-re/captures/battle2.pcap'))
    print('| dir | op/b1 | combate | cap115 | 1.9.5 battle2 |\n|--|--|--|--|--|')
    f=lambda L:'%d (%d–%d)'%(len(L),min(L),max(L)) if L else '0'
    for k in sorted(set(cur)|set(base)|set(old)):
        print('| %s | %02x/%02x | %s | %s | %s |'%(k[0],k[1],k[2],f(cur.get(k,[])),f(base.get(k,[])),f(old.get(k,[]))))
    for k in [(d,o,b) for (d,o,b) in cur if (o,b) in [(0x19,3),(0x1d,3),(0x35,2),(0x7d,2),(0x25,2),(0x3d,2),(0x79,2)]]:
        pass
