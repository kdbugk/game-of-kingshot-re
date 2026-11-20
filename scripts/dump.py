from parse import *
import sys
lt,n,S=streams('cap115.pcap')
allf=[]
for k,segs in S.items():
    buf,ts,dup,gap=reasm(segs)
    F,err,rest=frames(buf)
    d='C>S' if k[3]==30101 else 'S>C'
    import bisect
    offs=[t[0] for t in ts]
    for o,f in F:
        j=bisect.bisect_right(offs,o+len(f)+1)-1
        allf.append((ts[max(j,0)][1],d,f))
allf.sort(key=lambda x:x[0])
t0=allf[0][0]
for i,(t,d,f) in enumerate(allf):
    print(i,'%.3f'%(t-t0),d,len(f),f[:40].hex())
