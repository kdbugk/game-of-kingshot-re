import collections,statistics
from parse import *
lt,n,S=streams('cap_combat2.pcap')
ev=[]
for k,segs in S.items():
    d='C>S' if k[3]==30101 else 'S>C'
    buf,ta,_,_=reasm(segs);F,_,_=frames(buf)
    import bisect
    offs=[a[0] for a in ta]
    for o,f in F:
        i=bisect.bisect_right(offs,o+2+len(f)-1)-1  # segment containing last byte
        ev.append((ta[max(i,0)][1],d,f))
ev.sort(key=lambda x:x[0]); t0=ev[0][0]
def vi(b,o):
    v=0;s=0
    while True:
        c=b[o];o+=1;v|=(c&0x7f)<<s;s+=7
        if not c&0x80:return v,o
req={};res=[]
for t,d,f in ev:
    op=(f[0],f[1])
    if d=='C>S':
        if op==(0x35,2): rid=vi(f,3)[0]; 
        elif op in((0x7d,2),(0x3d,3),(0x6d,2)): rid=vi(f,4)[0] if op!=(0x3d,3) else vi(f,4)[0]
        elif op==(0x3d,2): rid=None
        else: rid=None
        req.setdefault(rid,[]).append((t-t0,op,len(f)))
    else:
        if op in((0x75,2),(0x35,3),(0x65,2)): rid=vi(f,3)[0]; res.append((t-t0,op,rid,len(f)))
print('events',len(ev),'dur',round(ev[-1][0]-t0,1))
m=0;lat=collections.defaultdict(list)
for t,op,rid,L in res:
    if rid in req:
        m+=1; r=req[rid][0]; lat[(r[1],op)].append(t-r[0])
print('responses',len(res),'matched by id',m)
for k,v in lat.items(): print('%02x/%02x -> %02x/%02x'%(k[0]+k[1]),'n',len(v),'lat med %.3f min %.3f max %.3f'%(statistics.median(v),min(v),max(v)))
# id sequence
ids=sorted(r for r in req if r is not None); print('ids range',ids[0],ids[-1],'n',len(ids)); print('step hist',collections.Counter(b-a for a,b in zip(ids,ids[1:])).most_common(6))
# timeline per 30s
b=collections.Counter()
for t,d,f in ev: b[(int((t-t0)//60),d,'%02x/%02x'%(f[0],f[1]))]+=1
for k in sorted(b): print(k,b[k])
# 3d/03 vs 35/03 timing
for t,d,f in ev:
    if (f[0],f[1]) in((0x3d,3),(0x35,3),(0x3d,2),(0x6d,2),(0x65,2),(0x55,1)): print(round(t-t0,2),d,'%02x/%02x'%(f[0],f[1]),len(f),f[:14].hex(' '))
