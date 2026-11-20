import sys,collections
from parse import *
for path in sys.argv[1:]:
    lt,n,S=streams(path); print('==',path,'lt',lt,'pkts',n,'trunc',TR)
    for k,segs in S.items():
        buf,ts,dup,gap=reasm(segs)
        F,err,rest=frames(buf)
        c=collections.Counter((f[0],f[1]) for o,f in F)
        print(k[1],'->',k[3],'segs',len(segs),'bytes',len(buf),'frames',len(F),'err',err,'rest',rest,'dup',dup,'gap',gap)
        print('  ',{'%02x/%02x'%a:b for a,b in sorted(c.items())})
