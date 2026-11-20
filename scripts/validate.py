import pickle,struct,collections
from kind03dec import *
F=pickle.load(open('frames.pkl','rb'))
def xor(b,ph=0): return bytes(c^K[(ph+j)%4] for j,c in enumerate(b))
def encode(r,f):
    hdr=f[:10] if r['dir']=='C>S' else f[:9]
    pre=bytes.fromhex(r['prefix'])
    if 'records' in r:
        p=struct.pack('<III',r['ver'],r['declen'],r['cnt'])+b'\0\0'+struct.pack('<I',len(bytes.fromhex(r['field4'])))+bytes.fromhex(r['field4'])+struct.pack('<I',r['reclen'])
        for q in r['records']:
            p+=struct.pack('<IHI',74,q['type'],q['idx'])+bytes.fromhex(q['z'])+b''.join(struct.pack('<Id',8,x) for x in q['d'])
        p+=bytes.fromhex(r['tail'])
    else: p=bytes.fromhex(r['plain'])
    body=bytearray(); ph=0; pos=0; toks=dict(r['tokens'])
    # tokens sao dados por indice no corpo cifrado (offset), insere quando chega
    out=bytearray(pre); cp=0
    tk=sorted(r['tokens'])
    for i in range(len(p)):
        while tk and len(out)==tk[0][0]: out+=tk.pop(0)[1]
        out.append(p[i]^K[i%4])
    while tk and len(out)==tk[0][0]: out+=tk.pop(0)[1]
    return hdr+bytes(out)
ok=collections.Counter()
for t,d,f in F:
    if f[1]!=3: continue
    r=decode(f); e=encode(r,f); k='big' if len(f)>2000 else ('264' if len(f)==264 else 'small'); ok[(k,e==f)]+=1
    if e!=f and k=='small': print(f.hex(' '),'\n',e.hex(' '))
print(ok)
# invariantes
inv=[]
for t,d,f in F:
    if f[1]==3 and len(f)>2000:
        r=decode(f); inv.append((r['declen']+12==len(f)-10-4, r['reclen']==78*len(r['records'])))
print('declen+12==body-after-prefix, reclen==78*n',collections.Counter(inv))
