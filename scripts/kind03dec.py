#!/usr/bin/env python3
"""Decoder experimental do canal kind 03 (Kingshot 1.14.27). Uso: python kind03dec.py [pkl]
Camadas: [hdr C>S: 3d 03 tag16 id16 | S>C: 35 03 01 id16][51 06 02 04][corpo]
corpo = (token 2B 'flag,n' ) + stream XOR com chave periodica de 4B (b9 24 5f bd) + tokens 2B inseridos
 (ff 00 / ff 1d / fd 64 ...) que NAO entram no stream (fase do XOR continua). Dentro: little-endian, BinaryWriter-like."""
import pickle,struct,sys
K=bytes([0xb9,0x24,0x5f,0xbd])
class Dec:
    def __init__(s,b): s.b=b;s.i=0;s.ph=0;s.tokens=[]
    def tok(s):
        s.tokens.append((s.i,bytes(s.b[s.i:s.i+2])));s.i+=2
    def take(s,n,tok_ok=False):
        if s.i+n>len(s.b): raise EOFError
        o=bytes(c^K[(s.ph+j)%4] for j,c in enumerate(s.b[s.i:s.i+n]));s.i+=n;s.ph=(s.ph+n)%4;return o
    def peek(s,n,skip=0):
        if s.i+skip+n>len(s.b): return None
        return bytes(c^K[(s.ph+j)%4] for j,c in enumerate(s.b[s.i+skip:s.i+skip+n]))
    def expect(s,pred,n):
        """le n bytes; se pred falha, tenta pular um token de 2B (inserido) antes"""
        for sk in (0,2):
            p=s.peek(n,sk)
            if p is not None and pred(p):
                if sk: s.tok()
                return s.take(n)
        raise ValueError('sync@%d'%s.i)
def split(f):
    d='C>S' if f[0]==0x3d else 'S>C'
    if d=='C>S': return dict(dir=d,tag=f[2:4],id=struct.unpack('<H',f[4:6])[0],magic=f[6:10],body=f[10:])
    return dict(dir=d,tag=None,id=struct.unpack('<H',f[3:5])[0],magic=f[5:9],body=f[9:])
def decode(f):
    m=split(f); b=m['body']; r=dict(m)
    # prefixo: flag,n (2B) ou ff ff 1a 13 (snapshot) ou 3f 1a 13 (ack do snapshot)
    if b[:4]==b'\xff\xff\x1a\x13': pre=b[:4]
    elif b[:3]==b'\x3f\x1a\x13': pre=b[:3]
    else: pre=b[:2]
    r['prefix']=pre.hex(' '); D=Dec(b); D.i=len(pre)
    if len(f)>2000:   # snapshot 2462
        h=D.take(12); ver,ln,cnt=struct.unpack('<III',h)
        r.update(ver=ver,declen=ln,cnt=cnt)
        D.take(2)               # 00 00
        l4=struct.unpack('<I',D.take(4))[0]; r['field4']=D.take(l4).hex()
        rl=struct.unpack('<I',D.take(4))[0]; r['reclen']=rl
        recs=[];used=0
        while used+78<=rl:
            sz=struct.unpack('<I',D.expect(lambda p:struct.unpack('<I',p)[0]==74,4))[0]
            typ=struct.unpack('<H',D.take(2))[0]; idx=struct.unpack('<I',D.take(4))[0]; z=D.take(8)
            ds=[]
            for _ in range(5):
                l=struct.unpack('<I',D.expect(lambda p:struct.unpack('<I',p)[0]==8,4))[0]
                ds.append(struct.unpack('<d',D.take(8))[0])
            recs.append(dict(type=typ,idx=idx,z=z.hex(),d=ds)); used+=78
        r['records']=recs; r['tail']=D.peek(len(b)-D.i).hex() if D.i<len(b) else ''
        r['tokens']=D.tokens
    else:
        # frames pequenos: u16/u32 LE (+ token 'ff nn' apos 6B) ; ficam como bytes plain com tokens marcados
        out=bytearray()
        rest=len(b)-D.i
        if pre[:1] in (b'\xfd',b'\xff') and len(f)>=27 or len(f)==30:
            out+=D.take(6); D.tok(); out+=D.take(len(b)-D.i)
        else: out+=D.take(len(b)-D.i)
        r['plain']=bytes(out).hex(' '); r['tokens']=D.tokens
    return r
if __name__=='__main__':
    F=pickle.load(open(sys.argv[1] if len(sys.argv)>1 else 'frames.pkl','rb'))
    for t,d,f in F:
        if f[1]!=3: continue
        try: r=decode(f)
        except Exception as e: print(t,d,len(f),'ERR',e); continue
        if 'records' in r:
            print(f"{t:7.2f} {d} {len(f)} id={r['id']} ver={r['ver']} declen={r['declen']} cnt={r['cnt']} reclen={r['reclen']} nrec={len(r['records'])} tokens={[(i,x.hex()) for i,x in r['tokens']]} tail={r['tail']}")
        else: print(f"{t:7.2f} {d} {len(f)} id={r['id']} pre={r['prefix']} plain={r['plain']} tok={[(i,x.hex()) for i,x in r['tokens']]}")
