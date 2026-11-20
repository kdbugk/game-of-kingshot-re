import re,struct
def tokenize(t):
    t=re.sub(r'#[^\n]*','',t)
    return re.findall(r'[{}:*()]|[^\s{}:*()]+',t)
def parse(text):
    tk=tokenize(text);i=0;types={};protos={}
    def parse_fields(owner):
        nonlocal i
        fields=[]
        while tk[i]!='}':
            if tk[i]=='.':pass
            if tk[i].startswith('.'):
                nm=tk[i][1:];i+=1
                assert tk[i]=='{';i+=1
                sub=parse_fields(owner+'.'+nm);i+=1
                types[owner+'.'+nm]=sub;continue
            name=tk[i];i+=1
            tag=int(tk[i]);i+=1
            assert tk[i]==':',(name,tk[i-3:i+3]);i+=1
            arr=False
            if tk[i]=='*':arr=True;i+=1
            ty=tk[i];i+=1;key=None;dec=None
            if i<len(tk) and tk[i]=='(':
                i+=1
                if tk[i]==')':key='';i+=1
                else:key=tk[i];i+=1;assert tk[i]==')';i+=1
            fields.append(dict(name=name,tag=tag,type=ty,arr=arr,key=key,owner=owner))
        return sorted(fields,key=lambda f:f['tag'])
    while i<len(tk):
        nm=tk[i];i+=1
        if nm.startswith('.'):
            assert tk[i]=='{';i+=1
            types[nm[1:]]=parse_fields(nm[1:]);i+=1
        else:
            tag=int(tk[i]);i+=1;assert tk[i]=='{';i+=1
            p={'tag':tag,'request':None,'response':None}
            while tk[i]!='}':
                kind=tk[i];i+=1
                if tk[i]=='{':
                    i+=1;p[kind]=parse_fields(nm+'.'+kind);i+=1
                else:
                    p[kind]=tk[i];i+=1
            i+=1;protos[nm]=p
    return types,protos
def unpack(b):
    out=bytearray();i=0
    while i<len(b):
        h=b[i];i+=1
        if h==0xff:
            n=b[i]+1;i+=1
            out+=b[i:i+n*8];i+=n*8
        else:
            for k in range(8):
                if h>>k&1:out.append(b[i]);i+=1
                else:out.append(0)
    return bytes(out)
class Dec:
    def __init__(s,types):s.types=types
    def resolve(s,ty,owner):
        if ty in('integer','string','boolean','double','binary'):return ty
        o=owner
        while True:
            c=o+'.'+ty if o else ty
            if c in s.types:return c
            if '.' not in o:break
            o=o.rsplit('.',1)[0]
        if ty in s.types:return ty
        raise KeyError((ty,owner))
    def struct(s,fields,b,p=0):
        fc=struct.unpack_from('<H',b,p)[0];hp=p+2;dp=hp+fc*2;tag=0;res={};pend=[]
        for k in range(fc):
            v=struct.unpack_from('<H',b,hp+k*2)[0]
            if v%2==1:tag+=(v+1)//2;continue
            f=next((f for f in fields if f['tag']==tag),None)
            if v==0:pend.append((tag,f))
            else:
                if f: res[f['name']]=s.scalar(f,v//2-1)
            tag+=1
        for tag,f in pend:
            ln=struct.unpack_from('<I',b,dp)[0];data=b[dp+4:dp+4+ln];dp+=4+ln
            if f is None:res['?%d'%tag]=data.hex();continue
            res[f['name']]=s.data(f,data)
        return res,dp
    def scalar(s,f,v):
        if f['type']=='boolean':return bool(v)
        return v
    def data(s,f,d):
        ty=s.resolve(f['type'],f['owner'])
        if f['arr']:
            if ty in('integer','boolean','double'):
                if not d:return []
                sz=d[0];return [int.from_bytes(d[1+k:1+k+sz],'little',signed=True) for k in range(0,len(d)-1,sz)]
            r=[];p=0
            while p<len(d):
                ln=struct.unpack_from('<I',d,p)[0];e=d[p+4:p+4+ln];p+=4+ln
                r.append(e.decode('utf8','replace') if ty=='string' else (e.hex() if ty=='binary' else s.struct(s.types[ty],e)[0]))
            return r
        if ty=='integer':return int.from_bytes(d,'little',signed=True)
        if ty=='double':return struct.unpack('<d',d)[0]
        if ty=='string':return d.decode('utf8','replace')
        if ty=='binary':return d.hex()
        return s.struct(s.types[ty],d)[0]
