import sys,glob,os
def uleb(b,p):
    r=0;s=0
    while True:
        c=b[p];p+=1;r|=(c&0x7f)<<s;s+=7
        if c<0x80:return r,p
def extract(b):
    res=[]
    # find longest utf8 string constants: scan for ".item {" etc
    i=b.find(b'\n.')
    best=None
    for m in range(0,min(len(b),200)):
        try:
            v,p=uleb(b,m)
        except IndexError:break
        L=v-5
        if 1000<L<len(b) and p+L<=len(b) and b[p:p+1] in(b'\n',b'.') :
            try: b[p:p+L].decode('utf8');return b[p:p+L].decode('utf8'),m
            except: pass
    return None,None
for f in sys.argv[1:]:
    b=open(f,'rb').read(); t,m=extract(b)
    print(f,len(b),m,None if t is None else len(t))
    if t: open(f.replace('.bin','.sproto'),'w',encoding='utf8').write(t)
