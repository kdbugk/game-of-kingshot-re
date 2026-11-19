#!/usr/bin/env python3
import struct, sys, json, os
VER=sys.argv[1]
KEYHEX=open(f"/mnt/c/Users/prs/work/laneI/key1152_{VER}.hex").read().strip(); key=bytes.fromhex(KEYHEX)
PATH={"114":"/home/re/work/apk/xapk/base_extract/assets/bin/Data/Managed/Metadata/global-metadata.dat",
      "195":"/home/re/work/apk/xapk195/base_extract/assets/bin/Data/Managed/Metadata/global-metadata.dat"}[VER]
raw=open(PATH,"rb").read()[8:]
n=len(raw)
reps=n//1152+1
k=(key*reps)[:n]
dec=(int.from_bytes(raw,'little')^int.from_bytes(k,'little')).to_bytes(n,'little')
open(f"/tmp/meta_dec_{VER}.bin","wb").write(dec)
U=lambda o:struct.unpack_from("<I",dec,o)[0]
pairs=[struct.unpack_from("<II",dec,8+i*8) for i in range(15,30)]
TD_OFF,TD_SZ=pairs[3]; IMG_OFF,IMG_SZ=pairs[4]
NT=pairs[0]
TD_N=TD_SZ//88; IMG_N=IMG_SZ//40
print("typeDefs",TD_N,"images",IMG_N, TD_SZ%88, IMG_SZ%40)
mod=dec.find(b"<Module>\0"); assert dec.count(b"<Module>\0")==1
best=None
for sh in (0,-8,8,-4,4):
    t=TD_OFF+sh
    nm=U(t)
    if U(t+84)==0x02000001:
        best=sh
print("td shift",best)
TD=TD_OFF+best
SO=mod-U(TD)
print("string start",hex(SO), dec[SO:SO+20])
def S(i):
    e=dec.index(b"\0",SO+i); return dec[SO+i:e].decode("utf8","replace")
IM=TD+TD_N*88
rows=[struct.unpack_from("<10i",dec,IM+i*40) for i in range(IMG_N)]
ssum=sum(r[3] for r in rows)
print("sum typeCount",ssum,"== typedefs",TD_N, "contig",all(rows[i][2]+rows[i][3]==rows[i+1][2] for i in range(IMG_N-1)))
tds=[struct.unpack_from("<22i",dec,TD+i*88) for i in range(TD_N)]
def find_methods():
    first=None
    for i,t in enumerate(tds):
        mc=t[16]&0xffff
        if mc>0 and t[9]==0: first=i;break
    print("first typedef with methods",first,S(tds[first][0]))
    cands=[]
    p=0
    while True:
        p=dec.find(b"\x01\x00\x00\x06",p+1)
        if p<0:break
        m=p-24
        if m<0:continue
        if U(m+4)==first and U(m+36+24)==0x06000002 and U(m+72+24)==0x06000003:
            cands.append(m)
    return first,cands
first,cands=find_methods()
print("method cands",[hex(c) for c in cands])
MS=cands[0]
bad=0;tot=0
for i,t in enumerate(tds):
    mc=t[16]&0xffff
    for j in range(mc):
        o=MS+(t[9]+j)*36
        tot+=1
        if U(o+4)!=i: bad+=1
print("method declaring mismatches",bad,"of",tot)
nested_total=sum((t[18]&0xffff) for t in tds)
nestedbase=NT[0]-8-4*nested_total
bad=0
for i,t in enumerate(tds):
    for j in range(t[18]&0xffff):
        v=U(nestedbase+(t[12]+j)*4)
        if not(v<TD_N and (tds[v][7]&7)>=2): bad+=1
print("nested total",nested_total,"bad",bad)
parent={}
if nestedbase is not None:
    for i,t in enumerate(tds):
        c=t[18]&0xffff
        for j in range(c):
            parent[U(nestedbase+(t[12]+j)*4)]=i
def tname(i):
    t=tds[i]; nm=S(t[0]); ns=S(t[1])
    if i in parent:
        return tname(parent[i])+"/"+nm
    return (ns+"." if ns else "")+nm
outdir=f"/home/re/work/apk/il2cpp_dump_{VER}"; os.makedirs(outdir,exist_ok=True)
for f in os.listdir(outdir): os.remove(os.path.join(outdir,f))
names=[]
for ii,r in enumerate(rows):
    nm=S(r[0])
    if not nm.endswith(".dll") and nm!="__Generated": nm+=".dll"
    classes=[]
    for i in range(r[2],r[2]+r[3]):
        t=tds[i]; mc=t[16]&0xffff
        meths=[]
        for j in range(mc):
            o=MS+(t[9]+j)*36
            meths.append({"name":S(U(o)),"flags":"0x%x"%struct.unpack_from("<H",dec,o+28)[0],"params":struct.unpack_from("<H",dec,o+34)[0]})
        classes.append({"name":S(t[0]),"namespace":S(t[1]),"fullName":tname(i),"flags":"0x%x"%(t[7]&0xffffffff),"nested":i in parent,"fieldCount":struct.unpack_from("<H",dec,TD+i*88+68)[0],"methods":meths})
    json.dump({"name":nm,"classes":classes},open(f"{outdir}/{ii:03d}_{nm}.json","w"),ensure_ascii=False)
    names.append((nm,len(classes)))
print(names[:5],len(names))
