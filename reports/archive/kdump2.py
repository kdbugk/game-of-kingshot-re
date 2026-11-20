#!/usr/bin/env python3
"""kdump2 - v24-obfuscated global-metadata FULL dumper (fields/params/returns + method RVAs from binary).
usage: kdump2.py 114|195   (needs /tmp/meta_dec_{VER}.bin from kdump.py)"""
import sys,json,glob,collections,struct,os
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from lib import *
VER=sys.argv[1]
OUT="/home/re/work/apk"
M=Meta(VER)
raw=open(BIN[VER],"rb").read()
w8=np.frombuffer(raw,dtype=np.uint8); w=w8[:len(w8)//8*8].view("<u8")
CODE_END=0x1612f04+0x279be1c if VER=="195" else 0x1724f14+0x29e04ec
# ---- module bases
if VER=="114":
    bases,_,_=assign_114(M,raw,w)
else:
    bases=assign_names(M,w,raw[:0x1612f04])
print("modules assigned",len(bases))
imgcnt={ii:sum(M.tds[t][16]&0xffff for t in range(M.imgs[ii][2],M.imgs[ii][2]+M.imgs[ii][3])) for ii in range(M.IMG_N)}
def rva(ii,rid):
    b=bases.get(ii)
    if b is None or rid<1 or rid>imgcnt[ii]: return None
    v=int(w[(b+(rid-1)*8)//8])
    if 0<v<CODE_END: return v
    return None
# ---- old dump oracle (1.9.5 runtime dump) for type names
OLD={}
for f in sorted(glob.glob("/mnt/c/Users/prs/projects/game-of-kingshot-re/il2cpp_dump/*.json")):
    j=json.load(open(f)); OLD[j["name"]]=j
tn={}
for i,t in enumerate(M.tds):
    for k in (2,5):
        if t[k]>=0 and t[k] not in tn: tn[t[k]]=M.tname(i)
votes=collections.defaultdict(collections.Counter)
def aname(ii):
    n=M.imgname(ii); return n if n.endswith(".dll") else n+".dll"
oldcls={}
for ii in range(M.IMG_N):
    old=OLD.get(aname(ii))
    if not old: continue
    d=collections.defaultdict(list)
    for c in old["classes"]: d[c["fullName"]].append(c)
    oldcls[ii]=d
def match_methods(ms,oms):
    """index-aligned if names equal elementwise, else None"""
    if len(ms)!=len(oms): return None
    for a,b in zip(ms,oms):
        if a["name"]!=b["name"] or a["pc"]!=len(b["params"]): return None
    return list(zip(ms,oms))
for ii in range(M.IMG_N):
    d=oldcls.get(ii)
    if not d: continue
    r=M.imgs[ii]
    for i in range(r[2],r[2]+r[3]):
        cl=d.get(M.tname(i))
        if not cl or len(cl)!=1: continue
        oc=cl[0]
        fs=M.fields(i)
        if [f["name"] for f in fs]==[f["name"] for f in oc["fields"]]:
            for f,o in zip(fs,oc["fields"]): votes[f["type"]][o["type"]]+=1
        pr=match_methods(M.methods(i),oc["methods"])
        if pr:
            for m,o in pr:
                votes[m["ret"]][o["ret"]]+=1
                ps=M.params(m)
                if len(ps)==len(o["params"]):
                    for p,op in zip(ps,o["params"]): votes[p["type"]][op["type"]]+=1
if VER=="114":
    N195={}
    for f in glob.glob(OUT+"/il2cpp_full_195/*.json"):
        j=json.load(open(f)); d=collections.defaultdict(list)
        for c in j["classes"]: d[c["fullName"]].append(c)
        N195[j["name"]]=d
    for ii in range(M.IMG_N):
        d=N195.get(aname(ii))
        if not d: continue
        r=M.imgs[ii]
        for i in range(r[2],r[2]+r[3]):
            cl=d.get(M.tname(i))
            if not cl or len(cl)!=1: continue
            oc=cl[0]; fs=M.fields(i)
            if [f["name"] for f in fs]==[f["name"] for f in oc["fields"]]:
                for f,o in zip(fs,oc["fields"]):
                    if not o["type"].startswith("T#"): votes[f["type"]][o["type"]]+=1
            ms=M.methods(i)
            if len(ms)==len(oc["methods"]) and all(a["name"]==b["name"] and a["pc"]==len(b["params"]) for a,b in zip(ms,oc["methods"])):
                for m,o in zip(ms,oc["methods"]):
                    if not o["ret"].startswith("T#"): votes[m["ret"]][o["ret"]]+=1
                    for p,op in zip(M.params(m),o["params"]):
                        if not op["type"].startswith("T#"): votes[p["type"]][op["type"]]+=1
vt={}
for k,c in votes.items():
    if k in tn: continue
    best,n=c.most_common(1)[0]; vt[k]=(best,n,sum(c.values()))
def T(k):
    if k in tn: return tn[k]
    if k in vt: return vt[k][0]
    return "T#%d"%k if k>=0 else "?"
print("type names: typedef-derived",len(tn),"oracle-voted",len(vt))
def acc(fl):
    return {1:"private",2:"protected internal" if False else "private protected",3:"internal",4:"protected",5:"protected internal",6:"public"}.get(fl&7,"")
os.makedirs(OUT,exist_ok=True)
jdir=f"{OUT}/il2cpp_full_{VER}"; os.makedirs(jdir,exist_ok=True)
cs=open(f"{OUT}/dumpcs_{VER}.cs","w",encoding="utf8")
cs.write(f"// kdump2 full dump of global-metadata v24-obf ({VER}); RVAs from reconstructed libil2cpp ({os.path.basename(BIN[VER])})\n// type names: typedef-derived or voted from 1.9.5 runtime dump (T#n = unresolved)\n\n")
stats=collections.Counter()
for ii in range(M.IMG_N):
    r=M.imgs[ii]; an=aname(ii); classes=[]
    cs.write(f"// ═══ {an} ({r[3]} classes) ═══\n\n")
    for i in range(r[2],r[2]+r[3]):
        t=M.tds[i]; fl=t[7]&0xffffffff
        fs=M.fields(i); ms=M.methods(i)
        cs.write(f"// Namespace: {M.S(t[1])}\n// Assembly: {an}\n// TypeDefIndex: {i}  Token: 0x{t[21]&0xffffffff:x}\n")
        kind="interface" if fl&0x20 else "class"
        mods=("abstract " if fl&0x80 and not fl&0x20 else "")+("sealed " if fl&0x100 else "")
        vis={0:"internal",1:"public",2:"public",3:"private",4:"protected",5:"internal",6:"protected internal",7:"private protected"}[fl&7]
        cs.write(f"{vis} {mods}{kind} {M.tname(i).split('/')[-1]}\n{{\n")
        fj=[]
        if fs: cs.write("\t// Fields\n")
        for f in fs:
            cs.write(f"\t{T(f['type'])} {f['name']}; // token 0x{f['token']:x}\n"); fj.append(dict(name=f["name"],type=T(f["type"]),typeIndex=f["type"],token="0x%x"%f["token"]))
        mj=[]
        if ms: cs.write("\n\t// Methods\n")
        for m in ms:
            rid=m["token"]&0xffffff; rv=rva(ii,rid); ps=M.params(m)
            stats["methods"]+=1; stats["rva"]+= rv is not None
            sig=", ".join(f"{T(p['type'])} {p['name']}" for p in ps)
            st="static " if m["flags"]&0x10 else ""; ab="abstract " if m["flags"]&0x400 else ("virtual " if m["flags"]&0x40 else "")
            cs.write(f"\t{acc(m['flags'])} {st}{ab}{T(m['ret'])} {m['name']}({sig}); // RVA: {('0x%x'%rv) if rv else 'n/a'} Token: 0x{m['token']:x} Slot: {m['slot'] if m['slot']!=0xffff else -1}\n")
            mj.append(dict(name=m["name"],token="0x%x"%m["token"],rva=("0x%x"%rv) if rv else None,flags="0x%x"%m["flags"],slot=m["slot"],
                ret=T(m["ret"]),retIndex=m["ret"],params=[dict(name=p["name"],type=T(p["type"]),typeIndex=p["type"]) for p in ps]))
        cs.write("}\n\n")
        classes.append(dict(name=M.S(t[0]),namespace=M.S(t[1]),fullName=M.tname(i),typeDefIndex=i,flags="0x%x"%fl,nested=i in M.parent,fields=fj,methods=mj))
    json.dump(dict(name=an,moduleBase=("0x%x"%bases[ii]) if ii in bases else None,classes=classes),open(f"{jdir}/{ii:03d}_{an}.json","w"),ensure_ascii=False)
cs.close()
print(dict(stats))
