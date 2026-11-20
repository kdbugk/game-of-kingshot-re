#!/usr/bin/env python3
"""Extrai receitas reais (resp+pushes por comando) das 2 capturas reais. Uso: python extract.py"""
import sys, os, pickle, json, collections
HERE = os.path.dirname(os.path.abspath(__file__)); W = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(W, "mockserver"))
import sproto_lib as L
SRC = [("login115", os.path.join(W, "mockserver", "gw_transcript115.pkl")),
       ("combate_kind03", os.path.join(W, "kind03", "frames.pkl"))]
S = L.default_schema()

def decode(path):
    P = L.Peer(S); out = []
    for t, d, raw in pickle.load(open(path, "rb")):
        try: m = P.parse(raw, d)
        except Exception: continue
        out.append((t, d, m))
    return out

def flat(o, p=""):
    r = {}
    if isinstance(o, dict):
        for k, v in o.items(): r.update(flat(v, f"{p}.{k}" if p else k))
    elif isinstance(o, list):
        for i, v in enumerate(o): r.update(flat(v, f"{p}[]"))   # indices colapsados
    else: r[p] = o
    return r

def collect(o, p, acc):
    if isinstance(o, dict):
        for k, v in o.items(): collect(v, f"{p}.{k}" if p else k, acc)
    elif isinstance(o, list):
        for v in o: collect(v, p + "[]", acc)
    else: acc.setdefault(p, []).append(o)

def dyn_paths(objs):
    """caminhos cujo valor varia entre ocorrências OU parecem timestamp/contador."""
    acc = {}
    for o in objs: collect(o, "", acc)
    dyn = set()
    for p, vals in acc.items():
        leaf = p.split(".")[-1].rstrip("[]")
        if len(objs) > 1 and len(set(map(repr, vals))) > len(objs) * 0 + 1 and p.count("[]") == 0: dyn.add(p)
        if any(isinstance(v, int) and 1.7e9 < v < 1.9e9 for v in vals): dyn.add(p)   # epoch s
        if any(isinstance(v, int) and 1.7e12 < v < 1.9e12 for v in vals): dyn.add(p)  # epoch ms
        if leaf in ("time", "servertime", "server_time", "now", "ts", "timestamp") : dyn.add(p)
    return sorted(dyn)

def main():
    occ = collections.defaultdict(list)   # cmd -> [{src,t,req,resp,pushes}]
    for sname, path in SRC:
        fr = decode(path)
        reqs = [i for i, (t, d, m) in enumerate(fr) if m["kind"] == "req"]
        for k, i in enumerate(reqs):
            nxt = reqs[k + 1] if k + 1 < len(reqs) else len(fr)
            t0, _, rq = fr[i]; resp = None; pushes = []
            for t, d, m in fr[i + 1:nxt]:
                if m["kind"] == "resp" and m["name"] == rq["name"] and resp is None: resp = (t, m["obj"])
                elif m["kind"] == "push": pushes.append((t, m["name"], m["obj"]))
            ref = None
            for t, d, m in fr:               # relogio do servidor mais proximo (heartbeat resp.time) -> base p/ rebase de epochs
                if m["kind"] == "resp" and m["name"] == "req_heartbeat" and isinstance(m["obj"].get("time"), int):
                    if ref is None or abs(t - t0) < abs(ref[0] - t0): ref = (t, m["obj"]["time"])
            if ref is None:
                for t, d, m in fr:
                    if m["kind"] == "resp" and m["name"] == "loginauth":
                        ref = (t, m["obj"].get("underage_info", {}).get("server_ts") or 0); break
            sref = (ref[1] + (t0 - ref[0])) if ref and ref[1] else None
            occ[rq["name"]].append(dict(sref=sref, src=sname, t=t0, req=rq["obj"], resp=resp, pushes=pushes))
    rec = {}
    for cmd, os_ in sorted(occ.items()):
        def score(o): return (o["resp"] is not None, len(json.dumps(o["resp"][1] if o["resp"] else {})) + len(o["pushes"]) * 1000)
        best = max(os_, key=score)
        resps = [o["resp"][1] for o in os_ if o["resp"]]
        deltas = [(o["resp"][0] - o["t"]) * 1000 for o in os_ if o["resp"]]
        dyn = dyn_paths(resps) if resps else []
        pnames = collections.Counter(n for o in os_ for _, n, _ in o["pushes"])
        push_dyn = {}
        for n in pnames:
            objs = [x for o in os_ for _, nn, x in o["pushes"] if nn == n]
            d = dyn_paths(objs)
            if d: push_dyn[n] = d
        # pushes estaveis: aparecem em >=50% das ocorrencias (evita timers coincidentes na janela do heartbeat)
        stable = [[n, x] for _, n, x in best["pushes"] if pnames[n] * 2 >= len(os_)]
        rec[cmd] = {
            "_ref_time": best["sref"],
            "response": best["resp"][1] if best["resp"] else None,
            "pushes": stable,
            "n_ocorrencias": len(os_),
            "delta_medio_ms": round(sum(deltas) / len(deltas), 1) if deltas else None,
            "fontes": sorted({o["src"] for o in os_}),
            "push_freq": dict(pnames),
            "req_exemplo": best["req"],
            "_dynamic": dyn,
            "_dynamic_pushes": push_dyn,
            "_variacoes": ({p: sorted({json.dumps(v) for v in collected})[:6] for p, collected in
                            ((p, vs) for p, vs in _acc(resps).items()) if p in dyn} if resps and len(resps) > 1 else {}),
        }
    json.dump(rec, open(os.path.join(HERE, "recipes.json"), "w", encoding="utf8"), ensure_ascii=False, indent=1)
    print(len(rec), "comandos;", sum(1 for r in rec.values() if r["response"] is not None), "com resposta")
    return rec

def _acc(objs):
    a = {}
    for o in objs: collect(o, "", a)
    return a

if __name__ == "__main__": main()
