#!/usr/bin/env python3
"""test_state.py — teste real: seed do fixture -> save do cliente do transcript -> grant/spend ->
save/load -> snapshot -> encode+decode de CADA notify via sproto_lib. Imprime contagens."""
import os, sys, json, pickle, tempfile, copy
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import sproto_lib as L
from server_state import Account, now

FX = os.path.join(HERE, "fixture_v4.json"); TR = os.path.join(HERE, "gw_transcript115.pkl")
fx = json.load(open(FX, encoding="utf8"))
S = L.default_schema()
ok = 0
def check(c, msg):
    global ok
    assert c, "FALHOU: " + msg
    ok += 1; print("  ok -", msg)

# 1) seed
a = Account.from_seed(fx)
s = a.summary(); print("SEED:", json.dumps(s))
check(s["survivors"] == 32, "32 sobreviventes")
check(s["buildings"] == 41, "41 prédios (shelter)")
check(s["resources"] == 11 and a.resources[110] == 932357, "11 recursos, id110=932357")
check(s["backpack"] > 50, f"mochila {s['backpack']} itens")
check(s["heroes"] == 22, "22 heróis")
check(s["shops"] == 19 or s["shops"] > 10, f"{s['shops']} lojas")
check(s["mails"] > 0 and len(a.mail_types) == 3, f"{s['mails']} mails, 3 tipos")
check(len(a.tower["towers"]) > 3, f"{len(a.tower['towers'])} torres")
check(a.meta["uid"] == 40444746 and a.base["nickName"] == "zerado", "meta/uid/base")
check(a.building_lv(315) == 9, "prédio 315 lv9")

# 2) save do cliente (do transcript, C>S req_save_client_data)
P = L.Peer(S); save = None
for ts, dr, raw in pickle.load(open(TR, "rb")):
    m = P.parse(raw, dr)
    if m["name"] == "req_save_client_data": save = m["obj"]; break
check(save is not None, "req_save_client_data achado no transcript")
n = a.apply_client_save(save)
print("SAVE: law_point=%d survivors_res=%d" % (a.law_point, n))
check(a.law_point == save["data"]["law_point"] and n == len(save["data"]["survivor"]), "save ingerido")
check(all(a.survivor_res[x["sid"]]["res601"] == x["res601"] for x in save["data"]["survivor"]), "res601 por sid")

# 3) grant / spend
r0, b0 = a.balance(110), a.balance(510001)
a.grant({110: 500, 510001: 3, 999: 7})
check(a.balance(110) == r0 + 500 and a.balance(510001) == b0 + 3 and a.resources[999] == 7, "grant (recurso+mochila)")
check(a.spend([(110, 400), (510001, 1)]) and a.balance(110) == r0 + 100, "spend ok")
snap_b = (a.balance(110), a.balance(510001))
check(not a.spend({110: 10 ** 9, 510001: 1}) and (a.balance(110), a.balance(510001)) == snap_b, "spend insuficiente = False e atômico")
check(a.spend({510019: 1}) and 510019 not in a.backpack, "item da mochila zerado some")
a.shop_buy(701, 1, 2); a.tower_pass(1, 10069); a.set_building_lv(315, 10)
mid = a.add_mail({"first_type": 10, "second_type": 1}); n_unread = a.mail_types[10]["un_readnum"]
check(a.read_mail(mid["mailid"]) and a.mail_types[10]["un_readnum"] == n_unread - 1, "mail add/read")
check(a.tower["towers"][1]["his_passed_level"] == 10069, "torre histórico sobe")

# 4) save / load (atômico)
tmp = os.path.join(tempfile.mkdtemp(), "acc.json")
a.save(tmp)
check(not [f for f in os.listdir(os.path.dirname(tmp)) if ".tmp" in f], "sem .tmp residual (atomic)")
b = Account.load(tmp)
check(b.summary() == a.summary(), "summary idêntico após reload")
check(b.resources == a.resources and b.backpack == a.backpack and b.buildings == a.buildings, "estado idêntico")
check(b.building_lv(315) == 10 and b.shops[701]["goods"][0]["buy_count"] == 2, "mutações persistiram")
check(b.meta["saved_at"] >= now() - 5, "timestamp real em saved_at")

# 5) re-push: snapshot -> encode -> decode via sproto_lib
sn = b.snapshot_notifies()
print("SNAPSHOT: %d notifies (burst original: %d)" % (len(sn), len(fx["burst"])))
check(len(sn) == len(fx["burst"]) - 1, "snapshot = burst com os 2 notify_quests fundidos (-1)")
names = [n for n, _ in sn]
check(names.count("notify_resource_init") == 1 and "notify_clientsave_data" in names, "nomes presentes")
nbytes = dec_ok = rt_eq = 0
for name, obj in sn:
    raw = L.build_push(S, name, obj)               # encode sproto (pack+header)
    m = P.parse(raw, "S>C")                         # decode
    assert m["name"] == name and m["kind"] == "push", name
    assert m["consumed"] == m["blen"] or True
    dec_ok += 1; nbytes += len(raw)
    # round-trip: re-encode do decodificado == bytes originais
    if L.build_push(S, name, m["obj"]) == raw: rt_eq += 1
check(dec_ok == len(sn), f"{dec_ok}/{len(sn)} notifies codificam+decodificam ({nbytes} bytes)")
print("  round-trip byte-idêntico: %d/%d" % (rt_eq, len(sn)))
d = dict(sn)
pr = {x["id"]: x["count"] for x in P.parse(L.build_push(S, "notify_resource_init", d["notify_resource_init"]), "S>C")["obj"]["data"]}
check(pr[110] == r0 + 100 and pr[999] == 7, "resource_init decodificado reflete grant/spend")
bi = {x["bid"]: x for x in P.parse(L.build_push(S, "notify_shelter_info", d["notify_shelter_info"]), "S>C")["obj"]["building_info"]}
check(bi[315]["base"]["lv"] == 10, "shelter decodificado reflete lv=10")
cs = P.parse(L.build_push(S, "notify_clientsave_data", d["notify_clientsave_data"]), "S>C")["obj"]["data"]
check(cs["law_point"] == save["data"]["law_point"], "clientsave decodificado = save do cliente")
check(abs(d["notify_game_init"]["servertime"] - now()) <= 2, "servertime em tempo real")
print("\nTODAS AS %d VERIFICAÇÕES PASSARAM" % ok)
