#!/usr/bin/env python3
"""cmd_console.py — simula o cliente sem o cliente: manda comandos legítimos e
mostra as respostas decodificadas.

Uso:
  python3 cmd_console.py <alvo> <comando> [args-json]
  alvo: mock | prod
  python3 cmd_console.py mock heartbeat
  python3 cmd_console.py mock mail_list
  python3 cmd_console.py mock mail_receive '{"mailid_new":"mock-1"}'
  python3 cmd_console.py mock climbtower '{"id":40021}'
  python3 cmd_console.py mock shop_info '{"arr_id":[101,601]}'
  python3 cmd_console.py prod schedule_info        # producao: so comandos leves, 1x
"""
import sys, os, socket, json, pickle, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sproto_lib as L
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGETS = {"mock": ("127.0.0.1", 30101), "prod": ("3.33.245.139", 30101)}
TRANSCRIPT = "/home/re/work/apk/gw_transcript115.pkl"

def main():
    alvo = sys.argv[1] if len(sys.argv) > 1 else "mock"
    cmd = sys.argv[2] if len(sys.argv) > 2 else "heartbeat"
    args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    name = cmd if cmd.startswith("req_") or cmd == "loginauth" else "req_" + cmd

    S = L.default_schema()
    if name not in S.c2s_by_name:
        print(f"[!] comando desconhecido no schema: {name}")
        print("    exemplos: heartbeat, mail_list, mail_receive, climbtower, shop_info, schedule_info, rank_info")
        return
    host, port = TARGETS.get(alvo, TARGETS["mock"])
    sock = socket.create_connection((host, port), timeout=8)
    peer = L.Peer(S); sess = 0

    def recvn(n):
        b = b""
        while len(b) < n:
            c = sock.recv(n - len(b))
            if not c: raise ConnectionError("fim")
            b += c
        return b

    def read_msgs(timeout=3.0, max=50):
        out = []
        sock.settimeout(timeout)
        end = time.time() + timeout
        while len(out) < max and time.time() < end:
            try:
                out.append(peer.parse(recvn(int.from_bytes(recvn(2), "big")), "S>C"))
            except socket.timeout:
                break
        return out

    def req(n, obj, tmo=3.0):
        nonlocal sess
        sess += 1
        sock.sendall(L.frame(L.build_request(S, n, obj, sess, key=peer.key)))
        peer.note_request(sess, n)
        for m in read_msgs(tmo):
            if m["kind"] == "resp" and m["name"] == n:
                return m["obj"]
            elif m["kind"] == "push":
                print(f"   [push] {m['name']} {str(m['obj'])[:90]}")
        return None

    # login com a identidade real do transcript
    tr = pickle.load(open(TRANSCRIPT, "rb"))
    P0 = L.Peer(S); login_obj = None
    for t, d, raw in tr:
        if d == "C>S":
            m = P0.parse(raw, d)
            if m["name"] == "loginauth": login_obj = m["obj"]; break
    r = req("loginauth", login_obj, 5.0)
    print(f"[login {alvo}] code={r.get('code')} uid={r.get('uid')} serverid={r.get('serverid')}")
    sk = r.get("secret_key")
    if isinstance(sk, str) and len(sk) == 8: peer.key = bytes.fromhex(sk)
    elif isinstance(sk, (bytes, bytearray)): peer.key = bytes(sk)

    # payload padrao por comando (formas reais do log)
    DEFAULTS = {
        "req_heartbeat": {},
        "req_schedule_info": {},
        "req_mail_cover_list": {"first_type": 30, "beginidx": 1, "endidx": 10},
        "req_mail_type_info": {},
        "req_shop_info": {"arr_id": [101, 601]},
        "req_rank_info": {"list_type": [{"type": 1, "ext": {"aid": 0}}]},
        "req_climbtower_challenge": {"id": 40023, "formation_prefab": [{"id": 1, "prefab": {"soldier": [{"k": 21000, "v": 51400}]}}]},
    }
    obj = args if args else DEFAULTS.get(name, {})

    # print(f"[enviado] {name} {json.dumps(obj, ensure_ascii=False)[:100]}")
    # resp = req(name, obj, 6.0)
    # print(f"[resposta] {json.dumps(resp, ensure_ascii=False, indent=1)[:800] if resp is not None else '(nenhuma)'}")


    def enviar(name, obj):
        print(f"[enviado] {name} {json.dumps(obj, ensure_ascii=False)[:100]}")
        return req(name, obj, 6.0)

    N = 10
    with ThreadPoolExecutor(max_workers=N) as pool:
        futuros = {pool.submit(enviar, name, obj): i for i in range(N)}
        for fut in as_completed(futuros):
            i = futuros[fut]
            try:
                resp = fut.result()
            except Exception as e:
                print(f"[erro #{i}] {name} {e!r}")
                continue
            print(f"[resposta #{i}] {json.dumps(resp, ensure_ascii=False, indent=1)[:800] if resp is not None else '(nenhuma)'}")
    resp is not None else '(nenhuma)'}")

    sock.close()
    print("[fim]")

if __name__ == "__main__":
    main()
