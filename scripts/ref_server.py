#!/usr/bin/env python3
"""ref_server.py - servidor de referência (esqueleto) p/ protocolo sproto tipo Kingshot.
Um arquivo, asyncio, só stdlib. Offline: nada de rede externa (loopback no self-test).
  python3 ref_server.py --proto <dir com game_proto_{c2s,s2c}.sproto> --replay gw_transcript115.pkl   # valida 312/312 + TCP loopback
  python3 ref_server.py --proto <dir> --serve 30101                                                    # sobe o gateway
Moldura: u16 BE len + 0-pack( header{type,session,ud} ++ body ).   (c2s=pedido ; s2c=resposta(sem type) | push(sem session))
"""
import asyncio, os, pickle, random, re, struct, sys, time

# ---------------------------------------------------------------- 1. sproto: parser + codec + 0-pack (adaptado de sproto_py.py)
def parse(text):
    tk = re.findall(r'[{}:*()]|[^\s{}:*()]+', re.sub(r'#[^\n]*', '', text)); i = 0; types = {}; protos = {}
    def fields(owner):
        nonlocal i; fs = []
        while tk[i] != '}':
            if tk[i].startswith('.'):
                nm = tk[i][1:]; i += 2; types[owner + '.' + nm] = fields(owner + '.' + nm); i += 1; continue
            name = tk[i]; tag = int(tk[i+1]); i += 3; arr = tk[i] == '*'; i += arr; ty = tk[i]; i += 1
            if i < len(tk) and tk[i] == '(':
                i += 2 if tk[i+1] == ')' else 3
            fs.append(dict(name=name, tag=tag, type=ty, arr=arr, owner=owner))
        return sorted(fs, key=lambda f: f['tag'])
    while i < len(tk):
        nm = tk[i]; i += 1
        if nm.startswith('.'):
            i += 1; types[nm[1:]] = fields(nm[1:]); i += 1
        else:
            p = {'tag': int(tk[i]), 'request': None, 'response': None}; i += 2
            while tk[i] != '}':
                kind = tk[i]; i += 1
                if tk[i] == '{': i += 1; p[kind] = fields(nm + '.' + kind); i += 1
                else: p[kind] = tk[i]; i += 1       # tipo nomeado ou "nil"
            i += 1; protos[nm] = p
    return types, protos

def unpack(b):                                       # 0-pack -> bytes
    out = bytearray(); i = 0
    while i < len(b):
        h = b[i]; i += 1
        if h == 0xff: n = b[i] + 1; i += 1; out += b[i:i+n*8]; i += n*8
        else:
            for k in range(8):
                if h >> k & 1: out.append(b[i]); i += 1
                else: out.append(0)
    return bytes(out)

def pack(b):                                         # bytes -> 0-pack (sem otimização de runs; grupo cheio = ff 00 + 8B)
    b = b + b'\0' * (-len(b) % 8); out = bytearray()
    for g in range(0, len(b), 8):
        grp = b[g:g+8]; h = sum(1 << k for k in range(8) if grp[k])
        if h == 0xff: out += b'\xff\x00' + grp
        else: out.append(h); out += bytes(c for c in grp if c)
    return bytes(out)

class Codec:
    def __init__(s, types): s.t = types
    def _res(s, ty, owner):
        if ty in ('integer', 'string', 'boolean', 'double', 'binary'): return ty
        o = owner
        while True:
            c = o + '.' + ty
            if c in s.t: return c
            if '.' not in o: break
            o = o.rsplit('.', 1)[0]
        if ty in s.t: return ty
        raise KeyError((ty, owner))
    def dec(s, fields, b, p=0):                      # -> (dict, fim)
        fc = struct.unpack_from('<H', b, p)[0]; hp = p + 2; dp = hp + fc*2; tag = 0; res = {}; pend = []
        for k in range(fc):
            v = struct.unpack_from('<H', b, hp + k*2)[0]
            if v & 1: tag += (v + 1) // 2; continue
            f = next((f for f in fields if f['tag'] == tag), None)
            if v == 0: pend.append((tag, f))
            elif f: res[f['name']] = bool(v//2 - 1) if f['type'] == 'boolean' else v//2 - 1
            tag += 1
        for tag, f in pend:
            ln = struct.unpack_from('<I', b, dp)[0]; d = b[dp+4:dp+4+ln]; dp += 4 + ln
            if f: res[f['name']] = s._val(f, d)
            else: res['?%d' % tag] = d.hex()
        return res, dp
    def _val(s, f, d):
        ty = s._res(f['type'], f['owner'])
        if f['arr']:
            if ty == 'boolean': return [bool(c) for c in d]
            if ty in ('integer', 'double'):
                sz = d[0] if d else 4
                return [struct.unpack('<d', d[k:k+8])[0] if ty == 'double' else int.from_bytes(d[k:k+sz], 'little', signed=True) for k in range(1, len(d), sz)]
            r = []; p = 0
            while p < len(d):
                ln = struct.unpack_from('<I', d, p)[0]; e = d[p+4:p+4+ln]; p += 4 + ln
                r.append(e.decode('utf8', 'replace') if ty == 'string' else e if ty == 'binary' else s.dec(s.t[ty], e)[0])
            return r
        if ty == 'integer': return int.from_bytes(d, 'little', signed=True)
        if ty == 'double': return struct.unpack('<d', d)[0]
        if ty == 'string': return d.decode('utf8', 'replace')
        if ty == 'binary': return bytes(d)
        return s.dec(s.t[ty], d)[0]
    def enc(s, fields, obj):                         # dict -> bytes (struct sproto)
        hdr = []; data = bytearray(); last = -1
        for f in fields:
            v = obj.get(f['name'])
            if v is None: continue
            if f['tag'] > last + 1: hdr.append(2 * (f['tag'] - last - 1) - 1)
            last = f['tag']; ty = s._res(f['type'], f['owner'])
            if not f['arr'] and ty in ('integer', 'boolean') and 0 <= int(v) < 0x7fff: hdr.append((int(v) + 1) * 2); continue
            hdr.append(0); d = s._raw(f, ty, v); data += struct.pack('<I', len(d)) + d
        return struct.pack('<H', len(hdr)) + b''.join(struct.pack('<H', h) for h in hdr) + bytes(data)
    def _int(s, v): return v.to_bytes(4, 'little', signed=True) if -2**31 <= v < 2**31 else v.to_bytes(8, 'little', signed=True)
    def _raw(s, f, ty, v):
        if f['arr']:
            if ty == 'boolean': return bytes(int(x) for x in v)
            if ty == 'integer':
                z = 8 if any(not -2**31 <= x < 2**31 for x in v) else 4
                return (bytes([z]) + b''.join(x.to_bytes(z, 'little', signed=True) for x in v)) if v else b''
            if ty == 'double': return b'\x08' + b''.join(struct.pack('<d', x) for x in v) if v else b''
            return b''.join(struct.pack('<I', len(e)) + e for e in (s._one(f, ty, x) for x in v))
        return s._one(f, ty, v)
    def _one(s, f, ty, v):
        if ty == 'integer': return s._int(int(v))
        if ty == 'boolean': return bytes([int(v)])
        if ty == 'double': return struct.pack('<d', v)
        if ty == 'string': return v.encode()
        if ty == 'binary': return bytes(v)
        return s.enc(s.t[ty], v)

# ---------------------------------------------------------------- 2. schema + cifra de corpo
class Schema:
    def __init__(s, d):
        rd = lambda n: parse(open(os.path.join(d, n), encoding='utf8').read())
        s.tc, s.pc = rd('game_proto_c2s.sproto'); s.ts, s.ps = rd('game_proto_s2c.sproto')
        s.cc, s.cs = Codec(s.tc), Codec(s.ts)                 # c2s tem req+resp ; s2c tem notify_*
        s.req_by_id = {p['tag']: n for n, p in s.pc.items()}  # msgId -> nome (dispatcher)
        s.push_by_id = {p['tag']: n for n, p in s.ps.items()}
        s.hdr = s.tc['package']                               # {type 0, session 1, ud 2{crypt_method, crypt_length}}

def xor(b, key): return bytes(c ^ key[i % len(key)] for i, c in enumerate(b))   # crypt_method=1 (obs.: chave 4 B periódica)

# ---------------------------------------------------------------- 3. gateway: sessão, dispatcher, handlers stub
class Session:
    def __init__(s, key): s.key = key; s.last = 0; s.uid = None; s.authed = False; s.created = time.time(); s.last_seen = time.time()

class Gateway:
    IDLE = 30.0
    def __init__(s, schema, fixed_key=None):
        s.S = schema; s.fixed_key = fixed_key; s.stats = {'req': 0, 'resp': 0, 'push': 0, 'unknown': 0, 'replay': 0, 'denied': 0}
        s.H = {'loginauth': s.h_login, 'req_heartbeat': s.h_heartbeat, 'req_loaddata': s.h_loaddata,
               'req_save_client_data': s.h_snapshot}
    # --- handlers: (sess, req) -> resp dict | None   (stub genérico = {'code':0})
    def h_login(s, ss, r):
        if not r.get('sdkToken') or not r.get('account'): return {'code': 1}          # TODO validar token no IdP + nonce/ts
        ss.authed = True; ss.uid = r.get('uid'); now = int(time.time())
        return {'code': 0, 'serverid': r.get('serverid', 1), 'uid': r.get('uid', 0), 'is_new': False, 'server_ts': now,
                'secret_key': ss.key, 'crypt_method': 1, 'version_info': {'appVersion': r.get('version', ''), 'resVersion': ''}}
    def h_heartbeat(s, ss, r): return {'time': int(time.time())}
    def h_loaddata(s, ss, r):
        s.push_later = [('notify_game_init', {'servertime': int(time.time()), 'utc_offset': 0})]   # TODO: ~50 notify_*_init do estado persistido
        return {'code': 0}
    def h_snapshot(s, ss, r):                          # 3001: cliente-autoritativo -> tratar como HINT
        for sv in (r.get('data') or {}).get('survivor', []):
            for k in range(601, 608):
                v = sv.get('res%d' % k)
                if v is not None and not 0.0 <= v <= 100.0: s.stats['denied'] += 1; return {'code': 2}   # fora de [0,100]
        return {'code': 0}                              # TODO: limitar taxa de variação; nunca creditar recurso a partir disto
    def stub(s, ss, name, r):
        if name.startswith('req_cheat_'): s.stats['denied'] += 1; return {'code': -1}     # GM/cheat: nunca em produção
        resp = s.S.pc[name]['response']
        return {'code': 0} if isinstance(resp, list) and any(f['name'] == 'code' for f in resp) else {}
    # --- pipeline de um frame (bytes sem o prefixo u16) -> lista de frames de saída (bytes sem prefixo)
    def handle(s, ss, raw, strict=True):
        S = s.S; ss.last_seen = time.time(); u = unpack(raw); h, off = S.cc.dec(S.hdr, u); body = u[off:]
        ud = h.get('ud') or {}; enc = ud.get('crypt_method') == 1
        if enc: n = ud.get('crypt_length', len(body)); body = xor(body[:n], ss.key) + body[n:]
        typ, ses = h.get('type'), h.get('session'); out = []
        name = S.req_by_id.get(typ)
        if name is None: s.stats['unknown'] += 1; return out
        if strict and ses is not None:                  # pareamento: session estritamente crescente por conexão
            if ses <= ss.last: s.stats['replay'] += 1; return out
        ss.last = ses or ss.last
        if name != 'loginauth' and not ss.authed: s.stats['denied'] += 1; return out      # tudo exige login antes
        sch = S.pc[name]['request']; req = S.cc.dec(sch, body)[0] if isinstance(sch, list) and body.strip(b'\0') else {}
        s.stats['req'] += 1
        resp = s.H[name](ss, req) if name in s.H else s.stub(ss, name, req)
        rs = S.pc[name]['response']
        if isinstance(rs, list) and resp is not None:    # há bloco response -> responde com o MESMO session
            hb = {'session': ses}; b = S.cc.enc(rs, resp)
            if enc: hb['ud'] = {'crypt_method': 1, 'crypt_length': len(b)}; b = xor(b, ss.key)   # obs.: servidor real ecoa crypt_length do pedido
            out.append(pack(S.cc.enc(S.hdr, hb) + b)); s.stats['resp'] += 1
        for pname, pobj in getattr(s, 'push_later', []):  # pushes notify_*: type, sem session
            out.append(s.push(pname, pobj))
        s.push_later = []
        return out
    def push(s, name, obj):
        s.stats['push'] += 1; p = s.S.ps[name]
        return pack(s.S.cs.enc(s.S.hdr, {'type': p['tag']}) + s.S.cs.enc(p['request'], obj))
    def new_session(s): return Session(s.fixed_key or bytes(random.SystemRandom().randrange(256) for _ in range(4)))

    async def conn(s, rd, wr):                          # TCP: u16 BE len + frame
        ss = s.new_session()
        try:
            while True:
                n = struct.unpack('>H', await asyncio.wait_for(rd.readexactly(2), s.IDLE))[0]   # idle => derruba (heartbeat obrigatório)
                for o in s.handle(ss, await rd.readexactly(n)): wr.write(struct.pack('>H', len(o)) + o)
                await wr.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError): pass
        finally: wr.close()

# ---------------------------------------------------------------- 4. self-test contra o transcript
def decode_all(S, tr):                                  # decodifica os 312 frames (lado "cliente/observador")
    ok = 0; pend = {}; key = None; kinds = {}
    for t, d, raw in tr:
        u = unpack(raw); h, off = S.cc.dec(S.hdr, u); body = u[off:]; ud = h.get('ud') or {}
        typ, ses = h.get('type'), h.get('session')
        if d == 'C>S': name = S.req_by_id[typ]; pend[ses] = name; sch = S.pc[name]['request']; c = S.cc
        elif typ is None: name = pend[ses]; sch = S.pc[name]['response']; c = S.cc; name += '.rsp'
        else: name = S.push_by_id[typ]; sch = S.ps[name]['request']; c = S.cs
        if ud.get('crypt_method') == 1:                 # chave aprendida do login rsp (secret_key) ; req: crypt_length ; rsp: corpo todo
            n = ud['crypt_length'] if d == 'C>S' else len(body); body = xor(body[:n], key) + body[n:]
        r = c.dec(sch, body)[0] if isinstance(sch, list) and body.strip(b'\0') else {}
        if name == 'loginauth.rsp': key = r['secret_key']
        kinds[name] = kinds.get(name, 0) + 1; ok += 1
    return ok, kinds, key

async def loopback(S, tr, key):
    gw = Gateway(S, fixed_key=key); gw.IDLE = 5
    srv = await asyncio.start_server(gw.conn, '127.0.0.1', 0); port = srv.sockets[0].getsockname()[1]
    rd, wr = await asyncio.open_connection('127.0.0.1', port); sent = got = ses_ok = 0; hb = lg = 0; pushes = 0
    for t, d, raw in [x for x in tr if x[1] == 'C>S']:
        wr.write(struct.pack('>H', len(raw)) + raw); await wr.drain(); sent += 1
        h = S.cc.dec(S.hdr, unpack(raw))[0]; need = isinstance(S.pc[S.req_by_id[h['type']]]['response'], list)
        if need:
            while True:                                 # lê saídas até achar o response (sem type) -> pareamento por session
                n = struct.unpack('>H', await rd.readexactly(2))[0]; o = unpack(await rd.readexactly(n)); oh = S.cc.dec(S.hdr, o)[0]
                if oh.get('type') is not None: pushes += 1; continue
                got += 1; ses_ok += oh['session'] == h['session']
                hb += h['type'] in (21, 22); lg += h['type'] == 1; break
    wr.close(); srv.close()
    return sent, got, ses_ok, hb, lg, pushes, gw.stats

if __name__ == '__main__':
    a = sys.argv; arg = lambda k, d=None: a[a.index(k) + 1] if k in a else d
    S = Schema(arg('--proto', '.'))
    print('schema: %d req/resp c2s, %d notify s2c' % (len(S.pc), len(S.ps)))
    if '--serve' in a:
        async def main():
            gw = Gateway(S); srv = await asyncio.start_server(gw.conn, '0.0.0.0', int(arg('--serve', 30101))); await srv.serve_forever()
        asyncio.run(main())
    else:
        tr = pickle.load(open(arg('--replay'), 'rb')); ok, kinds, key = decode_all(S, tr)
        print('DECODIFICADOS: %d/%d frames (C>S=%d, S>C=%d); chave de sessão aprendida do login rsp = %s' % (ok, len(tr), sum(x[1] == 'C>S' for x in tr), sum(x[1] == 'S>C' for x in tr), key.hex()))
        print('tipos distintos:', len(kinds), '| top:', sorted(kinds.items(), key=lambda x: -x[1])[:6])
        sent, got, ses_ok, hb, lg, pushes, st = asyncio.run(loopback(S, tr, key))
        print('LOOPBACK TCP: enviados %d pedidos C>S | respostas %d | session ecoada correta %d | heartbeat(21/22) respondidos %d | login(1) %d | pushes recebidos %d' % (sent, got, ses_ok, hb, lg, pushes))
        print('stats gateway:', st)
