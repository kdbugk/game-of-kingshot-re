import sys, struct, re, json, base64
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

data = open('battle2.pcap','rb').read()
off = 24; frames_raw = []
while off+16<=len(data):
    ts,tu,il,ol = struct.unpack_from('<IIII',data,off); off+=16
    frames_raw.append((ts+tu/1e6, data[off:off+il])); off+=il

def tcp_payload(pkt):
    try:
        p=pkt[16:]
        if p[9]!=6: return None,None,None
        ihl=(p[0]&0xf)*4; tcp=p[ihl:]
        sp=struct.unpack_from('>H',tcp,0)[0]; dp=struct.unpack_from('>H',tcp,2)[0]
        return sp,dp,tcp[(tcp[12]>>4)*4:]
    except: return None,None,None

sc_raw=b''; ct_raw=b''
for ts,pkt in frames_raw:
    sp,dp,pay=tcp_payload(pkt)
    if sp is None: continue
    if sp==30101 and pay: sc_raw+=pay
    if dp==30101 and pay: ct_raw+=pay

def pframes(d):
    out=[]; i=0
    while i+2<=len(d):
        ln=struct.unpack_from('>H',d,i)[0]
        if ln==0 or i+2+ln>len(d): i+=1; continue
        out.append(d[i+2:i+2+ln]); i+=2+ln
    return out

sc=pframes(sc_raw); ct=pframes(ct_raw)

def read_varint(data, pos):
    result = 0; shift = 0
    while pos < len(data):
        b = data[pos]; pos+=1
        result |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80): break
    return result, pos

def decode_proto(data):
    fields = []; pos = 0
    while pos < len(data):
        try:
            tag_wire, pos = read_varint(data, pos)
            if tag_wire == 0: break
            field_num = tag_wire >> 3
            wire_type = tag_wire & 7
            if wire_type == 0:
                val, pos = read_varint(data, pos)
                fields.append((field_num, 'varint', val))
            elif wire_type == 2:
                length, pos = read_varint(data, pos)
                val = data[pos:pos+length]; pos += length
                try:
                    s = val.decode('utf-8')
                    fields.append((field_num,'string',s))
                except:
                    fields.append((field_num,'bytes',val.hex()))
            elif wire_type == 5:
                val = struct.unpack('<I', data[pos:pos+4])[0]; pos+=4
                fields.append((field_num,'fixed32',val))
            else:
                break
        except:
            break
    return fields

# ─── ANALISE 1: coordenadas ──────────────────────────────────────
print('='*60)
print('ANALISE 1 -- Encoding das coordenadas (ASCII85-like)')
print('='*60)
print()

coord_re = re.compile(rb'[A-Za-z0-9]{3,6}[@$!#]')
all_coords = {}
for f in sc:
    for m in coord_re.finditer(f):
        c = m.group()
        all_coords[c] = all_coords.get(c, 0) + 1

print('Top coordenadas S->C com decodificacao:')
print('  {:12s}  {:5s}  {:6s}  {:6s}  {}'.format('encoded','count','reino','coord','sufixo'))
for raw, n in sorted(all_coords.items(), key=lambda x: -x[1])[:25]:
    suffix = chr(raw[-1])
    body = raw[:-1]
    v = 0
    for ch in body:
        v = v*85 + (ch - 33)
    x = v >> 16
    y = v & 0xffff
    print('  {:12s}  {:5d}  {:6d}  {:6d}  {}'.format(
        raw.decode('latin1'), n, x, y, suffix))

print()
print('Observacoes:')
print('  @ sufixo = coordenada de mapa global (reino, posicao)')
print('  $ sufixo = referencia de sub-objeto (ID de tropa/farm)')
print('  "931!" -> reino=2, y=43874 (possivelmente ID reino 931 codificado)')

# ─── ANALISE 2: JSONs embutidos ──────────────────────────────────
print()
print('='*60)
print('ANALISE 2 -- JSONs embutidos nos frames S->C')
print('='*60)

json_re = re.compile(rb'\{[^\x00-\x08\x0e-\x1f]{5,300}\}')
found_jsons = []
for i, f in enumerate(sc):
    for m in json_re.finditer(f):
        raw = m.group()
        if b':' not in raw: continue
        txt = raw.decode('utf-8', 'replace')
        if not any(c in txt for c in ['"', 'true', 'false']): continue
        found_jsons.append((i, f[0], txt))

for fidx, op, txt in found_jsons:
    print('  frame#{:3d} op=0x{:02x}: {}'.format(fidx, op, txt))

if not found_jsons:
    print('  Nenhum JSON completo. Fragmentos encontrados anteriormente:')
    print('  frame#66: {"12":true,"13":true,"11":true,"16":true,"10":true,"15":true,"22":true}')
    print('  frame#66: {"p_giftid":4000751,"device_lvl":2,"fp_countrycode":"BR"}')

print()
print('Interpretacao dos campos numericos (feature flags):')
flags = {"10": "?", "11": "?", "12": "?", "13": "?", "15": "?", "16": "?", "22": "?"}
print('  Todos true -> provavelmente flags de recursos/funcionalidades desbloqueadas')
print('  p_giftid=4000751 -> ID do gift/recompensa pendente')
print('  device_lvl=2     -> nivel do dispositivo classificado pelo servidor')
print('  fp_countrycode=BR-> pais detectado pelo fingerprint')

# ─── ANALISE 3: opcode 0x59 ──────────────────────────────────────
print()
print('='*60)
print('ANALISE 3 -- Opcode 0x59 C->S: estrutura e funcao')
print('='*60)

frames_59 = [(i,f) for i,f in enumerate(ct) if f and f[0] == 0x59]
print('Total frames 0x59: {}'.format(len(frames_59)))
print()

for i, f in frames_59:
    body = f[1:]
    fields = decode_proto(body)
    print('frame#{:3d} len={:3d}:'.format(i, len(f)))
    for fnum, ftype, fval in fields:
        if ftype == 'string' and len(str(fval)) > 10:
            try:
                dec = base64.b64decode(fval)
                print('  field[{}] string(b64_decoded {}B): {}'.format(fnum, len(dec), dec.hex()))
            except:
                print('  field[{}] string: {}'.format(fnum, str(fval)[:80]))
        else:
            print('  field[{}] {}: {}'.format(fnum, ftype, fval))

print()
print('Comparando campo variavel entre frames curtos (13B):')
short_59 = [(i,f) for i,f in frames_59 if len(f)==13]
prev_seq = None
for i, f in short_59:
    seq = f[3]
    delta = (seq - prev_seq) if prev_seq is not None else 0
    tail_int = struct.unpack_from('>I', f[8:12])[0] if len(f)>=12 else 0
    print('  frame#{:3d}: f[3]=0x{:02x}({:3d})  delta={:+d}  tail_bytes={}'.format(
        i, seq, seq, delta, f[8:].hex()))
    prev_seq = seq

print()
print('Hipotese: 0x59 = confirmacao de acao do cliente')
print('  Frames curtos (13B): ACK de evento do servidor com seq counter')
print('  Frame longo  (51B):  payload com assinatura criptografica (27B decoded)')
print('    -> base64 "Yuoo0N3p7nDUsi8hmNhCUW6UAO6mHsoxoeNg=="')
print('    -> decoded: 62ea28d0dde9ee70d4b22f2198d842516e9400eea61eca31a1e360')
print('    -> 27B = nao standard (SHA1=20B, SHA256=32B) -> custom HMAC ou token')
