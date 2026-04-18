"""
decode_1d_frames.py
Tenta decodificar os frames 0x1d (state sync S->C) como protobuf.
"""
import sys, struct, re, json, base64
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ── pcap + reassembly ─────────────────────────────────────────────
data = open('battle2.pcap', 'rb').read()
off = 24; raw_pkts = []
while off + 16 <= len(data):
    ts, tu, il, ol = struct.unpack_from('<IIII', data, off); off += 16
    raw_pkts.append(data[off:off+il]); off += il

def tcp_payload(pkt):
    try:
        p = pkt[16:]
        if p[9] != 6: return None, None, None
        ihl = (p[0] & 0xf) * 4; tcp = p[ihl:]
        sp = struct.unpack_from('>H', tcp, 0)[0]
        dp = struct.unpack_from('>H', tcp, 2)[0]
        return sp, dp, tcp[(tcp[12] >> 4) * 4:]
    except: return None, None, None

sc_raw = b''
for pkt in raw_pkts:
    sp, dp, pay = tcp_payload(pkt)
    if sp == 30101 and pay: sc_raw += pay

def parse_frames(d):
    out = []; i = 0
    while i + 2 <= len(d):
        ln = struct.unpack_from('>H', d, i)[0]
        if ln == 0 or i + 2 + ln > len(d): i += 1; continue
        out.append(d[i+2:i+2+ln]); i += 2 + ln
    return out

sc_frames = parse_frames(sc_raw)

# ── protobuf decoder ──────────────────────────────────────────────
def read_varint(buf, pos):
    result = 0; shift = 0
    while pos < len(buf):
        b = buf[pos]; pos += 1
        result |= (b & 0x7f) << shift; shift += 7
        if not (b & 0x80): break
    return result, pos

def decode_proto(buf, depth=0, path=''):
    fields = {}; pos = 0
    indent = '  ' * depth
    while pos < len(buf):
        try:
            start = pos
            tag_wire, pos = read_varint(buf, pos)
            if tag_wire == 0: break
            fnum = tag_wire >> 3
            wtype = tag_wire & 7
            key = '{}{}'.format(path, fnum) if path else str(fnum)

            if wtype == 0:
                val, pos = read_varint(buf, pos)
                fields[key] = val

            elif wtype == 2:
                length, pos = read_varint(buf, pos)
                if length < 0 or pos + length > len(buf): break
                raw = buf[pos:pos+length]; pos += length

                # classify content
                printable = sum(1 for b in raw if 32 <= b < 127)
                ratio = printable / max(len(raw), 1)

                if len(raw) == 0:
                    fields[key] = ''
                elif ratio > 0.85 and len(raw) >= 3:
                    try:
                        s = raw.decode('utf-8')
                        fields[key] = s
                    except:
                        fields[key] = raw.decode('latin1', 'replace')
                elif len(raw) >= 2 and len(raw) <= 500:
                    # try nested proto
                    try:
                        nested = decode_proto(raw, depth+1, key+'.')
                        if nested:
                            fields[key] = nested
                        else:
                            fields[key] = raw.hex()
                    except:
                        fields[key] = raw.hex()
                else:
                    fields[key] = '[{}B binary]'.format(len(raw))

            elif wtype == 5:
                val = struct.unpack_from('<I', buf, pos)[0]; pos += 4
                fields[key] = val
            else:
                break
        except Exception as e:
            break
    return fields

def pretty(obj, indent=0):
    pad = '  ' * indent
    if isinstance(obj, dict):
        lines = []
        for k, v in obj.items():
            lines.append('{}{}: {}'.format(pad, k, pretty(v, indent+1) if isinstance(v, dict) else repr(v) if isinstance(v, str) and len(v) > 60 else v))
        return '\n' + '\n'.join(lines)
    return str(obj)

# ── analyse frames ─────────────────────────────────────────────────
frames_1d = [(i, f) for i, f in enumerate(sc_frames) if f and f[0] == 0x1d]
print('Total frames 0x1d S->C: {}'.format(len(frames_1d)))
print()

# bucket by size
small  = [(i,f) for i,f in frames_1d if len(f) <= 30]
medium = [(i,f) for i,f in frames_1d if 30 < len(f) <= 200]
large  = [(i,f) for i,f in frames_1d if len(f) > 200]

print('  pequenos (<=30B):   {}'.format(len(small)))
print('  medios (31-200B):   {}'.format(len(medium)))
print('  grandes (>200B):    {}'.format(len(large)))

# ── pequenos: provavelmente ACKs ou eventos simples ───────────────
print()
print('=' * 60)
print('PEQUENOS (<=30B) -- ACKs / eventos simples')
print('=' * 60)
for i, f in small[:20]:
    body = f[1:]  # skip opcode
    parsed = decode_proto(body)
    strings = [v for v in parsed.values() if isinstance(v, str) and v]
    print('  frame#{:3d} len={:3d}  fields={}  strings={}'.format(
        i, len(f), {k: v for k,v in parsed.items() if not isinstance(v, dict)},
        strings))

# ── medios: eventos com dados ─────────────────────────────────────
print()
print('=' * 60)
print('MEDIOS (31-200B) -- Eventos com payload')
print('=' * 60)
for i, f in medium[:15]:
    body = f[1:]
    parsed = decode_proto(body)
    print()
    print('  frame#{:3d} len={:3d}'.format(i, len(f)))
    # show flat fields + strings
    for k, v in sorted(parsed.items(), key=lambda x: x[0]):
        if isinstance(v, str) and len(v) > 0:
            print('    [{}] string: {!r}'.format(k, v[:120]))
        elif isinstance(v, int):
            print('    [{}] int: {}  (0x{:x})'.format(k, v, v))
        elif isinstance(v, dict):
            print('    [{}] nested: {} fields'.format(k, len(v)))
        else:
            pass

# ── grandes: sync de estado ───────────────────────────────────────
print()
print('=' * 60)
print('GRANDES (>200B) -- State sync / dados de jogo')
print('=' * 60)

# pegar os 5 maiores
top_large = sorted(large, key=lambda x: len(x[1]), reverse=True)[:5]

for i, f in top_large:
    body = f[1:]
    print()
    print('  frame#{:3d} len={:4d}B'.format(i, len(f)))

    # string scan direto (mais confiavel para frames grandes)
    str_re = re.compile(rb'[\x20-\x7e]{5,}')
    strings = [m.group().decode('latin1') for m in str_re.finditer(body)]
    # filtra ruido
    strings = [s for s in strings if not all(c in '0123456789abcdef' for c in s.lower())]
    if strings:
        print('  strings encontradas:')
        for s in strings[:30]:
            print('    {!r}'.format(s))

    # tenta protobuf nos primeiros 300B
    parsed = decode_proto(body[:300])
    if parsed:
        print('  proto fields (primeiros 300B):')
        for k, v in list(parsed.items())[:20]:
            if isinstance(v, str) and v:
                print('    [{}] {!r}'.format(k, v[:100]))
            elif isinstance(v, int):
                # tenta interpretar como timestamp unix
                if 1700000000 < v < 1900000000:
                    import datetime
                    dt = datetime.datetime.fromtimestamp(v).strftime('%Y-%m-%d %H:%M:%S')
                    print('    [{}] int={} (timestamp: {})'.format(k, v, dt))
                else:
                    print('    [{}] int={}'.format(k, v))

# ── frame especifico: o maior ─────────────────────────────────────
print()
print('=' * 60)
biggest = max(frames_1d, key=lambda x: len(x[1]))
bi, bf = biggest
print('MAIOR FRAME: #{} com {}B -- decode profundo'.format(bi, len(bf)))
print('=' * 60)
body = bf[1:]

# scan completo de strings
str_re = re.compile(rb'[\x20-\x7e]{4,}')
all_strings = [m.group().decode('latin1', 'replace') for m in str_re.finditer(body)]
interesting = [s for s in all_strings
               if len(s) >= 4
               and not s.startswith('000')
               and any(c.isalpha() for c in s)]

print('Strings no maior frame:')
seen = set()
for s in interesting:
    if s not in seen:
        seen.add(s)
        print('  {!r}'.format(s))

# tenta JSON embutido
json_re = re.compile(rb'\{[^\x00-\x1f]{4,400}\}')
for m in json_re.finditer(body):
    raw = m.group()
    if b':' in raw:
        print()
        print('JSON embutido: {}'.format(raw.decode('utf-8','replace')[:400]))
