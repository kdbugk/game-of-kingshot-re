"""
decode_1d_v2.py
Abordagem raw: ignora protobuf, faz scan direto dos bytes
para extrair strings, inteiros e padroes nos frames 0x1d.
"""
import sys, struct, re, datetime
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
frames_1d = [(i, f) for i, f in enumerate(sc_frames) if f and f[0] == 0x1d]

# ── header pattern dos frames 0x1d ───────────────────────────────
print('=' * 70)
print('HEADER PATTERN -- primeiros 10 bytes de cada frame 0x1d')
print('=' * 70)
print('{:5s} {:5s} {:3s} {:3s}  {}'.format('frame','len','[1]','[2]','hex[0:16]'))
for i, f in frames_1d[:40]:
    b1 = f[1] if len(f) > 1 else 0
    b2 = f[2] if len(f) > 2 else 0
    print('{:5d} {:5d} {:3d} {:3d}  {}'.format(i, len(f), b1, b2, f[:16].hex()))

# ── read_varint helper ────────────────────────────────────────────
def read_varint(buf, pos):
    result = 0; shift = 0
    while pos < len(buf):
        b = buf[pos]; pos += 1
        result |= (b & 0x7f) << shift; shift += 7
        if not (b & 0x80): break
    return result, pos

def varint_walk(buf, max_steps=30):
    vals = []; pos = 0
    for _ in range(max_steps):
        if pos >= len(buf): break
        v, pos = read_varint(buf, pos)
        vals.append(v)
    return vals

# ── structure de um frame medio tipico ───────────────────────────
print()
print('=' * 70)
print('ESTRUTURA DETALHADA -- frames medios selecionados')
print('=' * 70)

medium = [(i, f) for i, f in frames_1d if 30 < len(f) <= 200]

for i, f in medium[:8]:
    print()
    print('frame#{:3d}  len={:3d}  hex:'.format(i, len(f)))
    for j in range(0, len(f), 16):
        h = ' '.join('{:02x}'.format(b) for b in f[j:j+16])
        a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in f[j:j+16])
        print('  {:04x}  {:<48}  |{}|'.format(j, h, a))
    # varint walk
    vals = varint_walk(f[2:])  # pula opcode + direction byte
    print('  varints (skip 2): {}'.format(vals[:20]))
    # uint32 LE scan
    u32s = []
    for j in range(0, len(f)-3, 4):
        v = struct.unpack_from('<I', f, j)[0]
        if 1700000000 < v < 1900000000:
            u32s.append((j, v, datetime.datetime.fromtimestamp(v).strftime('%Y-%m-%d %H:%M')))
        elif 900 < v < 1000:  # reino
            u32s.append((j, v, 'reino?'))
    if u32s:
        print('  u32 interessantes: {}'.format(u32s))

# ── frame maior: scan por todos os tipos de dado ─────────────────
print()
print('=' * 70)
print('MAIOR FRAME (#100, 3824B) -- scan completo por tipo')
print('=' * 70)

big = sc_frames[100]
body = big[1:]  # skip opcode

print('Opcode: 0x{:02x}, total {}B'.format(big[0], len(big)))
print()

# 1. todas as strings ASCII >= 4 chars
str_re = re.compile(rb'[\x20-\x7e]{4,}')
all_str = [(m.start(), m.group().decode('latin1')) for m in str_re.finditer(body)]
print('[STRINGS]  {} encontradas:'.format(len(all_str)))
seen = set()
for offset, s in all_str:
    if s not in seen and any(c.isalpha() for c in s):
        seen.add(s)
        print('  +0x{:04x}  {!r}'.format(offset, s[:80]))

# 2. timestamps unix (LE u32)
print()
print('[TIMESTAMPS LE-u32]')
for j in range(0, len(body)-3, 1):
    v = struct.unpack_from('<I', body, j)[0]
    if 1700000000 < v < 1900000000:
        dt = datetime.datetime.fromtimestamp(v).strftime('%Y-%m-%d %H:%M:%S')
        print('  +0x{:04x}  {}  ({})'.format(j, v, dt))

# 3. numeros grandes (BE u32) que possam ser UIDs
print()
print('[UIDS / numeros grandes BE-u32 > 1M]')
seen_uids = set()
for j in range(0, len(body)-3, 1):
    v = struct.unpack_from('>I', body, j)[0]
    if 1000000 < v < 999999999 and v not in seen_uids:
        seen_uids.add(v)
        print('  +0x{:04x}  {}'.format(j, v))
    if len(seen_uids) > 30: break

# 4. estrutura dos primeiros 64 bytes
print()
print('[PRIMEIROS 64B em detalhe]')
for j in range(0, min(64, len(body)), 16):
    h = ' '.join('{:02x}'.format(b) for b in body[j:j+16])
    a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in body[j:j+16])
    print('  {:04x}  {:<48}  |{}|'.format(j, h, a))

# ── comparar headers dos grandes frames ──────────────────────────
print()
print('=' * 70)
print('COMPARAR HEADERS -- frames grandes (>200B)')
print('=' * 70)
large = sorted([(i,f) for i,f in frames_1d if len(f) > 200], key=lambda x: x[0])
for i, f in large:
    vals = varint_walk(f[2:], 8)
    strs = re.findall(rb'[\x20-\x7e]{5,}', f[:80])
    strs_dec = [s.decode('latin1') for s in strs]
    print('  frame#{:3d} {:4d}B  varints={:30s}  strings={}'.format(
        i, len(f), str(vals[:6]), strs_dec[:3]))
