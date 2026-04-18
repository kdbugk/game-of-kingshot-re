"""
analyze_gateway.py

Analisa o pcap capturado na porta 30101 (game gateway).
Reconstrói as streams TCP, identifica framing e decodifica mensagens.

Framing detectado: uint16_BE(length) + body  (sem o próprio header de 2B no len)

Uso:
  python analyze_gateway.py battle.pcap
  python analyze_gateway.py gateway_20260414_224120.pcap
"""

import sys
import struct
from pathlib import Path
from collections import defaultdict, Counter

# Fix Windows console encoding
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── configuracao ──────────────────────────────────────────────────────────────

PCAP_FILE   = sys.argv[1] if len(sys.argv) > 1 else "battle.pcap"
TARGET_PORT = {30101, 31601}
MAX_DUMP    = 128  # bytes por hexdump

# ── helpers ───────────────────────────────────────────────────────────────────

def hexdump(data, indent="  ", max_b=MAX_DUMP):
    view = data[:max_b]
    out  = []
    for i in range(0, len(view), 16):
        chunk    = view[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        out.append(f"{indent}{i:04x}  {hex_part:<48}  |{asc_part}|")
    if len(data) > max_b:
        out.append(f"{indent}... ({len(data)} bytes total)")
    return "\n".join(out)

def strings(data, min_len=4):
    res, cur = [], []
    for b in data:
        if 0x20 <= b < 0x7f:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                res.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        res.append("".join(cur))
    return res

# ── leitura do pcap (parse manual, sem dpkt) ──────────────────────────────────

def read_pcap(path):
    """Lê pcap manualmente (format clássico v2.4). Retorna lista de (ts, raw_bytes)."""
    with open(path, "rb") as f:
        data = f.read()

    magic = struct.unpack_from("<I", data)[0]
    if magic == 0xa1b2c3d4:
        endian = "<"
    elif magic == 0xd4c3b2a1:
        endian = ">"
    else:
        raise ValueError(f"Magic pcap desconhecido: {magic:08x}")

    _, _, _, _, _, snaplen, linktype = struct.unpack_from(f"{endian}IHHiIII", data, 0)

    pkts = []
    pos  = 24
    while pos + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(f"{endian}IIII", data, pos)
        pos  += 16
        raw   = data[pos:pos+incl_len]
        pos  += incl_len
        pkts.append((ts_sec + ts_usec / 1_000_000, raw))

    return pkts, linktype

# ── extração de payloads TCP ──────────────────────────────────────────────────

def extract_tcp(pkts, linktype, target_ports):
    """Retorna lista de (ts, direction, stream_id, seq, payload_bytes)."""
    result = []
    stream_map = {}  # (src, dst) -> id

    for ts, raw in pkts:
        # Offset IP depende do linktype
        if linktype == 113:   # Linux SLL
            if len(raw) < 16:
                continue
            etype = struct.unpack_from(">H", raw, 14)[0]
            if etype != 0x0800:
                continue
            ip_off = 16
        elif linktype == 1:   # Ethernet
            if len(raw) < 14:
                continue
            etype = struct.unpack_from(">H", raw, 12)[0]
            if etype != 0x0800:
                continue
            ip_off = 14
        else:
            continue

        if len(raw) < ip_off + 20:
            continue

        ip_ihl  = (raw[ip_off] & 0x0f) * 4
        proto   = raw[ip_off + 9]
        if proto != 6:   # TCP
            continue

        src_ip = ".".join(str(raw[ip_off + 12 + i]) for i in range(4))
        dst_ip = ".".join(str(raw[ip_off + 16 + i]) for i in range(4))

        tcp_off = ip_off + ip_ihl
        if len(raw) < tcp_off + 20:
            continue

        sport    = struct.unpack_from(">H", raw, tcp_off)[0]
        dport    = struct.unpack_from(">H", raw, tcp_off + 2)[0]
        seq      = struct.unpack_from(">I", raw, tcp_off + 4)[0]
        flags    = raw[tcp_off + 13]
        doff     = ((raw[tcp_off + 12] >> 4) & 0xf) * 4
        payload  = raw[tcp_off + doff:]

        if sport not in target_ports and dport not in target_ports:
            continue

        src = f"{src_ip}:{sport}"
        dst = f"{dst_ip}:{dport}"

        if dport in target_ports:
            direction  = "C->S"
            stream_key = (src, dst)
        else:
            direction  = "S->C"
            stream_key = (dst, src)   # sempre (client, server)

        if stream_key not in stream_map:
            stream_map[stream_key] = len(stream_map)

        sid = stream_map[stream_key]
        result.append((ts, direction, sid, stream_key, seq, flags, payload))

    return result, stream_map

# ── reassembly de streams TCP ─────────────────────────────────────────────────

def reassemble_streams(pkt_list):
    """
    Retorna dict: sid -> {"c2s": bytes, "s2c": bytes, "key": stream_key,
                          "c2s_segs": [(ts, seq, data)], "s2c_segs": [...]}
    """
    raw = defaultdict(lambda: {"c2s": [], "s2c": [], "key": None})
    for ts, direction, sid, stream_key, seq, flags, payload in pkt_list:
        raw[sid]["key"] = stream_key
        if payload:
            raw[sid][direction.lower().replace("->", "2")].append((ts, seq, payload))

    streams = {}
    for sid, st in raw.items():
        def reassemble(segs):
            seen = {}
            for ts, seq, data in segs:
                if seq not in seen:
                    seen[seq] = (ts, data)
            ordered = sorted(seen.items())   # by seq
            return b"".join(d for _, (_, d) in ordered), [(t, s, d) for s, (t, d) in ordered]

        c2s_bytes, c2s_segs = reassemble(st["c2s"])
        s2c_bytes, s2c_segs = reassemble(st["s2c"])
        streams[sid] = {
            "key":       st["key"],
            "c2s":       c2s_bytes,
            "s2c":       s2c_bytes,
            "c2s_segs":  c2s_segs,
            "s2c_segs":  s2c_segs,
        }
    return streams

# ── parser de frames ──────────────────────────────────────────────────────────

def parse_frames_be2(data):
    """Framing: uint16_BE(length) + body de `length` bytes."""
    frames = []
    pos    = 0
    while pos + 2 <= len(data):
        flen = struct.unpack_from(">H", data, pos)[0]
        end  = pos + 2 + flen
        if end > len(data):
            # Frame truncado — captura parcial
            frames.append((pos, flen, data[pos+2:], True))   # truncado=True
            break
        frames.append((pos, flen, data[pos+2:end], False))
        pos = end
    return frames

# ── análise de opcodes ────────────────────────────────────────────────────────

def decode_varint(data, pos):
    result, shift = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7f) << shift
        shift  += 7
        if not (b & 0x80):
            return result, pos
    return None, pos

def describe_frame(body):
    """Tenta extrair opcode/tipo de uma mensagem."""
    if not body:
        return "empty"

    # Byte 0 como opcode direto
    op = body[0]

    # Strings legíveis
    strs = strings(body, min_len=4)

    # Tenta decodificar como sequência varint
    varints = []
    pos = 0
    for _ in range(8):
        if pos >= len(body):
            break
        v, new_pos = decode_varint(body, pos)
        if v is None or new_pos == pos:
            break
        varints.append(v)
        pos = new_pos

    return {
        "op":      op,
        "hex4":    body[:4].hex(),
        "strings": strs[:6],
        "varints": varints[:8],
        "len":     len(body),
    }

# ── display ───────────────────────────────────────────────────────────────────

def print_frames(frames, label, show_all=False, max_frames=60):
    print(f"\n{'='*64}")
    print(f"  {label}  ({len(frames)} frames)")
    print(f"  {'#':>4}  {'offset':>8}  {'len':>6}  {'op':>4}  {'hex[0:8]':<18}  strings")
    print(f"  {'─'*4}  {'─'*8}  {'─'*6}  {'─'*4}  {'─'*18}  {'─'*30}")
    for i, (offset, flen, body, trunc) in enumerate(frames[:max_frames]):
        op   = body[0] if body else 0
        hex4 = body[:8].hex() if body else ""
        strs = strings(body, min_len=4)
        str_hint = " | ".join(strs[:3])[:40]
        trunc_mark = "✂" if trunc else " "
        print(f"  {i:>4}  {offset:>8x}  {flen:>6}  {op:>4x}  {hex4:<18}  {str_hint} {trunc_mark}")
    if len(frames) > max_frames:
        print(f"  ... ({len(frames) - max_frames} frames omitidos)")

def print_frame_detail(body, label):
    print(f"\n  ── {label} ({len(body)}B) ──")
    print(hexdump(body, indent="    ", max_b=256))
    strs = strings(body, min_len=4)
    if strs:
        print(f"    strings: {strs[:15]}")
    # Varint walk
    varints = []
    pos = 0
    for _ in range(20):
        if pos >= len(body): break
        v, new_pos = decode_varint(body, pos)
        if v is None or new_pos == pos: break
        varints.append((pos, v))
        pos = new_pos
    if varints:
        print(f"    varint walk: {[(f'@{o}={v}' if v < 10000 else f'@{o}={v:#x}') for o, v in varints]}")

# ── análise de heartbeat ──────────────────────────────────────────────────────

def analyze_heartbeats(pkt_list, streams, t0):
    """Detecta padrão de heartbeat a partir de pacotes pequenos C->S."""
    print(f"\n{'#'*64}")
    print("  HEARTBEAT / PACOTES PEQUENOS C->S (≤ 16B)")
    print(f"{'#'*64}")

    small = [(ts, payload) for ts, direction, sid, _, seq, _, payload
             in pkt_list if direction == "C->S" and 4 <= len(payload) <= 16]

    if not small:
        print("  Nenhum pacote pequeno encontrado.")
        return

    hex_cnt = Counter(p.hex() for _, p in small)
    print(f"  {len(small)} pacotes pequenos. Top padrões:")
    for hex_val, cnt in hex_cnt.most_common(15):
        b = bytes.fromhex(hex_val)
        print(f"    {cnt:4}x  [{len(b)}B]  {hex_val}  {b!r}  strings={strings(b)}")

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    pcap_path = Path(PCAP_FILE)
    if not pcap_path.exists():
        print(f"Arquivo nao encontrado: {PCAP_FILE}")
        sys.exit(1)

    print(f"{'#'*64}")
    print(f"  Analisando: {PCAP_FILE} ({pcap_path.stat().st_size:,} bytes)")
    print(f"{'#'*64}")

    pkts, linktype = read_pcap(str(pcap_path))
    print(f"  Total pcap:  {len(pkts)} pacotes  linktype={linktype}")

    pkt_list, stream_map = extract_tcp(pkts, linktype, TARGET_PORT)
    print(f"  Porta alvo:  {len(pkt_list)} pacotes  {len(stream_map)} stream(s)")

    if not pkt_list:
        print("  Nenhum tráfego TCP encontrado. Verifique o filtro de portas.")
        sys.exit(1)

    streams = reassemble_streams(pkt_list)
    t0 = pkt_list[0][0]

    # ── sumário de pacotes raw ─────────────────────────────────────────────
    print(f"\n{'─'*64}")
    print("  PACOTES RAW (primeiros 50 com payload)")
    print(f"  {'#':>3}  {'t (s)':>9}  {'dir':>5}  {'sid':>3}  {'bytes':>6}  {'hex[0:10]':<22}  strings")
    print(f"  {'─'*3}  {'─'*9}  {'─'*5}  {'─'*3}  {'─'*6}  {'─'*22}  {'─'*30}")
    shown = 0
    for ts, direction, sid, stream_key, seq, flags, payload in pkt_list:
        if not payload:
            continue
        strs = strings(payload, min_len=5)
        str_hint = " | ".join(strs[:2])[:30]
        print(f"  {shown:>3}  {ts-t0:>9.3f}  {direction:>5}  {sid:>3}  "
              f"{len(payload):>6}  {payload[:10].hex():<22}  {str_hint}")
        shown += 1
        if shown >= 50:
            print("  ...")
            break

    # ── análise por stream ─────────────────────────────────────────────────
    for sid, st in sorted(streams.items()):
        key      = st["key"]
        c2s_data = st["c2s"]
        s2c_data = st["s2c"]

        print(f"\n\n{'#'*64}")
        print(f"  STREAM {sid}: {key[0]}  ->  {key[1]}")
        print(f"  C->S: {len(c2s_data):,} bytes  |  S->C: {len(s2c_data):,} bytes")
        print(f"{'#'*64}")

        c2s_frames = parse_frames_be2(c2s_data)
        s2c_frames = parse_frames_be2(s2c_data)

        print_frames(c2s_frames, f"C->S frames (stream {sid})")
        print_frames(s2c_frames, f"S->C frames (stream {sid})")

        # Detalha os primeiros frames importantes
        print(f"\n  ── DETALHE DOS PRIMEIROS FRAMES ──")

        if c2s_frames:
            print_frame_detail(c2s_frames[0][2], f"C->S[0] handshake ({c2s_frames[0][1]}B)")

        if len(c2s_frames) > 1:
            print_frame_detail(c2s_frames[1][2], f"C->S[1] ({c2s_frames[1][1]}B)")

        if len(c2s_frames) > 2:
            print_frame_detail(c2s_frames[2][2], f"C->S[2] ({c2s_frames[2][1]}B)")

        if s2c_frames:
            print_frame_detail(s2c_frames[0][2], f"S->C[0] ({s2c_frames[0][1]}B)")

        if len(s2c_frames) > 1:
            print_frame_detail(s2c_frames[1][2], f"S->C[1] ({s2c_frames[1][1]}B)")

        # Estatísticas de opcodes
        print(f"\n  ── DISTRIBUIÇÃO DE OPCODES ──")
        c2s_ops = Counter(f[2][0] for f in c2s_frames if f[2])
        s2c_ops = Counter(f[2][0] for f in s2c_frames if f[2])
        print(f"  C->S opcodes (byte[0]): {dict(c2s_ops.most_common(15))}")
        print(f"  S->C opcodes (byte[0]): {dict(s2c_ops.most_common(15))}")

        # Tamanhos de frames
        c2s_sizes = Counter(f[1] for f in c2s_frames)
        s2c_sizes = Counter(f[1] for f in s2c_frames)
        print(f"\n  C->S tamanhos: {dict(sorted(c2s_sizes.items()))}")
        print(f"  S->C tamanhos top-10: {dict(s2c_sizes.most_common(10))}")

        # Todos os strings das mensagens S->C
        all_strs_s2c = []
        for _, _, body, _ in s2c_frames:
            all_strs_s2c.extend(strings(body, min_len=5))
        strs_cnt = Counter(all_strs_s2c)
        if strs_cnt:
            print(f"\n  Strings mais frequentes S->C: {dict(strs_cnt.most_common(20))}")

    # ── análise de heartbeat global ────────────────────────────────────────
    analyze_heartbeats(pkt_list, streams, t0)

    # ── resumo final ──────────────────────────────────────────────────────
    print(f"\n\n{'#'*64}")
    print("  RESUMO DO PROTOCOLO")
    print(f"{'#'*64}")
    total_c2s = sum(len(st["c2s"]) for st in streams.values())
    total_s2c = sum(len(st["s2c"]) for st in streams.values())
    total_c2s_frames = sum(len(parse_frames_be2(st["c2s"])) for st in streams.values())
    total_s2c_frames = sum(len(parse_frames_be2(st["s2c"])) for st in streams.values())
    print(f"  Streams:   {len(streams)}")
    print(f"  C->S:      {total_c2s:,} bytes  /  {total_c2s_frames} frames")
    print(f"  S->C:      {total_s2c:,} bytes  /  {total_s2c_frames} frames")
    print(f"  Framing:   uint16_BE(length) + body")

if __name__ == "__main__":
    main()
