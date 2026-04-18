"""
analyze_mitm.py  — lê .mitm e imprime requests/responses de forma legível.

Uso:
  python analyze_mitm.py traffic.mitm
  python analyze_mitm.py traffic.mitm --filter passport
  python analyze_mitm.py traffic.mitm --filter api
"""

import sys
import json
import argparse
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

try:
    from mitmproxy.io import FlowReader
    from mitmproxy.http import HTTPFlow
except ImportError:
    print("mitmproxy não instalado: pip install mitmproxy")
    sys.exit(1)

INTERESTING_HEADERS = {
    'authorization', 'x-token', 'token', 'cookie',
    'x-uid', 'x-device-id', 'x-user-id', 'x-session',
    'x-request-id', 'user-agent',
}

def fmt_body(body: bytes, content_type: str = '') -> str:
    if not body:
        return ''
    ct = content_type.lower()
    if 'json' in ct or 'text' in ct:
        text = body[:2000].decode('utf-8', errors='replace')
        try:
            parsed = json.loads(body)
            return json.dumps(parsed, indent=2, ensure_ascii=False)[:2000]
        except Exception:
            return text
    elif 'protobuf' in ct or 'octet' in ct or not ct:
        return body[:256].hex() + (f'  [{len(body)} bytes total]' if len(body) > 256 else '')
    return body[:500].decode('utf-8', errors='replace')

def analyze(mitm_file: str, filter_str: str = None):
    path = Path(mitm_file)
    if not path.exists():
        print(f"Arquivo não encontrado: {mitm_file}")
        sys.exit(1)

    total = 0
    shown = 0

    with open(path, 'rb') as f:
        reader = FlowReader(f)
        for flow in reader.stream():
            if not isinstance(flow, HTTPFlow):
                continue
            total += 1

            req = flow.request
            url = req.pretty_url

            if filter_str and filter_str.lower() not in url.lower():
                continue

            shown += 1
            print('-' * 80)
            print(f'#{shown}  {req.method} {url}')

            # Headers interessantes do request
            interesting = {k: v for k, v in req.headers.items()
                          if k.lower() in INTERESTING_HEADERS}
            if interesting:
                for k, v in interesting.items():
                    print(f'  req-header  {k}: {v}')

            req_body = req.get_content()
            if req_body:
                ct = req.headers.get('content-type', '')
                print(f'  req-body ({len(req_body)}B):')
                print('    ' + fmt_body(req_body, ct).replace('\n', '\n    '))

            if flow.response:
                resp = flow.response
                ct = resp.headers.get('content-type', '')
                resp_body = resp.get_content()
                print(f'  → {resp.status_code}  [{ct}]  {len(resp_body)}B')
                if resp_body:
                    print(f'  resp-body:')
                    print('    ' + fmt_body(resp_body, ct).replace('\n', '\n    '))
            else:
                print('  → (sem resposta capturada)')

    print('-' * 80)
    print(f'\nTotal: {total} flows  |  Exibidos: {shown}')
    if filter_str:
        print(f'(filtro: "{filter_str}")')

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('mitm_file')
    ap.add_argument('--filter', '-f', default=None, help='filtro de URL (substring)')
    args = ap.parse_args()
    analyze(args.mitm_file, args.filter)
