#!/usr/bin/env python3
"""Solve the 15 unknown early-table pairs of the metadata header and emit
a candidate global-metadata.dat. Validation: entry chaining, divisibility,
nameIndex bounds; final check = Il2CppDumper."""
import struct, sys

VER = sys.argv[1] if len(sys.argv) > 1 else "114"
dec = bytearray(open(f"/tmp/meta_dec_{VER}.bin", "rb").read())
N = len(dec)
print(f"{VER}: body={N:,}")

# v31 table order (pairs 0..32). Entry sizes (0 = raw data).
ORDER = ["stringLiteral", "stringLiteralData", "string", "events", "properties",
         "methods", "parameterDefaultValues", "fieldDefaultValues",
         "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters",
         "fields", "genericParameters", "genericParameterConstraints",
         "genericContainers", "nestedTypes", "interfaces", "vtableMethods",
         "interfaceOffsets", "typeDefinitions", "images", "assemblies", "fieldRefs"]
ESIZE = {"stringLiteral": 8, "stringLiteralData": 0, "string": 0, "events": 0x20,
         "properties": 0x1C, "methods": 0x34, "parameterDefaultValues": 0x10,
         "fieldDefaultValues": 0x10, "fieldAndParameterDefaultValueData": 0,
         "fieldMarshaledSizes": 8, "parameters": 0x10, "fields": 0x10,
         "genericParameters": 0xC, "genericParameterConstraints": 4,
         "genericContainers": 0xC, "nestedTypes": 4, "interfaces": 4,
         "vtableMethods": 4, "interfaceOffsets": 8, "typeDefinitions": 0x5C,
         "images": 0x40, "assemblies": 0x30, "fieldRefs": 0xC}

# 1) stringLiteral: chaining
i = 0x110
ln0, di0 = struct.unpack_from("<II", dec, i)
prev = di0 + ln0
i += 8
while i + 8 <= N:
    ln, di = struct.unpack_from("<II", dec, i)
    if ln > 0x10000 or di != prev:
        break
    prev = di + ln
    i += 8
sl_end = i
sld_size = prev
print(f"stringLiteral: 0x110..0x{sl_end:x} ({(sl_end-0x110)//8} entradas), data=0x{sld_size:x}")

# alinhamento 4
def a4(x): return (x + 3) & ~3
sld_start = a4(sl_end)
string_start = a4(sld_start + sld_size)
print(f"string table: inicia ~0x{string_start:x}")

# 2) fim da string table: varre até achar 256B sem cara de texto
def text_score(b):
    return sum(1 for x in b if 32 <= x[0] < 127 or x[0] == 0)
j = string_start
last_text = string_start
while j + 256 <= min(N, string_start + 0x2000000):
    w = dec[j:j+256]
    npr = sum(1 for x in w if 32 <= x < 127)
    nz = w.count(0)
    if npr > 200 and nz > 40:
        last_text = j + 256
    elif npr < 100:
        break
    j += 256
string_end_guess = a4(last_text)
print(f"string table: termina ~0x{string_end_guess:x}")

# 3) tabelas 3..14 (events..genericContainers): entrada de tamanho fixo, nameIndex u32
#    fit guloso: começa em string_end_guess, termina onde par15 (conhecido) começa
known = struct.unpack_from("<II", dec, 128)  # par[15]
final_off = known[0]
print(f"tabela[15] (nestedTypes) em 0x{final_off:x}, tamanho 0x{known[1]:x}")

mid = ORDER[3:15]  # 12 tabelas de tamanho fixo
# bounds: cada tamanho divisível pelo ESIZE e nameIndex < string_size quando aplicável
start = string_end_guess
bounds = [start]
for t in mid:
    es = ESIZE[t]
    # procura o menor fim > start com (fim-start) % es == 0 e cujo INÍCIO da
    # próxima tabela pareça tabela (heurística: próxima entry nameIndex válido)
    # abordagem direta: achata — sem sinal forte, assume contíguo e resolve por
    # programação: deixa para validação; por agora registra range
    bounds.append(None)

# abordagem com constraint global: soma dos 12 tamanhos = final_off - string_end_guess
total_mid = final_off - string_end_guess
print(f"12 tabelas intermediárias: 0x{total_mid:x} bytes a particionar")

# fit por nameIndex: events/properties/methods/parameters/fields têm nameIndex no início
# varre candidatos de fronteira onde um u32 == string_table_size (fim de string) aparece como
# transição — simplificação: para este passo, escreve o header com particionamento
# PROPORCIONAL e marca TODO; a validação real vem do Il2CppDumper iterativo.
sizes_mid = []
remaining = total_mid
for k, t in enumerate(mid[:-1]):
    es = ESIZE[t]
    # heurística: usa nameIndex máximo observável na região como pista de contagem
    sizes_mid.append(None)

print("→ gerando header com: SL/SLD/string resolvidos; intermediárias = contiguidade forçada")
# pares 0..2 conhecidos; 3..14: particiona dividindo total_mid proporcionalmente aos
# tamanhos típicos não funciona — então: USA a solução de contiguidade + tamanhos múltiplos:
# aloca cada tabela com o MAIOR tamanho múltiplo que preserva >= 4*es para as restantes
# alocação proporcional por pesos típicos (methods domina), snap por entry-size
WEIGHTS = {"events": 2, "properties": 2, "methods": 30, "parameterDefaultValues": 6,
           "fieldDefaultValues": 6, "fieldAndParameterDefaultValueData": 3,
           "fieldMarshaledSizes": 1, "parameters": 12, "fields": 10,
           "genericParameters": 4, "genericParameterConstraints": 2, "genericContainers": 2}
alloc = []
rem = total_mid
wsum = sum(WEIGHTS[t] for t in mid)
for k, t in enumerate(mid):
    es = max(ESIZE[t], 1)
    if k == len(mid) - 1:
        take = rem
    else:
        take = int(total_mid * WEIGHTS[t] / wsum)
        take -= take % es
    alloc.append(take)
    rem -= take
sizes = [sl_end - 0x110, sld_size, string_end_guess - string_start] + alloc
offs = []
o = 0x110
for s in sizes:
    offs.append(o)
    o = a4(o + s)
print("pares 0..14 propostos:")
for k in range(15):
    print(f"  par[{k}] {ORDER[k]:36} (0x{offs[k]:x}, 0x{sizes[k]:x})")

# monta o arquivo final
out = bytearray()
out += struct.pack("<II", 0xFAB11BAF, 31)
for k in range(len(ORDER)):
    if k < 15:
        out += struct.pack("<II", offs[k], sizes[k])
    else:
        out += dec[128 + (k-15)*8 : 128 + (k-15)*8 + 8]
out += bytes(dec[0x110:])
assert len(out) == 8 + 8 * len(ORDER) + (N - 0x110), (len(out), N)
path = f"/home/re/work/apk/global_metadata_{VER}_rebuilt.dat"
open(path, "wb").write(bytes(out))
print(f"→ {path} ({len(out):,} bytes)")
