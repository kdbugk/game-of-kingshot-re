"""
search_dump.py
Busca nos JSONs do il2cpp_api_dump por classes e métodos relevantes.
Mostra RVAs prontos para usar no Ghidra (base 0x100000).

Uso:
  python search_dump.py                        # mostra assemblies disponíveis
  python search_dump.py --assembly dd.sdk      # filtra por nome de assembly
  python search_dump.py --class Network        # filtra por nome de classe
  python search_dump.py --method Request       # filtra por nome de método
  python search_dump.py --rva 0x4a3bc0         # busca pelo RVA
  python search_dump.py --assembly Assembly-CSharp --method Send
"""

import json, glob, argparse, sys
from pathlib import Path

INPUT_DIR  = "il2cpp_dump"
IL2CPP_BASE_GHIDRA = 0x100000  # base padrão do Ghidra


def rva_to_ghidra(rva_str):
    """Converte '0x4a3bc0' para endereço Ghidra com base 0x100000."""
    if not rva_str:
        return ""
    try:
        rva = int(rva_str, 16)
        return f"0x{(IL2CPP_BASE_GHIDRA + rva):x}"
    except ValueError:
        return rva_str


def load_assemblies(name_filter=None):
    files = sorted(glob.glob(f"{INPUT_DIR}/*.json"))
    for fpath in files:
        raw = Path(fpath).read_bytes()
        try:
            asm = json.loads(raw.decode("utf-8"))
        except Exception:
            continue
        asm_name = asm.get("name", "")
        if name_filter and name_filter.lower() not in asm_name.lower():
            continue
        yield asm


def print_class(asm_name, cls, method_filter=None, show_fields=True):
    ns       = cls.get("namespace", "")
    fullname = cls.get("fullName", cls.get("name", "?"))
    methods  = cls.get("methods", [])
    fields   = cls.get("fields", [])

    matched_methods = [
        m for m in methods
        if not method_filter or method_filter.lower() in m.get("name", "").lower()
    ]
    if method_filter and not matched_methods:
        return

    print(f"\n  [{asm_name}]  {fullname}")

    if show_fields and fields:
        print(f"    Fields ({len(fields)}):")
        for f in fields[:20]:
            offset = f.get("offset", "")
            suffix = f" // {offset}" if offset else ""
            print(f"      {f.get('type','?')} {f.get('name','?')}{suffix}")
        if len(fields) > 20:
            print(f"      ... +{len(fields)-20} mais")

    if matched_methods:
        label = f"Methods ({len(matched_methods)}" + (f"/{len(methods)}" if method_filter else "") + "):"
        print(f"    {label}")
        for m in matched_methods:
            static = "static " if m.get("is_static") else ""
            ret    = m.get("ret", "void")
            name   = m.get("name", "?")
            params = ", ".join(
                f"{p.get('type','?')} {p.get('name','')}" for p in m.get("params", [])
            )
            rva    = m.get("rva", "")
            ghidra = rva_to_ghidra(rva)
            print(f"      {static}{ret} {name}({params})")
            if ghidra:
                print(f"        RVA={rva}  Ghidra={ghidra}")


def cmd_list_assemblies():
    print(f"\n{'Assembly':<55} {'classes':>8} {'methods':>9}")
    print("-" * 75)
    total_cls = total_meth = 0
    for asm in load_assemblies():
        classes  = asm.get("classes", [])
        n_meth   = sum(len(c.get("methods", [])) for c in classes)
        total_cls  += len(classes)
        total_meth += n_meth
        print(f"  {asm['name']:<53} {len(classes):>8,} {n_meth:>9,}")
    print("-" * 75)
    print(f"  {'TOTAL':<53} {total_cls:>8,} {total_meth:>9,}")


def cmd_search(args):
    found_classes = 0
    for asm in load_assemblies(args.assembly):
        for cls in asm.get("classes", []):
            name = cls.get("name", "")
            ns   = cls.get("namespace", "")
            full = cls.get("fullName", name)

            if args.cls and args.cls.lower() not in full.lower():
                continue

            print_class(
                asm["name"], cls,
                method_filter=args.method,
                show_fields=not args.no_fields,
            )
            found_classes += 1

    print(f"\n[total: {found_classes} classe(s) encontrada(s)]")


def cmd_rva(rva_str):
    target = rva_str.lower().lstrip("0x")
    for asm in load_assemblies():
        for cls in asm.get("classes", []):
            for m in cls.get("methods", []):
                rva = m.get("rva", "").lower().lstrip("0x")
                if rva == target:
                    ns   = cls.get("namespace", "")
                    full = cls.get("fullName", cls.get("name", "?"))
                    name = m.get("name", "?")
                    print(f"\n  [{asm['name']}]  {full}.{name}")
                    print(f"  RVA={m['rva']}  Ghidra={rva_to_ghidra(m['rva'])}")
                    return
    print(f"[!] RVA {rva_str} não encontrado")


def main():
    if len(sys.argv) == 1:
        cmd_list_assemblies()
        print("\nUso: python search_dump.py --help")
        return

    parser = argparse.ArgumentParser(description="Busca no dump IL2CPP")
    parser.add_argument("--assembly", "-a", help="Filtro parcial no nome do assembly")
    parser.add_argument("--class",    "-c", dest="cls", help="Filtro parcial no nome da classe")
    parser.add_argument("--method",   "-m", help="Filtro parcial no nome do método")
    parser.add_argument("--rva",      "-r", help="Buscar por RVA exato (ex: 0x4a3bc0)")
    parser.add_argument("--no-fields", action="store_true", help="Omitir campos")
    args = parser.parse_args()

    if args.rva:
        cmd_rva(args.rva)
    else:
        cmd_search(args)


if __name__ == "__main__":
    main()
