"""
generate_dump_cs.py
Converte os JSONs do il2cpp_api_dump.js para dump.cs no estilo Il2CppDumper.
"""

import json
import glob
from pathlib import Path

INPUT_DIR  = "il2cpp_dump"
OUTPUT_FILE = "dump.cs"

ACCESS_FLAGS = {
    0x0001: "private",
    0x0002: "private",   # FamANDAssem
    0x0003: "internal",
    0x0004: "protected",
    0x0005: "protected internal",
    0x0006: "protected internal",
    0x0007: "public",
}

def field_access(flags_hex):
    if not flags_hex:
        return "public"
    f = int(flags_hex, 16)
    acc = f & 0x7
    return ACCESS_FLAGS.get(acc, "public")

def field_is_static(flags_hex):
    if not flags_hex:
        return False
    return bool(int(flags_hex, 16) & 0x10)

def format_method(m):
    static = "static " if m.get("is_static") else ""
    ret    = m.get("ret", "void")
    name   = m.get("name", "?")
    params = ", ".join(
        f"{p.get('type','?')} {p.get('name','')}" for p in m.get("params", [])
    )
    rva    = m.get("rva", "")
    addr   = m.get("addr", "")
    suffix = f" // RVA: {rva}" if rva else ""
    if addr and rva:
        suffix += f" VA: {addr}"
    return f"    public {static}{ret} {name}({params});{suffix}"

def format_field(fld):
    access = field_access(fld.get("flags"))
    static = "static " if field_is_static(fld.get("flags")) else ""
    typ    = fld.get("type", "?")
    name   = fld.get("name", "?")
    offset = fld.get("offset", "")
    suffix = f" // {offset}" if offset else ""
    return f"    {access} {static}{typ} {name};{suffix}"

def format_property(prop):
    name = prop.get("name", "?")
    return f"    public ? {name} {{ get; set; }}"  # type unknown from API

def format_class(cls, assembly_name):
    ns      = cls.get("namespace", "")
    name    = cls.get("name", "?")
    parent  = cls.get("parent", "")
    flags   = cls.get("flags", "")
    addr    = cls.get("addr", "")

    lines = []
    lines.append(f"// Namespace: {ns}")
    lines.append(f"// Assembly: {assembly_name}")
    if addr:
        lines.append(f"// TypeInfo: {addr}")

    inherits = f" : {parent}" if parent and parent not in ("Object", "ValueType", "Enum") else ""
    lines.append(f"public class {name}{inherits}")
    lines.append("{")

    fields = cls.get("fields", [])
    if fields:
        lines.append("    // Fields")
        for fld in fields:
            lines.append(format_field(fld))
        lines.append("")

    props = cls.get("properties", [])
    if props:
        lines.append("    // Properties")
        for p in props:
            lines.append(format_property(p))
        lines.append("")

    methods = cls.get("methods", [])
    if methods:
        lines.append("    // Methods")
        for m in methods:
            lines.append(format_method(m))

    lines.append("}")
    return "\n".join(lines)


def main():
    files = sorted(glob.glob(f"{INPUT_DIR}/*.json"))
    if not files:
        print(f"[!] Nenhum JSON em '{INPUT_DIR}/'")
        return

    total_classes  = 0
    total_methods  = 0

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.write("// IL2CPP dump gerado por il2cpp_api_dump.js + generate_dump_cs.py\n\n")

        for fpath in files:
            raw = Path(fpath).read_bytes()
            try:
                asm = json.loads(raw.decode("utf-8"))
            except Exception as e:
                print(f"[!] {fpath}: {e}")
                continue

            asm_name = asm.get("name", Path(fpath).stem)
            classes  = asm.get("classes", [])

            out.write(f"// ═══════════════════════════════════════════════\n")
            out.write(f"// {asm_name}  ({len(classes)} classes)\n")
            out.write(f"// ═══════════════════════════════════════════════\n\n")

            for cls in classes:
                out.write(format_class(cls, asm_name))
                out.write("\n\n")
                total_classes += 1
                total_methods += len(cls.get("methods", []))

            print(f"  {asm_name:<55} classes={len(classes):>5}")

    size_kb = Path(OUTPUT_FILE).stat().st_size / 1024
    print(f"\n[OK] {OUTPUT_FILE}  ({size_kb:.0f} KB)")
    print(f"     classes={total_classes}  métodos={total_methods}")


if __name__ == "__main__":
    main()
