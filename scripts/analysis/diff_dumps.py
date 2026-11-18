#!/usr/bin/env python3
"""Diff the old (custom Frida api-dump) IL2CPP dump against the new (Il2CppDumper) dump.

Old format : il2cpp_dump/*.json  {"name": asm, "classes":[{"fullName","namespace","methods":[{"name","rva"}]}]}
New format : Il2CppDumper dump.cs  (blocks: // RVA: 0x... lines + class/method declarations)

Usage:
  diff_dumps.py old-dir new-dump.cs > report.md
"""
import json, re, sys, glob, os
from collections import defaultdict

def load_old(old_dir):
    """-> {asm: {(classFqn, method): rva}}"""
    out = {}
    for path in sorted(glob.glob(os.path.join(old_dir, "*.json"))):
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception as e:
            print(f"WARNING: cannot parse {path}: {e}", file=sys.stderr)
            continue
        asm = data.get("name", os.path.basename(path))
        classes = {}
        for c in data.get("classes", []):
            fqn = (c.get("namespace", "") + "." + c["name"]).lstrip(".")
            for m in c.get("methods", []):
                classes[(fqn, m["name"])] = m.get("rva", "")
        out[asm] = classes
    return out

NEW_BLOCK = re.compile(r"^// RVA: 0x([0-9A-Fa-f]+)")
CLASS_RE = re.compile(
    r"^(?:public|private|protected|internal|static|sealed|abstract|ref|readonly|interface|class|struct|enum|\s)+"
    r"(?:class|struct|interface|enum)\s+([A-Za-z_0-9<>,\s.+]+?)\s*(?::|\{|$)", re.M)

def load_new(dump_cs):
    """-> {asm: {(classFqn, method): rva}}"""
    out = defaultdict(dict)
    cur_asm, cur_class, rva = None, None, None
    class_decl = re.compile(r"^(?:\[[^\]]*\]\s*)?(?:public|private|protected|internal|sealed|abstract|static|partial|ref|readonly| )*"
                            r"(class|struct|interface|enum)\s+([A-Za-z_][\w.<>, `]*?)"
                            r"\s*(?::[^{]*)?\{?\s*$")
    method_decl = re.compile(r"^\s{4,}(?:[A-Za-z_][\w.<>\[\], ]*\s+)?([A-Za-z_][\w]*)\s*(?:<[^>]*>)?\(")
    for line in open(dump_cs, encoding="utf-8", errors="replace"):
        s = line.rstrip()
        m = NEW_BLOCK.match(s)
        if m:
            rva = "0x" + m.group(1).lower()
            continue
        m = re.match(r"^// Assembly: (.+)$", s) or re.match(r"^// Image \d+: (.+?) - ", s)
        if m:
            continue
        m = class_decl.match(s)
        if m and not s.startswith("    "):
            cur_class = m.group(2).split("<")[0].strip()
            continue
        # assembly context: Il2CppDumper groups by '// Image N: name'
        m = re.match(r"^// Image \d+: ([\w.]+)", s)
        if m:
            cur_asm = m.group(1)
            continue
        m = method_decl.match(s)
        if m and cur_class:
            name = m.group(1)
            if name not in ("get", "set", "add", "remove"):
                out[cur_asm or "?"][(cur_class, name)] = rva or ""
            rva = None
    return dict(out)

def fqn_counts(d):
    """-> {(class, method): rva} flattened"""
    flat = {}
    for asm, classes in d.items():
        for (cls, meth), rva in classes.items():
            flat.setdefault((cls, meth), []).append(asm)
    return flat

INTEREST = re.compile(r"gateway|socket|opcode|packet|protocol|message|nesec|nethtp|http|network|certif|ifr|ifix|encrypt|decrypt|login|auth|battle|heartbeat|proto", re.I)

def main():
    old_dir, new_cs = sys.argv[1], sys.argv[2]
    old = load_old(old_dir)
    new = load_new(new_cs)
    old_flat, new_flat = fqn_counts(old), fqn_counts(new)

    old_keys, new_keys = set(old_flat), set(new_flat)
    added = new_keys - old_keys
    removed = old_keys - new_keys

    old_classes = {c for c, _ in old_keys}
    new_classes = {c for c, _ in new_keys}

    print(f"# IL2CPP dump diff (old -> new)\n")
    print(f"- methods old: {len(old_keys)}  new: {len(new_keys)}")
    print(f"- methods added: {len(added)}  removed: {len(removed)}")
    print(f"- classes old: {len(old_classes)}  new: {len(new_classes)}  added: {len(new_classes-old_classes)}  removed: {len(old_classes-new_classes)}\n")

    print("## Classes added (interesting)")
    for c in sorted(new_classes - old_classes):
        if INTEREST.search(c):
            print(f"+ {c}")
    print("\n## Classes removed (interesting)")
    for c in sorted(old_classes - new_classes):
        if INTEREST.search(c):
            print(f"- {c}")

    print("\n## Interesting methods added")
    for (c, m) in sorted(added):
        if INTEREST.search(c) or INTEREST.search(m):
            print(f"+ {c}::{m}  [{new_flat[(c,m)][0]}] rva={next((r for (cc,mm),r in [(k,v) for k,v in []]), '')}")
    print("\n## Interesting methods removed")
    for (c, m) in sorted(removed):
        if INTEREST.search(c) or INTEREST.search(m):
            print(f"- {c}::{m}")

    # RVA refresh table for classes present in both
    print("\n## Known-key classes (rva of first method, new dump)")
    for (c, m) in sorted(new_keys & old_keys):
        if c in ("DefaultCertificationValidator", "ButtonEx", "ClickListener", "Button"):
            print(f"= {c}::{m}  new_rva={new_flat[(c,m)]}")

if __name__ == "__main__":
    main()
