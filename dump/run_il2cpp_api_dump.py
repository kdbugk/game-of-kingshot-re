import frida, sys, time, json, os
from pathlib import Path

APP_ID      = "com.run.tower.defense"
SCRIPT      = "il2cpp_api_dump.js"
OUTPUT_DIR  = "il2cpp_dump"
SUMMARY_FILE = "il2cpp_dump_summary.txt"

Path(OUTPUT_DIR).mkdir(exist_ok=True)

assemblies_received = 0
dump_done = False


def on_message(message, data):
    global assemblies_received, dump_done

    if message["type"] == "send":
        payload = message["payload"]

        if isinstance(payload, str):
            print(payload)
            return

        if not isinstance(payload, dict):
            return

        t = payload.get("type")

        if t == "assembly":
            idx   = payload["index"]
            name  = payload["name"]
            count = payload["class_count"]
            print(f"[DUMP] assembly[{idx}] {name}  classes={count}")

            if data:
                out = Path(OUTPUT_DIR) / f"{idx:03d}_{name.replace('/', '_')}.json"
                out.write_bytes(data)
                print(f"       → {out}")

            assemblies_received += 1

        elif t == "dump_complete":
            dump_done = True
            n_asm  = payload.get("assemblies", 0)
            n_cls  = payload.get("classes", 0)
            n_meth = payload.get("methods", 0)
            print(f"\n[DONE] assemblies={n_asm}  classes={n_cls}  methods={n_meth}")

            # Write summary
            lines = [
                f"IL2CPP API Dump — {time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"assemblies : {n_asm}",
                f"classes    : {n_cls}",
                f"methods    : {n_meth}",
                f"output dir : {OUTPUT_DIR}/",
            ]
            Path(SUMMARY_FILE).write_text("\n".join(lines) + "\n")
            print(f"[DONE] resumo salvo em '{SUMMARY_FILE}'")

    elif message["type"] == "error":
        print("[ERR]", message.get("stack", message))


def main():
    device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
    print(f"[+] Device: {device}")

    src = open(SCRIPT, encoding="utf-8").read()

    pid = device.spawn([APP_ID])
    print(f"[+] spawned pid={pid}")

    session = device.attach(pid)

    script = session.create_script(src)
    script.on("message", on_message)
    script.load()

    device.resume(pid)
    print(f"[*] pid={pid} resumed — aguardando dump (Ctrl+C para encerrar)\n")

    detached = False
    def on_detach(r):
        nonlocal detached
        print(f"[!] detached: {r}")
        detached = True
    session.on("detached", on_detach)

    try:
        while not detached and not dump_done:
            time.sleep(1)
        # Give a couple of seconds for remaining chunk sends
        if dump_done:
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n[*] encerrado pelo usuario")


if __name__ == "__main__":
    main()
