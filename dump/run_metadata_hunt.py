import frida, sys, time, struct, os
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from crash_collector.crash_collector import CrashCollector

APP_ID       = "com.run.tower.defense"
SCRIPT       = "metadata_hunt.js"
OUTPUT_FILE  = "metadata_decrypted.dat"
HTPX_FILE    = "metadata_htpx_raw.dat"

dump_file    = None
htpx_file    = None
total_bytes  = 0
htpx_bytes   = 0

def on_message(message, data):
    global dump_file, htpx_file, total_bytes, htpx_bytes

    if message["type"] == "send":
        payload = message["payload"]

        if isinstance(payload, str):
            print(payload)
            return

        if not isinstance(payload, dict):
            return

        t = payload.get("type")

        # ── dump principal (metadata decriptado) ──────────────────────────
        if t == "dump_start":
            print(f"\n[DUMP] Iniciando — addr={payload['addr']}"
                  f"  estimado={payload['total_bytes'] / 1024 / 1024:.1f}MB")
            dump_file = open(OUTPUT_FILE, "wb")
            total_bytes = 0

        elif t == "chunk":
            if dump_file and data:
                dump_file.seek(payload["offset"])
                dump_file.write(data)
                total_bytes += len(data)
                print(f"[DUMP] {total_bytes / 1024 / 1024:.2f}MB recebidos...", end="\r", flush=True)

        elif t == "dump_done":
            if dump_file:
                dump_file.close()
                dump_file = None
                print(f"\n[DUMP] Salvo em '{OUTPUT_FILE}' — {total_bytes / 1024 / 1024:.2f}MB")
                validate_dump(OUTPUT_FILE)

        # ── dump HTPX (raw encriptado, para análise offline) ─────────────
        elif t == "htpx_start":
            print(f"\n[HTPX] Iniciando dump raw — {payload['size'] / 1024 / 1024:.1f}MB")
            htpx_file  = open(HTPX_FILE, "wb")
            htpx_bytes = 0

        elif t == "htpx_chunk":
            if htpx_file and data:
                htpx_file.seek(payload["offset"])
                htpx_file.write(data)
                htpx_bytes += len(data)
                print(f"[HTPX] {htpx_bytes / 1024 / 1024:.2f}MB...", end="\r", flush=True)

        elif t == "htpx_done":
            if htpx_file:
                htpx_file.close()
                htpx_file = None
                print(f"\n[HTPX] Salvo em '{HTPX_FILE}' — {htpx_bytes / 1024 / 1024:.2f}MB")

    elif message["type"] == "error":
        print("[ERR]", message.get("stack", message))


def validate_dump(path):
    with open(path, "rb") as f:
        header = f.read(16)

    ver = struct.unpack_from("<i", header, 4)[0] if len(header) >= 8 else -1
    print(f"\n[VAL] magic={header[:4].hex()}  ver={ver}")
    print(f"[VAL] primeiros 16 bytes: {header.hex()}")

    if header[:4] == b"\xaf\x1b\xb1\xfa":
        print(f"[VAL] Magic IL2CPP valido! ver={ver}")
        if 24 <= ver <= 29:
            print("[VAL] Versao no range esperado — pronto para Il2CppDumper!")
        else:
            print(f"[VAL] Versao fora do range (24-29) — examine manualmente")
    else:
        print("[VAL] Magic nao e IL2CPP — falso positivo ou formato diferente")


def main():
    collector = CrashCollector(
        base_dir="logs",
        package_name=APP_ID,
        include_low_level=True,
        include_bugreport=False,
    )
    collector.snapshot()

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
    print(f"[*] pid={pid} resumed — Ctrl+C para encerrar\n")

    crashed = False
    def on_detach(r):
        nonlocal crashed
        print(f"[!] detached: {r}")
        crashed = True
    session.on("detached", on_detach)

    try:
        while not crashed:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] encerrado pelo usuario")
    finally:
        if dump_file:
            dump_file.close()
        if htpx_file:
            htpx_file.close()
        time.sleep(4)
        collector.collect(pid=pid)


if __name__ == "__main__":
    main()
