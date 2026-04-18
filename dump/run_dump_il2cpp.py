import frida, sys, time, os
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from crash_collector.crash_collector import CrashCollector

APP_ID      = "com.run.tower.defense"
SCRIPT      = "dump_il2cpp.js"
OUTPUT_FILE = "libil2cpp_decrypted.so"

dump_file   = None
total_bytes = 0
dump_size   = 0

def on_message(message, data):
    global dump_file, total_bytes, dump_size

    if message["type"] == "send":
        payload = message["payload"]

        if isinstance(payload, str):
            print(payload)
            return

        if not isinstance(payload, dict):
            return

        t = payload.get("type")

        if t == "dump_start":
            dump_size = payload["size"]
            size_mb   = dump_size / 1024 / 1024
            print(f"\n[DUMP] Iniciando — base={payload['base']}  size={size_mb:.1f}MB")

            # Pré-aloca o arquivo com o tamanho correto (evita fragmentação)
            dump_file = open(OUTPUT_FILE, "wb")
            dump_file.seek(dump_size - 1)
            dump_file.write(b'\x00')
            dump_file.flush()
            total_bytes = 0

        elif t == "chunk":
            if dump_file and data:
                dump_file.seek(payload["offset"])
                dump_file.write(data)
                total_bytes += len(data)
                pct = (total_bytes / dump_size * 100) if dump_size else 0
                print(f"[DUMP] {total_bytes / 1024 / 1024:.1f}MB / "
                      f"{dump_size / 1024 / 1024:.1f}MB  ({pct:.1f}%)",
                      end="\r", flush=True)

        elif t == "dump_done":
            if dump_file:
                dump_file.close()
                dump_file = None
                actual = os.path.getsize(OUTPUT_FILE)
                print(f"\n[DUMP] Salvo em '{OUTPUT_FILE}'  ({actual / 1024 / 1024:.2f}MB)")
                print(f"[DUMP] Páginas inacessíveis zeradas: {payload.get('error_pages', '?')}")
                validate_dump(OUTPUT_FILE)

    elif message["type"] == "error":
        print("[ERR]", message.get("stack", message))


def validate_dump(path):
    with open(path, "rb") as f:
        header = f.read(16)

    magic = header[:4]
    if magic == b'\x7fELF':
        ei_class = header[4]   # 1=32bit, 2=64bit
        ei_data  = header[5]   # 1=LE, 2=BE
        e_type   = int.from_bytes(header[16:18] if len(header) >= 18 else b'\x00\x00', 'little')
        print(f"\n[VAL] Magic ELF válido!")
        print(f"[VAL] Classe: {'64-bit' if ei_class == 2 else '32-bit'}"
              f"  Endian: {'LE' if ei_data == 1 else 'BE'}")
        print(f"[VAL] Pronto para carregar no Ghidra como ELF ARM64!")
    else:
        print(f"\n[VAL] Magic inesperado: {magic.hex()}")
        print(f"[VAL] Primeiros 16 bytes: {header.hex()}")


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
    script  = session.create_script(src)
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
        print("\n[*] encerrado pelo usuário")
    finally:
        if dump_file:
            dump_file.close()
        time.sleep(4)
        collector.collect(pid=pid)


if __name__ == "__main__":
    main()
