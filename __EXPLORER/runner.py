import frida, sys, time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from crash_collector.crash_collector import CrashCollector

APP_ID  = "com.run.tower.defense"
SCRIPT  = "explorer.js"

def on_message(message, data):
    if message["type"] == "send":
        print(message["payload"])
    elif message["type"] == "error":
        print("[ERR]", message.get("stack", message))

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

    # ----- SPAWN em vez de attach -----
    # O app é iniciado suspenso; o script carrega ANTES de qualquer código nativo rodar.
    pid = device.spawn([APP_ID])
    print(f"[+] spawned pid={pid}")

    session = device.attach(pid)

    script = session.create_script(src)
    script.on("message", on_message)
    script.load()

    # Resume após o script estar carregado
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
        time.sleep(4)
        collector.collect(pid=pid)

if __name__ == "__main__":
    main()