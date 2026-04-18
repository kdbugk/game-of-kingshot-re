import frida, sys, time
from pathlib import Path

APP_ID = "com.run.tower.defense"
SCRIPT = "ifix_tracker.js"
LOG    = "ifix_tracker.log"

def on_message(message, data):
    if message["type"] == "send":
        print(message["payload"])
    elif message["type"] == "error":
        print("[ERR]", message.get("stack", message))

def main():
    log = open(LOG, "w", encoding="utf-8")

    orig_print = print
    def tee(*args, **kwargs):
        line = " ".join(str(a) for a in args)
        orig_print(line, **kwargs)
        log.write(line + "\n")
        log.flush()
    import builtins
    builtins.print = tee

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

    detached = False
    session.on("detached", lambda r: setattr(sys.modules[__name__], '_det', True))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] encerrado pelo usuario")
    finally:
        log.close()
        builtins.print = orig_print
        print(f"[*] log salvo em '{LOG}'")

if __name__ == "__main__":
    main()
