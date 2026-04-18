import frida, sys, time

APP_ID = "com.run.tower.defense"
SCRIPT = "jni_tracer.js"
LOG    = "jni_tracer.log"

log = open(LOG, "w", encoding="utf-8")

def tee(msg):
    print(msg)
    log.write(msg + "\n")
    log.flush()

def on_message(message, data):
    if message["type"] == "send":
        tee(str(message["payload"]))
    elif message["type"] == "error":
        tee("[ERR] " + str(message.get("stack", message)))

def main():
    device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
    tee(f"[+] Device: {device}")

    src = open(SCRIPT, encoding="utf-8").read()
    pid = device.spawn([APP_ID])
    tee(f"[+] spawned pid={pid}")

    session = device.attach(pid)
    script  = session.create_script(src)
    script.on("message", on_message)
    script.load()

    device.resume(pid)
    tee(f"[*] pid={pid} resumed — Ctrl+C para encerrar\n")

    session.on("detached", lambda r: tee(f"[!] detached: {r}"))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        tee("\n[*] encerrado pelo usuario")
    finally:
        log.close()

if __name__ == "__main__":
    main()
