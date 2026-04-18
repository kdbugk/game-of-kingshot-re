import frida, sys, time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from crash_collector.crash_collector import CrashCollector

APP_ID = "com.run.tower.defense"
SCRIPT = "gateway_diag.js"
LOG    = "gateway_diag.log"

log     = open(LOG, "w", encoding="utf-8")
t_start = time.time()

def elapsed():
    return f"{time.time() - t_start:.1f}s"

def tee(msg):
    line = f"[{elapsed()}] {msg}"
    print(line)
    log.write(line + "\n")
    log.flush()

def on_message(message, data):
    t = message.get("type")
    if t == "send":
        tee(str(message["payload"]))
    elif t == "log":
        tee(str(message.get("payload", "")))
    elif t == "error":
        tee("[ERR] " + str(message.get("stack", message)))

def main():
    device = frida.get_device_manager().add_remote_device("127.0.0.1:37555")
    tee(f"Device: {device}")

    src = open(SCRIPT, encoding="utf-8").read()
    pid = device.spawn([APP_ID])
    tee(f"spawned pid={pid}")

    session = device.attach(pid)
    script  = session.create_script(src)
    script.on("message", on_message)
    script.load()

    device.resume(pid)
    tee(f"pid={pid} resumed")
    tee("Entre em uma batalha. Sumário aparece a cada 15s.\n")

    session.on("detached", lambda r: tee(f"detached: {r}"))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        tee("encerrado")
    finally:
        tee(f"uptime: {elapsed()}")
        log.close()

if __name__ == "__main__":
    main()
