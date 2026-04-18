import frida, sys, time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from crash_collector.crash_collector import CrashCollector

APP_ID = "com.run.tower.defense"
SCRIPT = "certval_hook.js"
LOG    = "certval_hook.log"

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
    collector = CrashCollector(
        base_dir="logs",
        package_name=APP_ID,
        include_low_level=True,
        include_bugreport=False,
    )
    collector.snapshot()

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
    tee(f"pid={pid} resumed\n")

    session.on("detached", lambda r: tee(f"detached: {r}"))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        tee("encerrado pelo usuario")
    finally:
        tee(f"total uptime: {elapsed()}")
        log.close()
        try:
            collector.collect(pid=pid)
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
