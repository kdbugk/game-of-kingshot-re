import subprocess
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, Set


class CrashCollector:
    def __init__(
        self,
        base_dir: str = "logs",
        package_name: Optional[str] = None,
        include_low_level: bool = True,
        include_bugreport: bool = False,
    ):
        self.base_dir = Path(base_dir)
        self.package_name = package_name
        self.include_low_level = include_low_level
        self.include_bugreport = include_bugreport

        self.logcat_since: Optional[str] = None
        self.tombstones_before: Set[str] = set()
        self.anr_before: Set[str] = set()

    @staticmethod
    def _run(cmd: list[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _adb_logcat_timestamp() -> str:
        now = datetime.now()
        return now.strftime("%m-%d %H:%M:%S.%f")[:-3]

    @staticmethod
    def _write_text_if_any(path: Path, content: str) -> None:
        if content:
            path.write_text(content, encoding="utf-8")

    def _list_remote_files(self, remote_dir: str) -> Set[str]:
        r = self._run(["adb", "shell", "su", "-c", f"ls -1 '{remote_dir}' 2>/dev/null"])
        if r.returncode != 0:
            return set()
        return {line.strip() for line in r.stdout.splitlines() if line.strip()}

    def _read_remote_file(self, remote_path: str) -> str:
        r = self._run(["adb", "shell", "su", "-c", f"cat '{remote_path}'"])
        return r.stdout if r.returncode == 0 else ""

    def snapshot(self) -> None:
        self.logcat_since = self._adb_logcat_timestamp()
        self.tombstones_before = self._list_remote_files("/data/tombstones")
        self.anr_before = self._list_remote_files("/data/anr")

        print(f"[*] CrashCollector snapshot criado")
        print(f"[*] logcat desde: {self.logcat_since}")
        print(f"[*] tombstones antes: {len(self.tombstones_before)}")
        print(f"[*] ANRs antes: {len(self.anr_before)}")

    def collect(self, pid: Optional[int] = None) -> Path:
        ts = self._now_ts()
        out_dir = self.base_dir / f"crash_{ts}"
        out_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n[*] coletando logs em {out_dir}...")

        self._collect_logcat(out_dir)
        self._collect_tombstones(out_dir)
        self._collect_anr(out_dir)

        if self.include_low_level:
            self._collect_dmesg(out_dir)
            self._collect_pstore(out_dir)
            self._collect_dropbox(out_dir)

        if pid is not None:
            self._collect_proc_state(pid, out_dir)

        if self.include_bugreport:
            self._collect_bugreport(out_dir)

        print(f"[*] salvo em {out_dir}\n")
        return out_dir

    def _collect_logcat(self, out_dir: Path) -> None:
        try:
            cmd = ["adb", "logcat", "-d", "-b", "all"]
            if self.logcat_since:
                cmd.extend(["-T", self.logcat_since])

            r = self._run(cmd)
            self._write_text_if_any(out_dir / "logcat_full.txt", r.stdout)

            keywords = [
                "signal", "sigabrt", "sigbus", "sigsegv", "abort",
                "fatal", "crash", "tombstone", "backtrace", "debuggerd",
                "libc", "frida", "ptrace", "denied", "avc:",
                "anr", "lowmemorykiller", "oom", "watchdog"
            ]
            if self.package_name:
                keywords.append(self.package_name)

            relevant = [
                line for line in r.stdout.splitlines()
                if any(k.lower() in line.lower() for k in keywords)
            ]

            self._write_text_if_any(out_dir / "logcat_relevant.txt", "\n".join(relevant))

            print(f"[+] logcat ({len(relevant)} linhas relevantes)")
            if self.logcat_since:
                print(f"[+] filtro logcat desde: {self.logcat_since}")

        except Exception as e:
            print(f"[!] logcat: {e}")

    def _collect_tombstones(self, out_dir: Path) -> None:
        try:
            after = self._list_remote_files("/data/tombstones")
            new_files = sorted(after - self.tombstones_before)

            self._write_text_if_any(
                out_dir / "tombstones_list_before.txt",
                "\n".join(sorted(self.tombstones_before))
            )
            self._write_text_if_any(
                out_dir / "tombstones_list_after.txt",
                "\n".join(sorted(after))
            )
            self._write_text_if_any(
                out_dir / "tombstones_new.txt",
                "\n".join(new_files)
            )

            if not new_files:
                print("[*] nenhum tombstone novo")
                return

            for fname in new_files:
                content = self._read_remote_file(f"/data/tombstones/{fname}")
                if content:
                    self._write_text_if_any(out_dir / fname, content)
                    print(f"[+] tombstone novo: {fname}")

        except Exception as e:
            print(f"[!] tombstones: {e}")

    def _collect_anr(self, out_dir: Path) -> None:
        try:
            after = self._list_remote_files("/data/anr")
            new_files = sorted(after - self.anr_before)

            self._write_text_if_any(out_dir / "anr_list_before.txt", "\n".join(sorted(self.anr_before)))
            self._write_text_if_any(out_dir / "anr_list_after.txt", "\n".join(sorted(after)))
            self._write_text_if_any(out_dir / "anr_new.txt", "\n".join(new_files))

            if not new_files:
                print("[*] nenhum ANR novo")
                return

            for fname in new_files:
                content = self._read_remote_file(f"/data/anr/{fname}")
                if content:
                    self._write_text_if_any(out_dir / fname, content)
                    print(f"[+] ANR novo: {fname}")

        except Exception as e:
            print(f"[!] ANR: {e}")

    def _collect_dmesg(self, out_dir: Path) -> None:
        try:
            r = self._run(["adb", "shell", "su", "-c", "dmesg"])
            self._write_text_if_any(out_dir / "dmesg.txt", r.stdout)

            keywords = [
                "segfault", "fault", "avc:", "denied", "ptrace", "audit",
                "oom", "lowmemorykiller", "watchdog", "binder", "abort",
                "panic", "memfd", "frida"
            ]
            if self.package_name:
                keywords.append(self.package_name)

            relevant = [
                line for line in r.stdout.splitlines()
                if any(k.lower() in line.lower() for k in keywords)
            ]
            self._write_text_if_any(out_dir / "dmesg_relevant.txt", "\n".join(relevant))

            print(f"[+] dmesg ({len(relevant)} linhas relevantes)")

        except Exception as e:
            print(f"[!] dmesg: {e}")

    def _collect_pstore(self, out_dir: Path) -> None:
        try:
            listing = self._run([
                "adb", "shell", "su", "-c",
                "ls -la /sys/fs/pstore 2>/dev/null"
            ])
            self._write_text_if_any(out_dir / "pstore_list.txt", listing.stdout)

            dump = self._run([
                "adb", "shell", "su", "-c",
                "for f in /sys/fs/pstore/*; do "
                "[ -f \"$f\" ] && echo \"===== $f =====\" && cat \"$f\"; "
                "done 2>/dev/null"
            ])
            self._write_text_if_any(out_dir / "pstore_dump.txt", dump.stdout)

            if dump.stdout:
                print("[+] pstore coletado")
            else:
                print("[*] pstore vazio ou indisponível")

        except Exception as e:
            print(f"[!] pstore: {e}")

    def _collect_dropbox(self, out_dir: Path) -> None:
        try:
            r = self._run([
                "adb", "shell", "su", "-c",
                "dumpsys dropbox 2>/dev/null"
            ])
            self._write_text_if_any(out_dir / "dropbox.txt", r.stdout)

            if r.stdout:
                print("[+] dropbox coletado")
            else:
                print("[*] dropbox vazio ou indisponível")

        except Exception as e:
            print(f"[!] dropbox: {e}")

    def _collect_proc_state(self, pid: int, out_dir: Path) -> None:
        try:
            proc_dir = out_dir / f"proc_{pid}"
            proc_dir.mkdir(parents=True, exist_ok=True)

            files = {
                "status.txt": f"/proc/{pid}/status",
                "maps.txt": f"/proc/{pid}/maps",
                "smaps.txt": f"/proc/{pid}/smaps",
                "limits.txt": f"/proc/{pid}/limits",
                "cmdline.txt": f"/proc/{pid}/cmdline",
            }

            for local_name, remote_path in files.items():
                content = self._read_remote_file(remote_path)
                self._write_text_if_any(proc_dir / local_name, content)

            print(f"[+] /proc/{pid} coletado")

        except Exception as e:
            print(f"[!] /proc/{pid}: {e}")

    def _collect_bugreport(self, out_dir: Path) -> None:
        try:
            print("[*] coletando bugreport... isso pode demorar")
            bug_dir = out_dir / "bugreport"
            bug_dir.mkdir(parents=True, exist_ok=True)

            # O adb bugreport gera um .zip e às vezes um .txt ao lado, dependendo da versão.
            r = self._run(["adb", "bugreport", str(bug_dir)], timeout=600)

            self._write_text_if_any(bug_dir / "bugreport_stdout.txt", r.stdout)
            self._write_text_if_any(bug_dir / "bugreport_stderr.txt", r.stderr)

            print("[+] bugreport finalizado")

        except subprocess.TimeoutExpired:
            print("[!] bugreport: timeout")
        except Exception as e:
            print(f"[!] bugreport: {e}")


def get_pid(package_name: str) -> Optional[int]:
    r = subprocess.run(
        ["adb", "shell", "su", "-c", f"pidof {package_name}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if r.returncode != 0:
        return None

    out = r.stdout.strip()
    if not out:
        return None

    try:
        return int(out.split()[0])
    except ValueError:
        return None