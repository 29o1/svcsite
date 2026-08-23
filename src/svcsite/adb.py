from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
import shutil
import subprocess
from typing import Sequence

from svcsite.errors import EXIT_DEVICE, EXIT_ENVIRONMENT, SvcSiteError


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    uid: int
    name: str


def parse_package_uid(output: str, package: str) -> int | None:
    """Return the primary (user 0) UID from ``cmd package list packages -U``.

    Cloned or work-profile installs append extra UIDs as a comma list; the
    first entry is the user 0 UID this CLI monitors.
    """
    pattern = re.compile(
        rf"^package:{re.escape(package)}(?:\s+.*)?\s+uid:(\d+(?:,\d+)*)"
    )
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            return int(match.group(1).split(",")[0])
    return None


def parse_adb_devices(output: str) -> dict[str, str]:
    devices: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        fields = line.split()
        if len(fields) >= 2:
            devices[fields[0]] = fields[1]
    return devices


def parse_processes(output: str) -> list[ProcessInfo]:
    processes: list[ProcessInfo] = []
    for raw_line in output.splitlines():
        fields = raw_line.strip().split(maxsplit=2)
        if len(fields) < 3 or not fields[0].isdecimal() or not fields[1].isdecimal():
            continue
        pid, uid = int(fields[0]), int(fields[1])
        if pid > 0:
            processes.append(ProcessInfo(pid=pid, uid=uid, name=fields[2]))
    return sorted(processes, key=lambda process: process.pid)


def parse_uid_processes(output: str, target_uid: int) -> list[ProcessInfo]:
    return [
        process
        for process in parse_processes(output)
        if process.uid == target_uid
    ]


class AdbClient:
    def __init__(
        self,
        serial: str | None = None,
        timeout: float = 15.0,
        executable: str | None = None,
    ) -> None:
        adb_path = shutil.which(executable or "adb")
        if adb_path is None:
            raise SvcSiteError(
                "ADB_NOT_FOUND",
                "adb was not found in PATH",
                EXIT_ENVIRONMENT,
            )
        self.executable = adb_path
        self.serial = serial
        self.timeout = timeout

    def _command(self, arguments: Sequence[str], *, use_serial: bool = True) -> list[str]:
        command = [self.executable]
        if use_serial and self.serial:
            command.extend(("-s", self.serial))
        command.extend(arguments)
        return command

    def _run(
        self,
        arguments: Sequence[str],
        *,
        input_text: str | None = None,
        use_serial: bool = True,
    ) -> CommandResult:
        command = self._command(arguments, use_serial=use_serial)

        try:
            completed = subprocess.run(
                command,
                input=input_text,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SvcSiteError(
                "ADB_TIMEOUT",
                "adb command timed out",
                EXIT_ENVIRONMENT,
                {"timeout_seconds": self.timeout},
            ) from exc
        except OSError as exc:
            raise SvcSiteError(
                "ADB_EXEC_FAILED",
                "adb could not be executed",
                EXIT_ENVIRONMENT,
                {"reason": str(exc)},
            ) from exc

        return CommandResult(
            completed.returncode,
            completed.stdout,
            completed.stderr,
        )

    def resolve_serial(self, requested: str | None = None) -> str:
        result = self._run(("devices",), use_serial=False)
        if result.returncode != 0:
            raise SvcSiteError(
                "ADB_DEVICES_FAILED",
                "adb devices failed",
                EXIT_ENVIRONMENT,
                {"returncode": result.returncode, "stderr": result.stderr.strip()},
            )

        devices = parse_adb_devices(result.stdout)
        selected = requested or self.serial
        if selected:
            state = devices.get(selected)
            if state is None:
                raise SvcSiteError(
                    "DEVICE_NOT_FOUND",
                    "requested Android device was not found",
                    EXIT_DEVICE,
                    {"device": selected},
                )
            if state != "device":
                raise SvcSiteError(
                    "DEVICE_UNAVAILABLE",
                    "requested Android device is not ready",
                    EXIT_DEVICE,
                    {"device": selected, "state": state},
                )
            self.serial = selected
            return selected

        ready = sorted(serial for serial, state in devices.items() if state == "device")
        if not ready:
            raise SvcSiteError(
                "DEVICE_NOT_FOUND",
                "no ready Android device was found",
                EXIT_DEVICE,
                {"devices": devices},
            )
        if len(ready) > 1:
            raise SvcSiteError(
                "MULTIPLE_DEVICES",
                "multiple Android devices are ready; select one with --device",
                EXIT_DEVICE,
                {"devices": ready},
            )

        self.serial = ready[0]
        return ready[0]

    def shell(self, script: str) -> CommandResult:
        return self._run(("shell",), input_text=script)

    def root_shell(self, command: str) -> CommandResult:
        return self.shell(f"exec su -c {shlex.quote(command)}\n")

    def push(self, local_path: str | Path, remote_path: str) -> None:
        result = self._run(("push", str(local_path), remote_path))
        if result.returncode != 0:
            raise SvcSiteError(
                "ADB_PUSH_FAILED",
                "failed to push a file to the Android device",
                EXIT_ENVIRONMENT,
                {
                    "local_path": str(local_path),
                    "remote_path": remote_path,
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip(),
                },
            )

    def pull(self, remote_path: str, local_path: str | Path) -> None:
        result = self._run(("pull", remote_path, str(local_path)))
        if result.returncode != 0:
            raise SvcSiteError(
                "ADB_PULL_FAILED",
                "failed to pull a file from the Android device",
                EXIT_ENVIRONMENT,
                {
                    "remote_path": remote_path,
                    "local_path": str(local_path),
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip(),
                },
            )

    def truncate_root_file(self, path: str) -> None:
        result = self.root_shell(f": > {shlex.quote(path)}")
        if result.returncode != 0:
            raise SvcSiteError(
                "ADB_TRUNCATE_FILE_FAILED",
                "failed to truncate a device file",
                EXIT_ENVIRONMENT,
                {
                    "path": path,
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip(),
                },
            )

    def make_root_file_readable(self, path: str) -> None:
        result = self.root_shell(f"chmod 0644 {shlex.quote(path)}")
        if result.returncode != 0:
            raise SvcSiteError(
                "ADB_CHMOD_FILE_FAILED",
                "failed to make a device artifact readable",
                EXIT_ENVIRONMENT,
                {
                    "path": path,
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip(),
                },
            )

    def getprop(self, name: str) -> str:
        result = self.shell(f"getprop {shlex.quote(name)}\n")
        if result.returncode != 0:
            raise SvcSiteError(
                "ADB_GETPROP_FAILED",
                "failed to read Android system property",
                EXIT_ENVIRONMENT,
                {
                    "property": name,
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip(),
                },
            )
        return result.stdout.strip()

    def package_uid(self, package: str) -> int:
        result = self.shell(f"cmd package list packages -U {shlex.quote(package)}\n")
        if result.returncode != 0:
            raise SvcSiteError(
                "PACKAGE_LOOKUP_FAILED",
                "failed to resolve the Android package UID",
                EXIT_DEVICE,
                {"package": package, "stderr": result.stderr.strip()},
            )

        pattern_match = parse_package_uid(result.stdout, package)
        if pattern_match is not None:
            return pattern_match
        raise SvcSiteError(
            "PACKAGE_NOT_FOUND",
            "Android package was not found",
            EXIT_DEVICE,
            {"package": package},
        )

    def package_pids(self, package: str) -> list[int]:
        result = self.shell(f"pidof {shlex.quote(package)}\n")
        if result.returncode not in (0, 1):
            raise SvcSiteError(
                "PID_LOOKUP_FAILED",
                "failed to resolve target process IDs",
                EXIT_DEVICE,
                {"package": package, "stderr": result.stderr.strip()},
            )
        return sorted(
            {
                int(value)
                for value in result.stdout.split()
                if value.isdecimal() and int(value) > 0
            }
        )

    def processes_for_uid(self, uid: int) -> list[ProcessInfo]:
        result = self.shell("ps -A -o PID,UID,NAME\n")
        if result.returncode != 0:
            raise SvcSiteError(
                "PROCESS_LIST_FAILED",
                "failed to list Android processes",
                EXIT_DEVICE,
                {"uid": uid, "stderr": result.stderr.strip()},
            )
        return parse_uid_processes(result.stdout, uid)

    def process(self, pid: int) -> ProcessInfo:
        result = self.shell("ps -A -o PID,UID,NAME\n")
        if result.returncode != 0:
            raise SvcSiteError(
                "PROCESS_LIST_FAILED",
                "failed to list Android processes",
                EXIT_DEVICE,
                {"pid": pid, "stderr": result.stderr.strip()},
            )
        for process in parse_processes(result.stdout):
            if process.pid == pid:
                return process
        raise SvcSiteError(
            "PROCESS_NOT_FOUND",
            "target process was not found",
            EXIT_DEVICE,
            {"pid": pid},
        )

    def read_process_maps(self, pid: int) -> str:
        result = self.root_shell(f"cat /proc/{pid}/maps")
        if result.returncode != 0:
            raise SvcSiteError(
                "MAPS_READ_FAILED",
                "failed to read process maps",
                EXIT_DEVICE,
                {"pid": pid, "stderr": result.stderr.strip()},
            )
        return result.stdout

    def force_stop(self, package: str) -> None:
        result = self.shell(f"am force-stop {shlex.quote(package)}\n")
        if result.returncode != 0:
            raise SvcSiteError(
                "APP_STOP_FAILED",
                "failed to stop the target package",
                EXIT_DEVICE,
                {"package": package, "stderr": result.stderr.strip()},
            )

    def launch_package(self, package: str) -> dict[str, str]:
        package_arg = shlex.quote(package)
        resolved = self.shell(
            f"cmd package resolve-activity --brief --user 0 {package_arg}\n"
        )
        component = ""
        if resolved.returncode == 0:
            candidates = [
                line.strip()
                for line in resolved.stdout.splitlines()
                if "/" in line and not line.startswith("priority=")
            ]
            if candidates:
                component = candidates[-1]

        if component:
            result = self.shell(f"am start -n {shlex.quote(component)}\n")
            method = "am-start"
        else:
            result = self.shell(
                f"monkey -p {package_arg} -c android.intent.category.LAUNCHER 1\n"
            )
            method = "monkey"
        if result.returncode != 0:
            raise SvcSiteError(
                "APP_LAUNCH_FAILED",
                "failed to launch the target package",
                EXIT_DEVICE,
                {
                    "package": package,
                    "component": component or None,
                    "stderr": result.stderr.strip(),
                },
            )
        return {"method": method, "component": component}
