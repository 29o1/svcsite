from __future__ import annotations

from dataclasses import dataclass
import shutil
import subprocess
from typing import Sequence

from z9mon.errors import EXIT_DEVICE, EXIT_ENVIRONMENT, Z9MonError


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


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


class AdbClient:
    def __init__(
        self,
        serial: str | None = None,
        timeout: float = 15.0,
        executable: str | None = None,
    ) -> None:
        adb_path = shutil.which(executable or "adb")
        if adb_path is None:
            raise Z9MonError(
                "ADB_NOT_FOUND",
                "adb was not found in PATH",
                EXIT_ENVIRONMENT,
            )
        self.executable = adb_path
        self.serial = serial
        self.timeout = timeout

    def _run(
        self,
        arguments: Sequence[str],
        *,
        input_text: str | None = None,
        use_serial: bool = True,
    ) -> CommandResult:
        command = [self.executable]
        if use_serial and self.serial:
            command.extend(("-s", self.serial))
        command.extend(arguments)

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
            raise Z9MonError(
                "ADB_TIMEOUT",
                "adb command timed out",
                EXIT_ENVIRONMENT,
                {"timeout_seconds": self.timeout},
            ) from exc
        except OSError as exc:
            raise Z9MonError(
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
            raise Z9MonError(
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
                raise Z9MonError(
                    "DEVICE_NOT_FOUND",
                    "requested Android device was not found",
                    EXIT_DEVICE,
                    {"device": selected},
                )
            if state != "device":
                raise Z9MonError(
                    "DEVICE_UNAVAILABLE",
                    "requested Android device is not ready",
                    EXIT_DEVICE,
                    {"device": selected, "state": state},
                )
            self.serial = selected
            return selected

        ready = sorted(serial for serial, state in devices.items() if state == "device")
        if not ready:
            raise Z9MonError(
                "DEVICE_NOT_FOUND",
                "no ready Android device was found",
                EXIT_DEVICE,
                {"devices": devices},
            )
        if len(ready) > 1:
            raise Z9MonError(
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
        import shlex

        return self.shell(f"exec su -c {shlex.quote(command)}\n")

    def getprop(self, name: str) -> str:
        import shlex

        result = self.shell(f"getprop {shlex.quote(name)}\n")
        if result.returncode != 0:
            raise Z9MonError(
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
