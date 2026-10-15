from __future__ import annotations

import json
from pathlib import Path
import shlex
from typing import Any

from svcsite.adb import AdbClient
from svcsite.constants import (
    DEPLOYED_MARKER_PATH,
    KPATCH_CANDIDATES,
    LEGACY_MODULE_NAME,
    MODULE_NAME,
)
from svcsite.errors import EXIT_KPATCH, EXIT_KPM, EXIT_ROOT, SvcSiteError
from svcsite.session import sha256_file


_HEXDIGITS = frozenset("0123456789abcdef")


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, "***") if secret else text


def parse_json_payload(raw: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    last_payload: dict[str, Any] | None = None
    cursor = 0
    while cursor < len(raw):
        index = raw.find("{", cursor)
        if index < 0:
            break
        try:
            payload, consumed = decoder.raw_decode(raw[index:])
        except json.JSONDecodeError:
            cursor = index + 1
            continue
        if isinstance(payload, dict):
            last_payload = payload
        cursor = index + max(consumed, 1)

    if last_payload is None:
        raise SvcSiteError(
            "KPM_INVALID_RESPONSE",
            "KPM did not return a JSON object",
            EXIT_KPM,
        )
    return last_payload


def require_root(adb: AdbClient) -> None:
    result = adb.root_shell("id -u")
    if result.returncode != 0 or result.stdout.strip() != "0":
        raise SvcSiteError(
            "ROOT_DENIED",
            "root shell is unavailable",
            EXIT_ROOT,
            {
                "returncode": result.returncode,
                "stderr": result.stderr.strip(),
            },
        )


def find_kpatch(adb: AdbClient) -> str:
    probes = " ".join(shlex.quote(path) for path in KPATCH_CANDIDATES)
    command = (
        f"for candidate in {probes}; do "
        'if [ -x "$candidate" ]; then printf "%s\\n" "$candidate"; exit 0; fi; '
        "done; exit 127"
    )
    result = adb.root_shell(command)
    if result.returncode != 0:
        raise SvcSiteError(
            "KPATCH_NOT_FOUND",
            "kpatch executable was not found on the device",
            EXIT_KPATCH,
            {"candidates": list(KPATCH_CANDIDATES)},
        )

    path = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if path not in KPATCH_CANDIDATES:
        raise SvcSiteError(
            "KPATCH_INVALID_PATH",
            "device returned an unexpected kpatch path",
            EXIT_KPATCH,
            {"path": path},
        )
    return path


class KpmController:
    def __init__(self, adb: AdbClient, superkey: str) -> None:
        self.adb = adb
        self.superkey = superkey
        self.kpatch_path: str | None = None

    def locate_kpatch(self) -> str:
        path = find_kpatch(self.adb)
        self.kpatch_path = path
        return path

    def _run_kpatch(self, *arguments: str) -> tuple[int, str, str]:
        kpatch_path = self.kpatch_path or self.locate_kpatch()
        remote_command = shlex.join((kpatch_path, self.superkey, *arguments))
        result = self.adb.root_shell(remote_command)
        return (
            result.returncode,
            _redact(result.stdout, self.superkey).strip(),
            _redact(result.stderr, self.superkey).strip(),
        )

    def module_names(self) -> list[str]:
        returncode, stdout, stderr = self._run_kpatch("kpm", "list")
        if returncode != 0:
            raise SvcSiteError(
                "KPM_LIST_FAILED",
                "failed to list loaded KPM modules",
                EXIT_KPM,
                {"returncode": returncode, "stderr": stderr},
            )
        return [name for name in stdout.split() if name]

    def is_loaded(self) -> bool:
        return MODULE_NAME in self.module_names()

    def require_loaded(self) -> None:
        if not self.is_loaded():
            raise SvcSiteError(
                "MODULE_NOT_LOADED",
                f"{MODULE_NAME} is not loaded",
                EXIT_KPM,
                {
                    "module": MODULE_NAME,
                    "hint": (
                        "deploy once with capture --kpm PATH; matching builds are skipped"
                    ),
                },
            )

    def module_info(self) -> str:
        self.require_loaded()
        returncode, stdout, stderr = self._run_kpatch("kpm", "info", MODULE_NAME)
        if returncode != 0:
            raise SvcSiteError(
                "KPM_INFO_FAILED",
                "failed to read KPM module information",
                EXIT_KPM,
                {"returncode": returncode, "stderr": stderr},
            )
        return stdout

    def replace_module(self, local_path: str | Path) -> dict[str, Any]:
        """Replace the module with a generous timeout for hook installation."""
        original_timeout = self.adb.timeout
        self.adb.timeout = max(original_timeout, 60.0)
        try:
            return self._replace_module(local_path)
        finally:
            self.adb.timeout = original_timeout

    def ensure_module(self, local_path: str | Path) -> dict[str, Any]:
        """Converge the loaded module to the file at local_path.

        A matching deployed fingerprint skips the reload entirely.
        """
        path = Path(local_path).expanduser().resolve()
        if not path.is_file():
            raise SvcSiteError(
                "KPM_FILE_NOT_FOUND",
                "KPM file was not found",
                EXIT_KPM,
                {"path": str(path)},
            )
        digest = sha256_file(path)
        module_names = self.module_names()
        loaded = MODULE_NAME in module_names
        if loaded and self._read_deployed_marker() == digest:
            return {
                "action": "current",
                "local_path": str(path),
                "sha256": digest,
            }
        outcome = self.replace_module(path)
        outcome["action"] = "replaced" if loaded else "loaded"
        return outcome

    def _read_deployed_marker(self) -> str | None:
        result = self.adb.root_shell(f"cat {shlex.quote(DEPLOYED_MARKER_PATH)}")
        if result.returncode != 0:
            return None
        value = result.stdout.strip().lower()
        if len(value) != 64 or not set(value) <= _HEXDIGITS:
            return None
        return value

    def _write_deployed_marker(self, digest: str) -> bool:
        command = (
            f"printf %s {shlex.quote(digest)} "
            f"> {shlex.quote(DEPLOYED_MARKER_PATH)}"
        )
        result = self.adb.root_shell(command)
        return result.returncode == 0

    def _replace_module(self, local_path: str | Path) -> dict[str, Any]:
        path = Path(local_path).expanduser().resolve()
        if not path.is_file():
            raise SvcSiteError(
                "KPM_FILE_NOT_FOUND",
                "KPM file was not found",
                EXIT_KPM,
                {"path": str(path)},
            )

        digest = sha256_file(path)
        remote_path = f"/data/local/tmp/{MODULE_NAME}-{digest[:12]}.kpm"
        self.adb.push(path, remote_path)

        loaded_modules = self.module_names()
        for module_name in (MODULE_NAME, LEGACY_MODULE_NAME):
            if module_name not in loaded_modules:
                continue
            returncode, stdout, stderr = self._run_kpatch(
                "kpm",
                "unload",
                module_name,
            )
            if returncode != 0:
                raise SvcSiteError(
                    "KPM_UNLOAD_FAILED",
                    "failed to unload the existing KPM module",
                    EXIT_KPM,
                    {
                        "returncode": returncode,
                        "stdout": stdout,
                        "stderr": stderr,
                        "module": module_name,
                    },
                )

        returncode, stdout, stderr = self._run_kpatch(
            "kpm",
            "load",
            remote_path,
        )
        if returncode != 0:
            raise SvcSiteError(
                "KPM_LOAD_FAILED",
                "failed to load the KPM module",
                EXIT_KPM,
                {
                    "returncode": returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                    "remote_path": remote_path,
                },
            )
        return {
            "local_path": str(path),
            "remote_path": remote_path,
            "sha256": digest,
            "info": self.module_info(),
            "marker_written": self._write_deployed_marker(digest),
        }

    def ctl0(self, command: str) -> dict[str, Any]:
        if "\0" in command or "\n" in command or "\r" in command:
            raise SvcSiteError(
                "KPM_COMMAND_INVALID",
                "KPM command contains an unsupported control character",
                EXIT_KPM,
            )

        returncode, stdout, stderr = self._run_kpatch(
            "kpm",
            "ctl0",
            MODULE_NAME,
            command,
        )
        if returncode != 0:
            if not self.is_loaded():
                raise SvcSiteError(
                    "MODULE_NOT_LOADED",
                    f"{MODULE_NAME} is not loaded",
                    EXIT_KPM,
                    {"module": MODULE_NAME},
                )
            raise SvcSiteError(
                "KPM_COMMAND_FAILED",
                "KPM ctl0 command failed",
                EXIT_KPM,
                {
                    "returncode": returncode,
                    "stderr": stderr,
                },
            )

        try:
            payload = parse_json_payload(stdout)
        except SvcSiteError as exc:
            raise SvcSiteError(
                exc.code,
                exc.message,
                exc.exit_code,
                {"response": stdout[-1000:]},
            ) from exc

        if payload.get("ok") is not True:
            messages = {
                "KPM_CONTROL_BUSY": "another KPM control command is in progress; retry when it completes",
                "KPM_MONITORING_ENABLED": "stop monitoring before selecting syscall hooks",
                "KPM_SYSCALL_SELECTION_INVALID": "KPM requires a nonempty comma-separated syscall list",
                "SYSCALL_UNSUPPORTED": "syscall is outside the KPM static whitelist",
                "KPM_HOOK_INSTALL_FAILED": "KPM could not install a requested syscall hook",
            }
            code = payload.get("code")
            if isinstance(code, str) and code in messages:
                details = {}
                nr = payload.get("nr")
                if type(nr) is int and 0 <= nr < 512:
                    details["syscall_nr"] = nr
                raise SvcSiteError(code, messages[code], EXIT_KPM, details)
            raise SvcSiteError(
                "KPM_REJECTED",
                "KPM rejected the command",
                EXIT_KPM,
                {"reason": payload.get("error", "unknown")},
            )
        return payload

    def status(self) -> dict[str, Any]:
        return self.ctl0("status")

    def resolve_syscall(self, name: str) -> int | None:
        if not name.replace("_", "").isalnum():
            return None
        payload = self.ctl0(f"sysnr {name}")
        number = payload.get("nr")
        return number if isinstance(number, int) and number >= 0 else None

    def set_uid(self, uid: int) -> dict[str, Any]:
        return self.ctl0(f"uid {uid}")

    def set_pid(self, pid: int) -> dict[str, Any]:
        return self.ctl0(f"pid {pid}")

    def set_nrs(self, syscall_numbers: list[int]) -> dict[str, Any]:
        encoded = ",".join(str(number) for number in syscall_numbers)
        original_timeout = self.adb.timeout
        self.adb.timeout = max(original_timeout, 60.0)
        try:
            return self.ctl0(f"set_nrs {encoded}")
        finally:
            self.adb.timeout = original_timeout

    def clear(self) -> dict[str, Any]:
        return self.ctl0("clear")

    def start(self) -> dict[str, Any]:
        return self.ctl0("enable")

    def stop(self) -> dict[str, Any]:
        return self.ctl0("disable")
