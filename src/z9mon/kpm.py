from __future__ import annotations

import json
import shlex
from typing import Any

from z9mon.adb import AdbClient
from z9mon.constants import KPATCH_CANDIDATES, MODULE_NAME
from z9mon.errors import EXIT_KPATCH, EXIT_KPM, EXIT_ROOT, Z9MonError


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, "***") if secret else text


def parse_json_payload(raw: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    last_payload: dict[str, Any] | None = None

    for index, character in enumerate(raw):
        if character != "{":
            continue
        try:
            payload, _ = decoder.raw_decode(raw[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            last_payload = payload

    if last_payload is None:
        raise Z9MonError(
            "KPM_INVALID_RESPONSE",
            "KPM did not return a JSON object",
            EXIT_KPM,
        )
    return last_payload


def require_root(adb: AdbClient) -> None:
    result = adb.root_shell("id -u")
    if result.returncode != 0 or result.stdout.strip() != "0":
        raise Z9MonError(
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
        raise Z9MonError(
            "KPATCH_NOT_FOUND",
            "kpatch executable was not found on the device",
            EXIT_KPATCH,
            {"candidates": list(KPATCH_CANDIDATES)},
        )

    path = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if path not in KPATCH_CANDIDATES:
        raise Z9MonError(
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

    def ctl0(self, command: str) -> dict[str, Any]:
        if "\0" in command or "\n" in command or "\r" in command:
            raise Z9MonError(
                "KPM_COMMAND_INVALID",
                "KPM command contains an unsupported control character",
                EXIT_KPM,
            )

        kpatch_path = self.kpatch_path or self.locate_kpatch()
        remote_command = shlex.join(
            (
                kpatch_path,
                self.superkey,
                "kpm",
                "ctl0",
                MODULE_NAME,
                command,
            )
        )
        result = self.adb.root_shell(remote_command)
        stdout = _redact(result.stdout, self.superkey).strip()
        stderr = _redact(result.stderr, self.superkey).strip()

        if result.returncode != 0:
            raise Z9MonError(
                "KPM_COMMAND_FAILED",
                "KPM ctl0 command failed",
                EXIT_KPM,
                {
                    "returncode": result.returncode,
                    "stderr": stderr,
                },
            )

        try:
            payload = parse_json_payload(stdout)
        except Z9MonError as exc:
            raise Z9MonError(
                exc.code,
                exc.message,
                exc.exit_code,
                {"response": stdout[-1000:]},
            ) from exc

        if payload.get("ok") is not True:
            raise Z9MonError(
                "KPM_REJECTED",
                "KPM rejected the command",
                EXIT_KPM,
                {"reason": payload.get("error", "unknown")},
            )
        return payload

    def status(self) -> dict[str, Any]:
        return self.ctl0("status")

    def stop(self) -> dict[str, Any]:
        return self.ctl0("disable")
