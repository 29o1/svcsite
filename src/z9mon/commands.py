from __future__ import annotations

import platform
from typing import Any

from z9mon.adb import AdbClient
from z9mon.config import read_superkey
from z9mon.constants import MODULE_NAME
from z9mon.errors import EXIT_DEVICE, Z9MonError
from z9mon.kpm import KpmController, find_kpatch, require_root


def _with_checks(error: Z9MonError, checks: list[dict[str, Any]]) -> Z9MonError:
    details = dict(error.details)
    details["checks"] = checks
    return Z9MonError(error.code, error.message, error.exit_code, details)


def run_doctor(
    *,
    device: str | None,
    timeout: float,
    key_file: str | None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = [
        {
            "name": "python",
            "ok": True,
            "version": platform.python_version(),
        }
    ]

    try:
        adb = AdbClient(timeout=timeout)
        checks.append({"name": "adb", "ok": True, "path": adb.executable})

        serial = adb.resolve_serial(device)
        checks.append({"name": "device", "ok": True, "serial": serial})

        abi = adb.getprop("ro.product.cpu.abi")
        if abi != "arm64-v8a":
            raise Z9MonError(
                "UNSUPPORTED_ABI",
                "device ABI is not supported",
                EXIT_DEVICE,
                {"abi": abi, "required": "arm64-v8a"},
            )
        checks.append({"name": "abi", "ok": True, "value": abi})

        android_version = adb.getprop("ro.build.version.release")
        checks.append(
            {
                "name": "android",
                "ok": True,
                "version": android_version,
            }
        )

        require_root(adb)
        checks.append({"name": "root", "ok": True})

        kpatch_path = find_kpatch(adb)
        checks.append({"name": "kpatch", "ok": True, "path": kpatch_path})

        key = read_superkey(key_file)
        checks.append({"name": "superkey", "ok": True, "source": key.source})
    except Z9MonError as exc:
        checks.append({"name": exc.code.lower(), "ok": False, "code": exc.code})
        raise _with_checks(exc, checks) from exc

    return {
        "device": {
            "serial": serial,
            "abi": abi,
            "android_version": android_version,
        },
        "kpatch": kpatch_path,
        "superkey_source": key.source,
        "checks": checks,
    }


def _controller(
    *,
    device: str | None,
    timeout: float,
    key_file: str | None,
) -> tuple[str, KpmController]:
    adb = AdbClient(timeout=timeout)
    serial = adb.resolve_serial(device)
    require_root(adb)
    key = read_superkey(key_file)
    controller = KpmController(adb, key.value)
    controller.locate_kpatch()
    return serial, controller


def run_status(
    *,
    device: str | None,
    timeout: float,
    key_file: str | None,
) -> dict[str, Any]:
    serial, controller = _controller(
        device=device,
        timeout=timeout,
        key_file=key_file,
    )
    return {
        "device": serial,
        "module": MODULE_NAME,
        "status": controller.status(),
    }


def run_stop(
    *,
    device: str | None,
    timeout: float,
    key_file: str | None,
) -> dict[str, Any]:
    serial, controller = _controller(
        device=device,
        timeout=timeout,
        key_file=key_file,
    )
    if not controller.is_loaded():
        return {
            "device": serial,
            "module": MODULE_NAME,
            "status": {"loaded": False, "enabled": False},
        }
    return {
        "device": serial,
        "module": MODULE_NAME,
        "status": controller.stop(),
    }
