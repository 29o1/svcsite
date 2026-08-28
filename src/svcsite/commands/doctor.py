from __future__ import annotations

import argparse
import platform
from typing import Any

from svcsite.adb import AdbClient
from svcsite.commands._common import add_common_options
from svcsite.config import read_superkey
from svcsite.errors import EXIT_DEVICE, SvcSiteError
from svcsite.kpm import find_kpatch, require_root

NAME = "doctor"


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="check host, device, root, kpatch, and SuperKey configuration",
    )
    add_common_options(parser)


def run(args: argparse.Namespace) -> dict[str, Any]:
    checks: list[dict[str, Any]] = [
        {
            "name": "python",
            "ok": True,
            "version": platform.python_version(),
        }
    ]

    try:
        adb = AdbClient(timeout=args.timeout)
        checks.append({"name": "adb", "ok": True, "path": adb.executable})

        serial = adb.resolve_serial(args.device)
        checks.append({"name": "device", "ok": True, "serial": serial})

        abi = adb.getprop("ro.product.cpu.abi")
        if abi != "arm64-v8a":
            raise SvcSiteError(
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

        key = read_superkey(args.key_file)
        checks.append({"name": "superkey", "ok": True, "source": key.source})
    except SvcSiteError as exc:
        checks.append({"name": exc.code.lower(), "ok": False, "code": exc.code})
        error = SvcSiteError(
            exc.code,
            exc.message,
            exc.exit_code,
            {**exc.details, "checks": checks},
        )
        raise error from exc

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
