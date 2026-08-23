from __future__ import annotations

import argparse

from svcsite.adb import AdbClient
from svcsite.config import read_superkey
from svcsite.kpm import KpmController, require_root


def build_controller(args: argparse.Namespace) -> tuple[str, KpmController]:
    adb = AdbClient(timeout=args.timeout)
    serial = adb.resolve_serial(args.device)
    require_root(adb)
    key = read_superkey(args.key_file)
    controller = KpmController(adb, key.value)
    controller.locate_kpatch()
    return serial, controller
