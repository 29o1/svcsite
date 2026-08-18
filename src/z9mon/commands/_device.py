from __future__ import annotations

import argparse

from z9mon.adb import AdbClient
from z9mon.config import read_superkey
from z9mon.kpm import KpmController, require_root


def build_controller(args: argparse.Namespace) -> tuple[str, KpmController]:
    adb = AdbClient(timeout=args.timeout)
    serial = adb.resolve_serial(args.device)
    require_root(adb)
    key = read_superkey(args.key_file)
    controller = KpmController(adb, key.value)
    controller.locate_kpatch()
    return serial, controller
