from __future__ import annotations

import argparse
from typing import Any

from z9mon.commands._common import add_common_options
from z9mon.commands._device import build_controller
from z9mon.constants import MODULE_NAME

NAME = "stop"


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="pause z9null_monitor KPM monitoring",
    )
    add_common_options(parser)


def operation(args: argparse.Namespace) -> str:
    return NAME


def run(args: argparse.Namespace) -> dict[str, Any]:
    serial, controller = build_controller(args)
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
