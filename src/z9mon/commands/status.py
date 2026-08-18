from __future__ import annotations

import argparse
from typing import Any

from z9mon.commands._common import add_common_options
from z9mon.commands._device import build_controller
from z9mon.constants import MODULE_NAME

NAME = "status"


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="read z9null_monitor KPM status")
    add_common_options(parser)


def operation(args: argparse.Namespace) -> str:
    return NAME


def run(args: argparse.Namespace) -> dict[str, Any]:
    serial, controller = build_controller(args)
    return {
        "device": serial,
        "module": MODULE_NAME,
        "status": controller.status(),
    }
