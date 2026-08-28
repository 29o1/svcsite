from __future__ import annotations

import argparse
from typing import Any

from svcsite.commands._common import add_common_options
from svcsite.commands._device import build_controller
from svcsite.constants import MODULE_NAME

NAME = "status"


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="read svcsite KPM status")
    add_common_options(parser)


def run(args: argparse.Namespace) -> dict[str, Any]:
    serial, controller = build_controller(args)
    return {
        "device": serial,
        "module": MODULE_NAME,
        "status": controller.status(),
    }
