from __future__ import annotations

import argparse
from typing import Any

from z9mon.commands._common import address_value, positive_integer
from z9mon.maps import run_address_resolve

NAME = "address"


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="resolve runtime addresses using a capture session's maps",
    )
    address_subparsers = parser.add_subparsers(
        dest="address_command",
        required=True,
    )
    resolve_parser = address_subparsers.add_parser(
        "resolve",
        help="resolve one runtime address to a module and relative offset",
    )
    resolve_parser.add_argument("session", help="capture session directory")
    resolve_parser.add_argument(
        "--pid",
        required=True,
        type=positive_integer,
        help="process ID whose maps should be used",
    )
    resolve_parser.add_argument(
        "--address",
        required=True,
        type=address_value,
        help="runtime address in decimal or 0x-prefixed hexadecimal",
    )
    resolve_parser.add_argument(
        "--json",
        action="store_true",
        help="emit one compact JSON object",
    )


def operation(args: argparse.Namespace) -> str:
    return f"{NAME}.{args.address_command}"


def run(args: argparse.Namespace) -> dict[str, Any]:
    return run_address_resolve(
        session=args.session,
        pid=args.pid,
        address=args.address,
    )
