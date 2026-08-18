from __future__ import annotations

import argparse
import os
from typing import Sequence


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return timeout


def positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return number


def address_value(value: str) -> int:
    try:
        address = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "address must be a decimal or 0x-prefixed hexadecimal integer"
        ) from exc
    if address <= 0:
        raise argparse.ArgumentTypeError("address must be greater than zero")
    return address


def flatten_values(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        item.strip()
        for value in values
        for item in value.split(",")
        if item.strip()
    )


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--device",
        default=os.environ.get("ANDROID_SERIAL"),
        help="ADB device serial; defaults to ANDROID_SERIAL or the only ready device",
    )
    parser.add_argument(
        "--timeout",
        type=positive_timeout,
        default=15.0,
        help="per-command timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "--key-file",
        help="SuperKey file; defaults to Z9MON_SUPERKEY_FILE or ~/.config/z9mon/superkey",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit one compact JSON object",
    )
