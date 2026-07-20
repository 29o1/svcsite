from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from z9mon import __version__
from z9mon.commands import run_doctor, run_status, run_stop
from z9mon.errors import EXIT_INTERNAL, EXIT_USAGE, Z9MonError
from z9mon.output import error_payload, success_payload, write_payload


class Z9MonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Z9MonError("USAGE_ERROR", message, EXIT_USAGE)


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return timeout


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--device",
        default=os.environ.get("ANDROID_SERIAL"),
        help="ADB device serial; defaults to ANDROID_SERIAL or the only ready device",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_timeout,
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


def build_parser() -> argparse.ArgumentParser:
    parser = Z9MonArgumentParser(
        prog="z9mon",
        description="Agent-friendly Android syscall dynamic analysis CLI",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("doctor", "check host, device, root, kpatch, and SuperKey configuration"),
        ("status", "read z9null_monitor KPM status"),
        ("stop", "pause z9null_monitor KPM monitoring"),
    ):
        command_parser = subparsers.add_parser(name, help=help_text)
        _add_common_options(command_parser)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argument_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    operation = next(
        (value for value in argument_list if value in {"doctor", "status", "stop"}),
        "cli",
    )
    compact = "--json" in argument_list

    try:
        args = parser.parse_args(argument_list)
        operation = args.command
        compact = args.json
        if operation == "doctor":
            data = run_doctor(
                device=args.device,
                timeout=args.timeout,
                key_file=args.key_file,
            )
        elif operation == "status":
            data = run_status(
                device=args.device,
                timeout=args.timeout,
                key_file=args.key_file,
            )
        else:
            data = run_stop(
                device=args.device,
                timeout=args.timeout,
                key_file=args.key_file,
            )
        payload = success_payload(operation, data)
        exit_code = 0
    except Z9MonError as exc:
        payload = error_payload(operation, exc)
        exit_code = exc.exit_code
    except KeyboardInterrupt:
        error = Z9MonError("INTERRUPTED", "operation was interrupted", 130)
        payload = error_payload(operation, error)
        exit_code = error.exit_code
    except Exception as exc:
        error = Z9MonError(
            "INTERNAL_ERROR",
            "unexpected internal error",
            EXIT_INTERNAL,
            {"exception": type(exc).__name__},
        )
        payload = error_payload(operation, error)
        exit_code = error.exit_code

    write_payload(payload, sys.stdout, compact=compact)
    return exit_code
