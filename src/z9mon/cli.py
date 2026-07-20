from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

from z9mon import __version__
from z9mon.capture import CaptureOptions, run_capture
from z9mon.commands import run_doctor, run_status, run_stop
from z9mon.errors import EXIT_INTERNAL, EXIT_USAGE, Z9MonError
from z9mon.output import error_payload, success_payload, write_payload
from z9mon.query import run_query


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


def _positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return number


def _flatten_values(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        item.strip()
        for value in values
        for item in value.split(",")
        if item.strip()
    )


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

    capture_parser = subparsers.add_parser(
        "capture",
        help="run one bounded syscall capture and save a session",
    )
    _add_common_options(capture_parser)
    capture_parser.add_argument("--package", required=True, help="Android package name")
    capture_parser.add_argument(
        "--duration",
        type=_positive_timeout,
        default=15.0,
        help="active capture duration in seconds (default: 15)",
    )
    capture_parser.add_argument(
        "--preset",
        default="reverse-basic",
        help="syscall preset (default: reverse-basic)",
    )
    capture_parser.add_argument(
        "--syscall",
        action="append",
        default=[],
        help="custom syscall name/number; repeat or comma-separate (overrides preset)",
    )
    capture_parser.add_argument(
        "--launch",
        action="store_true",
        help="launch the target without first stopping it",
    )
    capture_parser.add_argument(
        "--restart",
        action="store_true",
        help="force-stop and relaunch the target without clearing app data",
    )
    capture_parser.add_argument(
        "--output",
        default="./captures",
        help="session output directory (default: ./captures)",
    )
    capture_parser.add_argument(
        "--load-module",
        help="explicitly replace/load the KPM from this local absolute or relative path",
    )

    query_parser = subparsers.add_parser(
        "query",
        help="filter a capture session without loading all events into Agent context",
    )
    query_parser.add_argument("session", help="capture session directory or events.bin")
    query_parser.add_argument(
        "--syscall",
        action="append",
        default=[],
        help="syscall name/number filter; repeat or comma-separate",
    )
    query_parser.add_argument("--pid", type=_positive_integer, help="process ID filter")
    query_parser.add_argument("--tid", type=_positive_integer, help="thread ID filter")
    query_parser.add_argument("--contains", help="case-insensitive text filter")
    query_parser.add_argument(
        "--limit",
        type=_positive_integer,
        default=100,
        help="maximum returned events (default: 100)",
    )
    query_parser.add_argument(
        "--stats",
        action="store_true",
        help="return aggregate counts without event objects",
    )
    query_parser.add_argument(
        "--format",
        choices=("json", "jsonl"),
        default="json",
        help="output encoding (default: json)",
    )
    query_parser.add_argument(
        "--json",
        action="store_true",
        help="emit one compact JSON object",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argument_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    operation = next(
        (
            value
            for value in argument_list
            if value in {"doctor", "status", "stop", "capture", "query"}
        ),
        "cli",
    )
    jsonl = operation == "query" and "jsonl" in argument_list
    compact = "--json" in argument_list or jsonl

    try:
        args = parser.parse_args(argument_list)
        operation = args.command
        compact = args.json
        jsonl = operation == "query" and args.format == "jsonl"
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
        elif operation == "stop":
            data = run_stop(
                device=args.device,
                timeout=args.timeout,
                key_file=args.key_file,
            )
        elif operation == "capture":
            data = run_capture(
                CaptureOptions(
                    device=args.device,
                    timeout=args.timeout,
                    key_file=args.key_file,
                    package=args.package,
                    duration=args.duration,
                    preset=args.preset,
                    syscalls=_flatten_values(args.syscall),
                    launch=args.launch,
                    restart=args.restart,
                    output=args.output,
                    load_module=args.load_module,
                )
            )
        else:
            data = run_query(
                session=args.session,
                syscalls=_flatten_values(args.syscall),
                pid=args.pid,
                tid=args.tid,
                contains=args.contains,
                limit=args.limit,
                stats_only=args.stats,
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

    if jsonl and exit_code == 0:
        for event in payload["data"]["events"]:
            sys.stdout.write(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
            sys.stdout.write("\n")
    else:
        write_payload(payload, sys.stdout, compact=compact)
    return exit_code
