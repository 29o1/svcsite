from __future__ import annotations

import argparse
from typing import Any

from svcsite.capture import CaptureOptions, run_capture
from svcsite.commands._common import (
    add_common_options,
    flatten_values,
    positive_integer,
    positive_timeout,
)

NAME = "capture"


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="run one bounded syscall capture and save a session",
    )
    add_common_options(parser)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--package", help="Android package name")
    target.add_argument(
        "--pid",
        type=positive_integer,
        help="exact process ID/TGID to monitor (attach mode only)",
    )
    parser.add_argument(
        "--duration",
        type=positive_timeout,
        default=15.0,
        help="active capture duration in seconds (default: 15)",
    )
    parser.add_argument(
        "--syscall",
        action="append",
        default=[],
        help=(
            "custom syscall name/number; repeat or comma-separate; "
            "defaults to reverse-basic"
        ),
    )
    parser.add_argument(
        "--target-mode",
        choices=("attach", "launch", "restart"),
        default="attach",
        help="target lifecycle mode (default: attach)",
    )
    parser.add_argument(
        "--output",
        default="./captures",
        help="session output directory (default: ./captures)",
    )
    parser.add_argument(
        "--kpm",
        help=(
            "converge the loaded KPM to this local module file; "
            "replacement is skipped when the deployed sha256 already matches"
        ),
    )


def operation(args: argparse.Namespace) -> str:
    return NAME


def run(args: argparse.Namespace) -> dict[str, Any]:
    return run_capture(
        CaptureOptions(
            device=args.device,
            timeout=args.timeout,
            key_file=args.key_file,
            package=args.package,
            duration=args.duration,
            syscalls=flatten_values(args.syscall),
            target_mode=args.target_mode,
            output=args.output,
            kpm=args.kpm,
            pid=args.pid,
        )
    )
