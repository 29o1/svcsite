from __future__ import annotations

import argparse
from typing import Any

from svcsite.commands._common import flatten_values, positive_integer
from svcsite.query import run_query

NAME = "query"


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="return bounded events and ranked callsites from a session",
    )
    parser.add_argument("session", help="capture session directory or events.bin")
    parser.add_argument(
        "--syscall",
        action="append",
        default=[],
        help="syscall name/number filter; repeat or comma-separate",
    )
    parser.add_argument("--pid", type=positive_integer, help="process ID filter")
    parser.add_argument("--tid", type=positive_integer, help="thread ID filter")
    parser.add_argument("--contains", help="case-insensitive text filter")
    parser.add_argument(
        "--limit",
        type=positive_integer,
        default=20,
        help="maximum returned events and callsites (default: 20)",
    )
    parser.add_argument(
        "--module-id",
        action="append",
        default=[],
        help="require a callsite with this exact module_id; may be repeated",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit one compact JSON object",
    )


def run(args: argparse.Namespace) -> dict[str, Any]:
    return run_query(
        session=args.session,
        syscalls=flatten_values(args.syscall),
        pid=args.pid,
        tid=args.tid,
        contains=args.contains,
        limit=args.limit,
        module_ids=tuple(args.module_id),
    )
