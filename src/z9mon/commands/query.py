from __future__ import annotations

import argparse
from typing import Any

from z9mon.commands._common import flatten_values, positive_integer
from z9mon.errors import EXIT_USAGE, Z9MonError
from z9mon.query import run_query

NAME = "query"


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="filter a capture session without loading all events into Agent context",
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
        help="maximum returned events or callsites (default: 20)",
    )
    parser.add_argument(
        "--mode",
        choices=("events", "stats", "callsites"),
        default="events",
        help="query result mode (default: events)",
    )
    parser.add_argument(
        "--module-id",
        action="append",
        default=[],
        help="require a callsite with this exact module_id; may be repeated",
    )
    parser.add_argument(
        "--detail",
        choices=("compact", "full"),
        default="compact",
        help="event address detail (default: compact)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "jsonl"),
        default="json",
        help="output encoding (default: json)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit one compact JSON object",
    )


def operation(args: argparse.Namespace) -> str:
    return NAME


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.json and args.format == "jsonl":
        raise Z9MonError(
            "USAGE_ERROR",
            "--json and --format jsonl are mutually exclusive",
            EXIT_USAGE,
        )
    if args.format == "jsonl" and args.mode != "events":
        raise Z9MonError(
            "USAGE_ERROR",
            "JSONL output requires query mode events",
            EXIT_USAGE,
        )
    if args.mode != "events" and args.detail != "compact":
        raise Z9MonError(
            "USAGE_ERROR",
            "--detail applies only to query mode events",
            EXIT_USAGE,
        )
    return run_query(
        session=args.session,
        mode=args.mode,
        syscalls=flatten_values(args.syscall),
        pid=args.pid,
        tid=args.tid,
        contains=args.contains,
        limit=args.limit,
        detail=args.detail,
        module_ids=tuple(args.module_id),
    )
