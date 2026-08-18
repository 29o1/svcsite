from __future__ import annotations

import argparse
import sys
from typing import Any

from z9mon.bench import BenchOptions, render_compare_table, run_bench, run_compare
from z9mon.commands._common import (
    add_common_options,
    positive_integer,
    positive_timeout,
)
from z9mon.config import resolve_kpm_path

NAME = "bench"


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="benchmark capture quality and query performance",
    )
    bench_subparsers = parser.add_subparsers(
        dest="bench_command",
        required=True,
    )
    bench_run_parser = bench_subparsers.add_parser(
        "run",
        help="converge the module, run capture trials, and write a report",
    )
    add_common_options(bench_run_parser)
    bench_run_parser.add_argument(
        "--package",
        default="io.z9null.tracefixture",
        help="controlled workload package (default: io.z9null.tracefixture)",
    )
    bench_run_parser.add_argument(
        "--kpm",
        help=(
            "converge the loaded KPM to this local module file before the "
            "trials; replacement is skipped when the deployed sha256 matches"
        ),
    )
    bench_run_parser.add_argument(
        "--duration",
        type=positive_timeout,
        default=15.0,
        help="active capture duration per trial in seconds (default: 15)",
    )
    bench_run_parser.add_argument(
        "--trials",
        type=positive_integer,
        default=5,
        help="number of capture trials (default: 5)",
    )
    bench_run_parser.add_argument(
        "--query-iterations",
        type=positive_integer,
        default=5,
        help="query subprocess iterations per mode (default: 5)",
    )
    bench_run_parser.add_argument(
        "--target-mode",
        choices=("attach", "launch", "restart"),
        default="restart",
        help="target lifecycle mode for every trial (default: restart)",
    )
    bench_run_parser.add_argument(
        "--output",
        default="./bench",
        help="bench output directory (default: ./bench)",
    )
    bench_run_parser.add_argument(
        "--keep-sessions",
        action="store_true",
        help="keep every trial session instead of only the median one",
    )

    bench_compare_parser = bench_subparsers.add_parser(
        "compare",
        help="compare two bench reports with noise-aware verdicts",
    )
    bench_compare_parser.add_argument("baseline", help="baseline report.json path")
    bench_compare_parser.add_argument("candidate", help="candidate report.json path")
    bench_compare_parser.add_argument(
        "--json",
        action="store_true",
        help="emit one compact JSON object",
    )


def operation(args: argparse.Namespace) -> str:
    return f"{NAME}.{args.bench_command}"


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.bench_command == "run":
        return run_bench(
            BenchOptions(
                device=args.device,
                timeout=args.timeout,
                key_file=args.key_file,
                package=args.package,
                kpm=resolve_kpm_path(args.kpm),
                duration=args.duration,
                trials=args.trials,
                output=args.output,
                keep_sessions=args.keep_sessions,
                query_iterations=args.query_iterations,
                target_mode=args.target_mode,
            )
        )
    comparison = run_compare(args.baseline, args.candidate)
    sys.stderr.write(render_compare_table(comparison) + "\n")
    return comparison
