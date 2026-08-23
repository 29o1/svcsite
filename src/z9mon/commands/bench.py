from __future__ import annotations

import argparse
import sys
from typing import Any, Sequence

from z9mon.bench import BenchOptions, render_compare_table, run_bench, run_compare
from z9mon.commands._common import (
    add_common_options,
    positive_integer,
    positive_timeout,
)
from z9mon.errors import EXIT_INTERNAL, Z9MonError
from z9mon.output import error_payload, success_payload, write_payload

def build_parser() -> argparse.ArgumentParser:
    from z9mon.cli import Z9MonArgumentParser

    parser = Z9MonArgumentParser(
        prog="z9mon-bench",
        description="development benchmark for capture quality and query performance",
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
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.bench_command == "run":
        return run_bench(
            BenchOptions(
                device=args.device,
                timeout=args.timeout,
                key_file=args.key_file,
                package=args.package,
                kpm=args.kpm,
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


def main(argv: Sequence[str] | None = None) -> int:
    argument_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    operation_name = (
        f"bench.{argument_list[0]}" if argument_list else "bench"
    )
    compact = "--json" in argument_list
    try:
        args = parser.parse_args(argument_list)
        operation_name = f"bench.{args.bench_command}"
        compact = args.json
        payload = success_payload(operation_name, run(args))
        exit_code = 0
    except Z9MonError as exc:
        payload = error_payload(operation_name, exc)
        exit_code = exc.exit_code
    except KeyboardInterrupt:
        error = Z9MonError("INTERRUPTED", "operation was interrupted", 130)
        payload = error_payload(operation_name, error)
        exit_code = error.exit_code
    except Exception as exc:
        error = Z9MonError(
            "INTERNAL_ERROR",
            "unexpected internal error",
            EXIT_INTERNAL,
            {"exception": type(exc).__name__},
        )
        payload = error_payload(operation_name, error)
        exit_code = error.exit_code
    write_payload(payload, sys.stdout, compact=compact)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
