from __future__ import annotations

import argparse
import sys
from typing import Sequence

from svcsite import __version__
from svcsite.commands import COMMAND_MODULES
from svcsite.errors import EXIT_INTERNAL, EXIT_USAGE, SvcSiteError
from svcsite.output import error_payload, success_payload, write_payload


class SvcSiteArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise SvcSiteError("USAGE_ERROR", message, EXIT_USAGE)


def build_parser() -> argparse.ArgumentParser:
    parser = SvcSiteArgumentParser(
        prog="svcsite",
        description="Agent-friendly Android syscall dynamic analysis CLI",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for module in COMMAND_MODULES:
        module.add_parser(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argument_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    modules = {module.NAME: module for module in COMMAND_MODULES}
    # Pre-parse operation/output state so usage errors still emit JSON with
    # the right operation name.
    operation = (
        argument_list[0]
        if argument_list and argument_list[0] in modules
        else "cli"
    )
    compact = "--json" in argument_list

    try:
        args = parser.parse_args(argument_list)
        module = modules[args.command]
        operation = module.NAME
        compact = args.json
        data = module.run(args)
        payload = success_payload(operation, data)
        exit_code = 0
    except SvcSiteError as exc:
        payload = error_payload(operation, exc)
        exit_code = exc.exit_code
    except KeyboardInterrupt:
        error = SvcSiteError("INTERRUPTED", "operation was interrupted", 130)
        payload = error_payload(operation, error)
        exit_code = error.exit_code
    except Exception as exc:
        error = SvcSiteError(
            "INTERNAL_ERROR",
            "unexpected internal error",
            EXIT_INTERNAL,
            {"exception": type(exc).__name__},
        )
        payload = error_payload(operation, error)
        exit_code = error.exit_code

    write_payload(payload, sys.stdout, compact=compact)
    return exit_code
