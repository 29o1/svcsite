from __future__ import annotations

import argparse
import sys
from typing import Any, Sequence

from svcsite import __version__
from svcsite.commands import COMMAND_MODULES
from svcsite.errors import EXIT_USAGE, SvcSiteError
from svcsite.output import execute_operation


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

    def prepare() -> tuple[str, bool, Any]:
        args = parser.parse_args(argument_list)
        module = modules[args.command]
        return module.NAME, args.json, lambda: module.run(args)

    return execute_operation(
        operation,
        compact=compact,
        prepare=prepare,
        stream=sys.stdout,
    )
