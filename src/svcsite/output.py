from __future__ import annotations

from collections.abc import Callable
import json
from typing import Any, TextIO

from svcsite.constants import RESULT_SCHEMA
from svcsite.errors import EXIT_INTERNAL, SvcSiteError


_PreparedOperation = tuple[
    str,
    bool,
    Callable[[], dict[str, Any]],
]


def success_payload(operation: str, data: dict[str, Any]) -> dict[str, Any]:
    payload_data = dict(data)
    warnings = payload_data.pop("warnings", [])
    if not isinstance(warnings, list):
        warnings = []
    return {
        "schema_version": RESULT_SCHEMA,
        "ok": True,
        "operation": operation,
        "data": payload_data,
        "warnings": warnings,
    }


def error_payload(operation: str, error: SvcSiteError) -> dict[str, Any]:
    return {
        "schema_version": RESULT_SCHEMA,
        "ok": False,
        "operation": operation,
        "error": {
            "code": error.code,
            "message": error.message,
            "details": error.details,
        },
    }


def write_payload(
    payload: dict[str, Any],
    stream: TextIO,
    *,
    compact: bool,
) -> None:
    if compact:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    else:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    stream.write(encoded)
    stream.write("\n")


def execute_operation(
    operation: str,
    *,
    compact: bool,
    prepare: Callable[[], _PreparedOperation],
    stream: TextIO,
) -> int:
    try:
        operation, compact, action = prepare()
        payload = success_payload(operation, action())
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

    write_payload(payload, stream, compact=compact)
    return exit_code
