from __future__ import annotations

import json
from typing import Any, TextIO

from z9mon.constants import RESULT_SCHEMA
from z9mon.errors import Z9MonError


def success_payload(operation: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": RESULT_SCHEMA,
        "ok": True,
        "operation": operation,
        "data": data,
        "warnings": [],
    }


def error_payload(operation: str, error: Z9MonError) -> dict[str, Any]:
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
