from __future__ import annotations

import json
from typing import Any, TextIO

from svcsite.constants import RESULT_SCHEMA
from svcsite.errors import SvcSiteError


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
