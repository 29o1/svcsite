from __future__ import annotations

from collections.abc import Mapping
from typing import Any


EXIT_USAGE = 2
EXIT_CONFIG = 10
EXIT_ENVIRONMENT = 20
EXIT_DEVICE = 21
EXIT_ROOT = 22
EXIT_KPATCH = 23
EXIT_KPM = 30
EXIT_INTERNAL = 70


class Z9MonError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        exit_code: int,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code
        self.details = dict(details or {})
