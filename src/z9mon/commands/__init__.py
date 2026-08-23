from __future__ import annotations

from z9mon.commands import (
    capture,
    doctor,
    query,
    status,
    stop,
)

COMMAND_MODULES = (doctor, status, stop, capture, query)
