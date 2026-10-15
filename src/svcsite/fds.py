"""Conservative, offline fd provenance from observed entry/return pairs.

This is an observed history, not a snapshot of the kernel fd table. Missing
creators and inherited descriptors stay unknown. Unobserved alias changes cannot
be reconstructed; provenance is explicitly marked observed, never confirmed.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from svcsite.protocol import Event

_FD_CALLS = {
    25,
    29,
    57,
    61,
    62,
    63,
    64,
    65,
    66,
    67,
    68,
    80,
    200,
    201,
    202,
    203,
    206,
    207,
    208,
    209,
    210,
    211,
    212,
    222,
    242,
}
_CREATORS = {56, 198, 202, 242, 279}
_PATH = re.compile(r'\bpath="(.*)"\s+flags=')
_ENDPOINT = re.compile(r'AF_INET6 \[[^\]]+\]:\d+|AF_INET [\d.]+:\d+|AF_UNIX "[^\n]*"')
_MAX_TRACKED = 4096


def _fd(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & (1 << 31) else value


def _event_fd(event: Event) -> int:
    if event.nr == 222:
        return -1 if event.arguments[3] & 0x20 else _fd(event.arguments[4])
    return _fd(event.arguments[0])


class FdTracker:
    def __init__(self, *, lifecycle_captured: bool) -> None:
        self.lifecycle_captured = lifecycle_captured
        self.resources: dict[tuple[int, int], dict[str, Any]] = {}
        self.pending: dict[tuple[int, int], tuple[Event, dict[str, Any] | None]] = {}

    def clear(self) -> None:
        self.resources.clear()
        self.pending.clear()

    def _forget_process(self, pid: int) -> None:
        self.resources = {
            key: value for key, value in self.resources.items() if key[0] != pid
        }
        self.pending = {
            key: value for key, value in self.pending.items() if key[0] != pid
        }

    def _invalidate_fd(self, key: tuple[int, int]) -> None:
        self.resources.pop(key, None)
        # Concurrent close/reuse makes an in-flight operation ambiguous.
        self.pending = {
            thread: value
            for thread, value in self.pending.items()
            if not (
                thread[0] == key[0]
                and value[0].nr in _FD_CALLS
                and _event_fd(value[0]) == key[1]
            )
        }

    def observe(self, event: Event) -> dict[str, Any] | None:
        if len(self.resources) >= _MAX_TRACKED or len(self.pending) >= _MAX_TRACKED:
            self.clear()
        process = event.tgid
        thread = (process, event.pid)
        fd = _event_fd(event)
        key = (process, fd)
        resource = deepcopy(self.resources.get(key)) if event.nr in _FD_CALLS else None
        if event.nr in (93, 94, 220, 435, 221, 281, 97):
            # Do not infer fd inheritance, CLONE_FILES or CLOEXEC behavior.
            self._forget_process(process)
        if event.flags == 1:
            self.pending[thread] = (event, resource)
            if event.nr == 57:
                # Linux can release a descriptor even when close returns an error.
                self._invalidate_fd(key)
            elif event.nr in (23, 24, 436):
                self._forget_process(process)
        elif event.flags == 2:
            pending = self.pending.pop(thread, None)
            entry = pending[0] if pending else None
            if entry is None or entry.seq != event.entry_seq or entry.nr != event.nr:
                entry = None
                resource = None
            elif pending:
                resource = pending[1]
            ret = event.ret
            if ret is not None and ret >= 0 and event.nr in _CREATORS:
                key = (process, ret)
                self._invalidate_fd(key)
                resource = self._created(event, entry)
                if resource and self.lifecycle_captured:
                    self.resources[key] = resource
                fd = ret
            elif entry and event.nr == 203:
                endpoint = _ENDPOINT.search(entry.description)
                # A failed reconnect must not preserve an earlier peer as current.
                self.resources.pop(key, None)
                resource = None
                if endpoint and ret in (0, -115):
                    resource = {
                        "kind": "socket",
                        "peer": endpoint.group(),
                        "connection": "connected" if ret == 0 else "pending",
                        "source_seq": entry.seq,
                    }
                    if self.lifecycle_captured:
                        self.resources[key] = resource
            elif entry and event.nr == 209 and event.arguments[1:3] == (1, 4):
                match = re.search(r"\bSO_ERROR=(\d+)", event.description)
                if ret == 0 and match and key in self.resources:
                    current = deepcopy(self.resources[key])
                    # Zero SO_ERROR alone is not evidence of a connect attempt.
                    if current.get("connection") == "pending":
                        current["connection"] = (
                            "connected" if match[1] == "0" else "failed"
                        )
                        self.resources[key] = resource = current
            elif (
                event.nr == 25
                and event.arguments[1] in (0, 1030)
                and ret is not None
                and ret >= 0
            ):
                # Duplicates can share socket state; leave the new alias unknown.
                self.resources.pop((process, ret), None)
            elif event.nr == 212 and "control_bytes=" in event.description:
                # SCM_RIGHTS may introduce aliases, including across processes.
                self.clear()
                resource = None
        if event.nr not in _FD_CALLS and event.nr not in _CREATORS:
            return None
        if not self.lifecycle_captured:
            resource = None
        return {
            "fd": (
                event.ret
                if event.return_valid and event.ret is not None and event.ret >= 0
                else None
            )
            if event.nr in _CREATORS
            else fd,
            "resource": deepcopy(resource),
            "confidence": "observed" if resource else "unknown",
        }

    @staticmethod
    def _created(event: Event, entry: Event | None) -> dict[str, Any] | None:
        if entry is None:
            return None
        if event.nr == 56:
            match = _PATH.search(entry.description)
            if not match:
                return None
            return {
                "kind": "file",
                "path": match[1],
                "dirfd": _fd(entry.arguments[0]),
                "path_basis": "openat",
                "source_seq": entry.seq,
            }
        if event.nr == 198:
            return {
                "kind": "socket",
                "domain": entry.arguments[0],
                "type": entry.arguments[1],
                "connection": "unconnected",
                "source_seq": entry.seq,
            }
        if event.nr in (202, 242):
            endpoint = _ENDPOINT.search(event.description)
            return {
                "kind": "socket",
                "peer": endpoint.group() if endpoint else None,
                "connection": "connected",
                "source_seq": entry.seq,
            }
        return None
