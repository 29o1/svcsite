from __future__ import annotations

from collections import Counter
from typing import Any, Sequence

from z9mon.constants import KNOWN_SYSCALL_NAMES, KNOWN_SYSCALLS
from z9mon.errors import EXIT_USAGE, Z9MonError
from z9mon.maps import ModuleIndex
from z9mon.protocol import Event, parse_events
from z9mon.session import resolve_session, sequence_quality


def _syscall_maps(manifest: dict[str, Any]) -> tuple[dict[str, int], dict[int, str]]:
    by_name = dict(KNOWN_SYSCALLS)
    by_number = dict(KNOWN_SYSCALL_NAMES)
    configured = manifest.get("capture", {}).get("syscalls", [])
    if isinstance(configured, list):
        for item in configured:
            if not isinstance(item, dict):
                continue
            name, number = item.get("name"), item.get("nr")
            if isinstance(name, str) and isinstance(number, int):
                by_name[name] = number
                by_number[number] = name
    return by_name, by_number


def _resolve_syscall_filter(
    values: Sequence[str],
    by_name: dict[str, int],
) -> set[int]:
    selected: set[int] = set()
    unknown: list[str] = []
    for raw_value in values:
        value = raw_value.strip().removeprefix("sys_")
        if value.isdecimal():
            selected.add(int(value))
        elif value in by_name:
            selected.add(by_name[value])
        elif value:
            unknown.append(raw_value)
    if unknown:
        raise Z9MonError(
            "SYSCALL_UNKNOWN",
            "one or more syscall names are unknown",
            EXIT_USAGE,
            {"values": unknown},
        )
    return selected


def _matches(
    event: Event,
    *,
    syscall_numbers: set[int],
    pid: int | None,
    tid: int | None,
    contains: str | None,
    syscall_names: dict[int, str],
) -> bool:
    if syscall_numbers and event.nr not in syscall_numbers:
        return False
    if pid is not None and event.tgid != pid:
        return False
    if tid is not None and event.pid != tid:
        return False
    if contains:
        needle = contains.casefold()
        haystack = " ".join(
            (
                syscall_names.get(event.nr, f"sys_{event.nr}"),
                event.comm,
                event.description,
            )
        ).casefold()
        if needle not in haystack:
            return False
    return True


def _event_payload(
    event: Event,
    syscall_names: dict[int, str],
    module_index: ModuleIndex | None,
) -> dict[str, Any]:
    payload = event.to_dict(syscall_names)
    if module_index is None:
        return payload
    registers = payload["registers"]
    registers["pc_resolved"] = module_index.resolve(event.tgid, event.pc)
    registers["caller_resolved"] = module_index.resolve(event.tgid, event.caller)
    registers["clone_fn_resolved"] = module_index.resolve(
        event.tgid, event.clone_fn
    )
    payload["backtrace_resolved"] = [
        module_index.resolve(event.tgid, address) for address in event.backtrace
    ]
    return payload


def run_query(
    *,
    session: str,
    syscalls: Sequence[str],
    pid: int | None,
    tid: int | None,
    contains: str | None,
    limit: int,
    stats_only: bool,
) -> dict[str, Any]:
    session_dir, events_path, manifest = resolve_session(session)
    parsed = parse_events(events_path.read_bytes())
    module_index = ModuleIndex.from_session(session_dir)
    by_name, by_number = _syscall_maps(manifest)
    selected = _resolve_syscall_filter(syscalls, by_name)
    matching = [
        event
        for event in parsed.events
        if _matches(
            event,
            syscall_numbers=selected,
            pid=pid,
            tid=tid,
            contains=contains,
            syscall_names=by_number,
        )
    ]
    returned = [] if stats_only else matching[:limit]
    by_syscall = Counter(
        by_number.get(event.nr, f"sys_{event.nr}") for event in matching
    )
    by_pid = Counter(str(event.tgid) for event in matching)

    return {
        "session": str(session_dir),
        "source": str(events_path),
        "query": {
            "syscalls": list(syscalls),
            "pid": pid,
            "tid": tid,
            "contains": contains,
            "limit": limit,
            "stats_only": stats_only,
        },
        "counts": {
            "total": len(parsed.events),
            "matched": len(matching),
            "returned": len(returned),
            "truncated": max(0, len(matching) - len(returned))
            if not stats_only
            else 0,
        },
        "stats": {
            "by_syscall": dict(sorted(by_syscall.items())),
            "by_pid": dict(sorted(by_pid.items(), key=lambda item: int(item[0]))),
            "source_sequence": sequence_quality(parsed.events),
        },
        "parser": parsed.quality(),
        "address_resolution": {
            "available": module_index is not None,
            "source": str(module_index.source) if module_index else None,
        },
        "events": [
            _event_payload(event, by_number, module_index) for event in returned
        ],
    }
