from __future__ import annotations

from collections import Counter
from typing import Any, Sequence

from z9mon.constants import KNOWN_SYSCALL_NAMES, KNOWN_SYSCALLS
from z9mon.hexutil import hex_str
from z9mon.errors import EXIT_DATA, EXIT_USAGE, Z9MonError
from z9mon.maps import ModuleIndex
from z9mon.protocol import Event, open_event_stream
from z9mon.session import resolve_session


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
    detail: str,
) -> dict[str, Any]:
    payload = event.to_dict(syscall_names)
    caller_callsite = event.caller - 4 if event.caller >= 4 else None
    backtrace_callsites = [
        None if address == event.pc or address < 4 else address - 4
        for address in event.backtrace
    ]
    registers = payload["registers"]
    registers["caller_callsite"] = (
        hex_str(caller_callsite) if caller_callsite is not None else None
    )
    payload["backtrace_callsites"] = [
        hex_str(address) if address is not None else None
        for address in backtrace_callsites
    ]
    if module_index is None:
        return payload
    compact = detail == "compact"
    registers["pc_resolved"] = _resolution_payload(
        module_index.resolve(event.tgid, event.pc), compact
    )
    registers["caller_callsite_resolved"] = (
        _resolution_payload(
            module_index.resolve(event.tgid, caller_callsite), compact
        )
        if caller_callsite is not None
        else None
    )
    registers["clone_fn_resolved"] = _resolution_payload(
        module_index.resolve(event.tgid, event.clone_fn), compact
    )
    payload["backtrace_callsites_resolved"] = [
        _resolution_payload(module_index.resolve(event.tgid, address), compact)
        if address is not None
        else None
        for address in backtrace_callsites
    ]
    if not compact:
        registers["caller_resolved"] = module_index.resolve(
            event.tgid, event.caller
        )
        payload["backtrace_resolved"] = [
            module_index.resolve(event.tgid, address) for address in event.backtrace
        ]
    return payload


_COMPACT_RESOLUTION_FIELDS = (
    "runtime",
    "snapshot_id",
    "module",
    "module_id",
    "path",
    "module_offset",
)


def _resolution_payload(
    resolved: dict[str, Any] | None,
    compact: bool,
) -> dict[str, Any] | None:
    if resolved is None or not compact:
        return resolved
    return {key: resolved.get(key) for key in _COMPACT_RESOLUTION_FIELDS}


def event_callsites(
    event: Event,
    module_index: ModuleIndex,
) -> list[dict[str, Any]]:
    candidates: list[tuple[str, int | None, int]] = [("pc", None, event.pc)]
    if event.caller >= 4:
        candidates.append(("caller", None, event.caller - 4))
    candidates.extend(
        ("backtrace", depth, address - 4)
        for depth, address in enumerate(event.backtrace)
        if address != event.pc and address >= 4
    )
    callsites: list[dict[str, Any]] = []
    for frame, depth, address in candidates:
        resolved = module_index.resolve(event.tgid, address)
        if resolved is None:
            continue
        callsites.append(
            {
                "frame": frame,
                "depth": depth,
                "address": address,
                "resolved": resolved,
            }
        )
    return callsites


def _module_matches(
    callsites: Sequence[dict[str, Any]],
    module_ids: set[str],
) -> bool:
    return not module_ids or any(
        callsite["resolved"].get("module_id") in module_ids
        for callsite in callsites
    )


def _update_callsite_counts(
    counts: dict[tuple[int, str | None, str | None, str | None, str], dict[str, Any]],
    event: Event,
    callsites: Sequence[dict[str, Any]],
    syscall_names: dict[int, str],
    module_ids: set[str],
) -> None:
    seen: set[tuple[int, str | None, str | None, str | None, str]] = set()
    for callsite in callsites:
        resolved = callsite["resolved"]
        module_id = resolved.get("module_id")
        if module_ids and module_id not in module_ids:
            continue
        key = (
            event.nr,
            module_id,
            resolved.get("path"),
            resolved.get("module"),
            resolved["module_offset"],
        )
        if key in seen:
            continue
        seen.add(key)
        current = counts.get(key)
        if current is None:
            counts[key] = {
                "syscall": {
                    "nr": event.nr,
                    "name": syscall_names.get(event.nr, f"sys_{event.nr}"),
                },
                "module": resolved.get("module"),
                "module_id": module_id,
                "path": resolved.get("path"),
                "module_offset": resolved["module_offset"],
                "count": 1,
                "frames": {callsite["frame"]},
                "sample": {
                    "seq": event.seq,
                    "pid": event.tgid,
                    "tid": event.pid,
                    "address": hex_str(callsite["address"]),
                },
            }
        else:
            current["count"] += 1
            current["frames"].add(callsite["frame"])


def _sorted_callsites(
    counts: dict[tuple[int, str | None, str | None, str | None, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    callsites = sorted(
        counts.values(),
        key=lambda item: (
            -item["count"],
            item["module_id"] or "",
            int(item["module_offset"], 0),
            item["syscall"]["nr"],
        ),
    )
    for item in callsites:
        item["frames"] = sorted(item["frames"])
    return callsites


def _update_module_counts(
    counts: dict[tuple[str | None, str | None, str | None], dict[str, Any]],
    callsites: Sequence[dict[str, Any]],
) -> None:
    seen: set[tuple[str | None, str | None, str | None]] = set()
    for callsite in callsites:
        resolved = callsite["resolved"]
        key = (
            resolved.get("module_id"),
            resolved.get("path"),
            resolved.get("module"),
        )
        if not isinstance(key[0], str):
            continue
        if key in seen:
            continue
        seen.add(key)
        current = counts.get(key)
        if current is None:
            counts[key] = {
                "module": key[2],
                "module_id": key[0],
                "path": key[1],
                "event_count": 1,
            }
        else:
            current["event_count"] += 1


def run_query(
    *,
    session: str,
    mode: str,
    syscalls: Sequence[str],
    pid: int | None,
    tid: int | None,
    contains: str | None,
    limit: int,
    detail: str = "compact",
    module_ids: Sequence[str] = (),
) -> dict[str, Any]:
    session_dir, events_path, manifest = resolve_session(session)
    module_index = ModuleIndex.from_session(session_dir)
    by_name, by_number = _syscall_maps(manifest)
    selected = _resolve_syscall_filter(syscalls, by_name)
    selected_module_ids = {value for value in module_ids if value}
    if (selected_module_ids or mode == "callsites") and module_index is None:
        raise Z9MonError(
            "MODULES_NOT_FOUND",
            "module-aware query requires modules.json",
            EXIT_DATA,
            {"session": str(session_dir)},
        )

    returned: list[Event] = []
    by_syscall: Counter[str] = Counter()
    by_pid: Counter[str] = Counter()
    callsite_counts: dict[
        tuple[int, str | None, str | None, str | None, str], dict[str, Any]
    ] = {}
    module_counts: dict[
        tuple[str | None, str | None, str | None], dict[str, Any]
    ] = {}
    total = 0
    matched = 0
    sequence_gaps = 0
    sequence_missing = 0
    previous_seq: int | None = None
    with open_event_stream(events_path) as stream:
        for event in stream:
            total += 1
            if previous_seq is not None:
                delta = (event.seq - previous_seq) & 0xFFFFFFFF
                if delta > 1:
                    sequence_gaps += 1
                    sequence_missing += delta - 1
            previous_seq = event.seq
            if not _matches(
                event,
                syscall_numbers=selected,
                pid=pid,
                tid=tid,
                contains=contains,
                syscall_names=by_number,
            ):
                continue
            callsites = (
                event_callsites(event, module_index)
                if module_index is not None
                and (selected_module_ids or mode in {"stats", "callsites"})
                else []
            )
            if not _module_matches(callsites, selected_module_ids):
                continue
            matched += 1
            if mode == "stats":
                by_syscall[by_number.get(event.nr, f"sys_{event.nr}")] += 1
                by_pid[str(event.tgid)] += 1
                _update_module_counts(module_counts, callsites)
            elif mode == "callsites":
                _update_callsite_counts(
                    callsite_counts,
                    event,
                    callsites,
                    by_number,
                    selected_module_ids,
                )
            elif len(returned) < limit:
                returned.append(event)
        parser_quality = stream.quality()

    filters: dict[str, Any] = {}
    if syscalls:
        filters["syscalls"] = list(syscalls)
    if pid is not None:
        filters["pid"] = pid
    if tid is not None:
        filters["tid"] = tid
    if contains:
        filters["contains"] = contains
    if module_ids:
        filters["module_ids"] = list(module_ids)

    result: dict[str, Any] = {
        "session": str(session_dir),
        "source": str(events_path),
        "mode": mode,
        "filters": filters,
        "limit": limit,
        "counts": {
            "total": total,
            "matched": matched,
        },
        "quality": {
            "sequence": {
                "gaps": sequence_gaps,
                "missing": sequence_missing,
            },
            "parser": parser_quality,
        },
        "address_resolution": {
            "available": module_index is not None,
            "source": str(module_index.source) if module_index else None,
        },
    }
    if mode == "events":
        event_payloads = [
            _event_payload(event, by_number, module_index, detail)
            for event in returned
        ]
        result["detail"] = detail
        result["counts"].update(
            {
                "returned": len(event_payloads),
                "truncated": max(0, matched - len(event_payloads)),
            }
        )
        result["events"] = event_payloads
    elif mode == "stats":
        ranked_modules = sorted(
            module_counts.values(),
            key=lambda item: (
                -item["event_count"],
                item["module_id"] or "",
            ),
        )
        returned_modules = ranked_modules[:limit]
        result["module_counts"] = {
            "unique": len(ranked_modules),
            "returned": len(returned_modules),
            "truncated": max(0, len(ranked_modules) - len(returned_modules)),
        }
        result["stats"] = {
            "by_syscall": dict(sorted(by_syscall.items())),
            "by_pid": dict(sorted(by_pid.items(), key=lambda item: int(item[0]))),
            "by_module": returned_modules,
        }
    else:
        ranked_callsites = _sorted_callsites(callsite_counts)
        returned_callsites = ranked_callsites[:limit]
        result["callsite_counts"] = {
            "unique": len(ranked_callsites),
            "returned": len(returned_callsites),
            "truncated": max(0, len(ranked_callsites) - len(returned_callsites)),
        }
        result["callsites"] = returned_callsites
    return result
