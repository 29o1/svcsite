from __future__ import annotations

from typing import Any, Sequence

from svcsite.constants import KNOWN_SYSCALL_NAMES, KNOWN_SYSCALLS
from svcsite.hexutil import hex_str
from svcsite.fds import FdTracker
from svcsite.errors import EXIT_DATA, EXIT_USAGE, SvcSiteError
from svcsite.maps import ModuleIndex
from svcsite.protocol import Event, open_event_stream
from svcsite.session import resolve_session


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
        raise SvcSiteError(
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
    fd_provenance: dict[str, Any] | None = None,
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
                str((fd_provenance or {}).get("resource") or ""),
            )
        ).casefold()
        if needle not in haystack:
            return False
    return True


def _return_callsites(
    event: Event,
) -> tuple[int | None, tuple[int | None, ...]]:
    caller = event.caller - 4 if event.caller >= 4 else None
    backtrace = tuple(
        None if address == event.pc or address < 4 else address - 4
        for address in event.backtrace
    )
    return caller, backtrace


def _event_payload(
    event: Event,
    syscall_names: dict[int, str],
    module_index: ModuleIndex | None,
) -> dict[str, Any]:
    payload = event.to_dict(syscall_names)
    caller_callsite, backtrace_callsites = _return_callsites(event)
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
    registers["pc_resolved"] = module_index.resolve(event.tgid, event.pc)
    registers["caller_callsite_resolved"] = (
        module_index.resolve(event.tgid, caller_callsite)
        if caller_callsite is not None
        else None
    )
    registers["clone_fn_resolved"] = module_index.resolve(
        event.tgid, event.clone_fn
    )
    payload["backtrace_callsites_resolved"] = [
        module_index.resolve(event.tgid, address)
        if address is not None
        else None
        for address in backtrace_callsites
    ]
    return payload


def event_callsites(
    event: Event,
    module_index: ModuleIndex,
) -> list[dict[str, Any]]:
    caller_callsite, backtrace_callsites = _return_callsites(event)
    candidates: list[tuple[str, int | None, int]] = [("pc", None, event.pc)]
    if caller_callsite is not None:
        candidates.append(("caller", None, caller_callsite))
    candidates.extend(
        ("backtrace", depth, address)
        for depth, address in enumerate(backtrace_callsites)
        if address is not None
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


def run_query(
    *,
    session: str,
    syscalls: Sequence[str],
    pid: int | None,
    tid: int | None,
    contains: str | None,
    limit: int,
    module_ids: Sequence[str] = (),
) -> dict[str, Any]:
    session_dir, events_path, manifest = resolve_session(session)
    module_index = ModuleIndex.from_session(session_dir)
    by_name, by_number = _syscall_maps(manifest)
    selected = _resolve_syscall_filter(syscalls, by_name)
    selected_module_ids = {value for value in module_ids if value}
    if selected_module_ids and module_index is None:
        raise SvcSiteError(
            "MODULES_NOT_FOUND",
            "module filtering requires mapping data",
            EXIT_DATA,
            {"session": str(session_dir)},
        )

    returned: list[Event] = []
    fd_evidence: list[dict[str, Any] | None] = []
    configured = manifest.get("capture", {}).get("syscalls", [])
    if not isinstance(configured, list):
        configured = []
    lifecycle_captured = any(isinstance(item, dict) and item.get("nr") == 57 for item in configured)
    tracker = FdTracker(lifecycle_captured=lifecycle_captured)
    parser_errors = (0, 0)
    callsite_counts: dict[
        tuple[int, str | None, str | None, str | None, str], dict[str, Any]
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
                if delta != 1:
                    tracker.clear()
                if delta > 1:
                    sequence_gaps += 1
                    sequence_missing += delta - 1
            previous_seq = event.seq
            current_errors = (stream.skipped_bytes, stream.invalid_records)
            if current_errors != parser_errors:
                tracker.clear()
            parser_errors = current_errors
            provenance = tracker.observe(event)
            if not _matches(
                event,
                syscall_numbers=selected,
                pid=pid,
                tid=tid,
                contains=contains,
                syscall_names=by_number,
                fd_provenance=provenance,
            ):
                continue
            callsites = (
                event_callsites(event, module_index)
                if module_index is not None
                else []
            )
            if not _module_matches(callsites, selected_module_ids):
                continue
            matched += 1
            _update_callsite_counts(
                callsite_counts,
                event,
                callsites,
                by_number,
                selected_module_ids,
            )
            if len(returned) < limit:
                returned.append(event)
                fd_evidence.append(provenance)
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

    event_payloads = [
        _event_payload(event, by_number, module_index) for event in returned
    ]
    for payload, provenance in zip(event_payloads, fd_evidence):
        payload["fd_provenance"] = provenance
    ranked_callsites = _sorted_callsites(callsite_counts)
    returned_callsites = ranked_callsites[:limit]
    summary = manifest.get("summary")
    kernel_dropped = (
        summary.get("kernel_dropped") if isinstance(summary, dict) else None
    )
    return {
        "session": str(session_dir),
        "source": str(events_path),
        "filters": filters,
        "limit": limit,
        "counts": {
            "total": total,
            "matched": matched,
            "events_returned": len(event_payloads),
            "events_truncated": max(0, matched - len(event_payloads)),
            "callsites_unique": len(ranked_callsites),
            "callsites_returned": len(returned_callsites),
            "callsites_truncated": max(
                0, len(ranked_callsites) - len(returned_callsites)
            ),
        },
        "quality": {
            "kernel_dropped": kernel_dropped,
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
        "events": event_payloads,
        "callsites": returned_callsites,
    }
