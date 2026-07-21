from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from z9mon.adb import AdbClient, ProcessInfo
from z9mon.constants import MODULES_SCHEMA
from z9mon.errors import EXIT_DATA, Z9MonError
from z9mon.session import utc_now


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _module_name(path: str) -> str | None:
    normalized = path.removesuffix(" (deleted)")
    if not normalized:
        return None
    if normalized.startswith("["):
        return normalized
    return PurePosixPath(normalized).name or normalized


@dataclass(frozen=True)
class ParsedMaps:
    mappings: tuple[dict[str, Any], ...]
    invalid_lines: int


def parse_proc_maps(raw: str) -> ParsedMaps:
    mappings: list[dict[str, Any]] = []
    invalid_lines = 0
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            invalid_lines += 1
            continue
        region, permissions, file_offset, device, inode_text = fields[:5]
        path = fields[5] if len(fields) == 6 else ""
        try:
            start_text, end_text = region.split("-", 1)
            start = int(start_text, 16)
            end = int(end_text, 16)
            offset = int(file_offset, 16)
            inode = int(inode_text)
        except (ValueError, TypeError):
            invalid_lines += 1
            continue
        if end <= start:
            invalid_lines += 1
            continue
        mappings.append(
            {
                "start": _hex(start),
                "end": _hex(end),
                "size": _hex(end - start),
                "permissions": permissions,
                "file_offset": _hex(offset),
                "device": device,
                "inode": inode,
                "path": path or None,
                "module": _module_name(path),
            }
        )
    return ParsedMaps(tuple(mappings), invalid_lines)


def capture_maps_snapshot(
    adb: AdbClient,
    *,
    uid: int,
    maps_dir: Path,
    snapshot_id: str,
    warnings: list[str],
    only_pids: Iterable[int] | None = None,
    wait_seconds: float = 0.0,
) -> dict[str, Any]:
    import time

    wanted = set(only_pids) if only_pids is not None else None
    deadline = time.monotonic() + wait_seconds
    processes: list[ProcessInfo] = []
    process_lookup_failed = False
    while True:
        try:
            processes = adb.processes_for_uid(uid)
        except Z9MonError as exc:
            warnings.append(f"{snapshot_id}: {exc.code}")
            process_lookup_failed = True
            break
        if wanted is not None:
            processes = [process for process in processes if process.pid in wanted]
        if processes or time.monotonic() >= deadline:
            break
        time.sleep(0.2)

    try:
        maps_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        warnings.append(f"{snapshot_id}: MAPS_DIRECTORY_FAILED")
        return {
            "snapshot_id": snapshot_id,
            "captured_at": utc_now(),
            "processes": [],
        }
    captured_at = utc_now()
    captured_processes: list[dict[str, Any]] = []
    for process in processes:
        try:
            raw = adb.read_process_maps(process.pid)
            raw_path = (maps_dir / f"{snapshot_id}-{process.pid}.maps").resolve()
            raw_path.write_text(raw, encoding="utf-8")
        except Z9MonError as exc:
            warnings.append(f"{snapshot_id}: pid {process.pid}: {exc.code}")
            continue
        except OSError:
            warnings.append(f"{snapshot_id}: pid {process.pid}: MAPS_WRITE_FAILED")
            continue
        parsed = parse_proc_maps(raw)
        captured_processes.append(
            {
                "pid": process.pid,
                "uid": process.uid,
                "name": process.name,
                "maps_path": str(raw_path),
                "mapping_count": len(parsed.mappings),
                "invalid_lines": parsed.invalid_lines,
                "mappings": list(parsed.mappings),
            }
        )

    found = {process["pid"] for process in captured_processes}
    if wanted is not None and not process_lookup_failed:
        for pid in sorted(wanted - found):
            warnings.append(f"{snapshot_id}: pid {pid}: MAPS_UNAVAILABLE")
    elif wanted is None and not processes and not process_lookup_failed:
        warnings.append(f"{snapshot_id}: no process found for uid {uid}")

    return {
        "snapshot_id": snapshot_id,
        "captured_at": captured_at,
        "processes": captured_processes,
    }


def build_modules_document(
    session_id: str,
    snapshots: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": MODULES_SCHEMA,
        "session_id": session_id,
        "snapshots": list(snapshots),
    }


class ModuleIndex:
    def __init__(self, source: Path, document: dict[str, Any]) -> None:
        self.source = source
        snapshots = document.get("snapshots")
        if document.get("schema_version") != MODULES_SCHEMA or not isinstance(
            snapshots, list
        ):
            raise Z9MonError(
                "MODULES_INVALID",
                "modules.json has an unsupported structure",
                EXIT_DATA,
                {"path": str(source)},
            )
        self.snapshots = snapshots

    @classmethod
    def from_session(cls, session_dir: Path) -> ModuleIndex | None:
        source = session_dir / "modules.json"
        if not source.is_file():
            return None
        try:
            document = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise Z9MonError(
                "MODULES_INVALID",
                "modules.json could not be read",
                EXIT_DATA,
                {"path": str(source), "reason": str(exc)},
            ) from exc
        if not isinstance(document, dict):
            raise Z9MonError(
                "MODULES_INVALID",
                "modules.json must contain a JSON object",
                EXIT_DATA,
                {"path": str(source)},
            )
        return cls(source, document)

    def resolve(self, pid: int, address: int) -> dict[str, Any] | None:
        if address <= 0:
            return None
        for snapshot in reversed(self.snapshots):
            if not isinstance(snapshot, dict):
                continue
            processes = snapshot.get("processes")
            if not isinstance(processes, list):
                continue
            for process in processes:
                if not isinstance(process, dict) or process.get("pid") != pid:
                    continue
                mappings = process.get("mappings")
                if not isinstance(mappings, list):
                    continue
                for mapping in mappings:
                    resolved = self._resolve_mapping(mapping, address)
                    if resolved is not None:
                        return {
                            "runtime": _hex(address),
                            "pid": pid,
                            "snapshot_id": snapshot.get("snapshot_id"),
                            "captured_at": snapshot.get("captured_at"),
                            **resolved,
                        }
        return None

    @staticmethod
    def _resolve_mapping(
        mapping: Any,
        address: int,
    ) -> dict[str, Any] | None:
        if not isinstance(mapping, dict):
            return None
        try:
            start = int(str(mapping["start"]), 0)
            end = int(str(mapping["end"]), 0)
            file_offset = int(str(mapping["file_offset"]), 0)
        except (KeyError, TypeError, ValueError):
            return None
        if not start <= address < end:
            return None
        module_base = start - file_offset
        if module_base < 0:
            module_base = start
        return {
            "module": mapping.get("module"),
            "path": mapping.get("path"),
            "module_base": _hex(module_base),
            "module_offset": _hex(address - module_base),
            "mapping_start": _hex(start),
            "mapping_end": _hex(end),
            "file_offset": _hex(file_offset),
            "permissions": mapping.get("permissions"),
        }


def require_module_index(session_dir: Path) -> ModuleIndex:
    index = ModuleIndex.from_session(session_dir)
    if index is None:
        raise Z9MonError(
            "MODULES_NOT_FOUND",
            "session does not contain modules.json",
            EXIT_DATA,
            {"session": str(session_dir)},
        )
    return index


def run_address_resolve(
    *,
    session: str,
    pid: int,
    address: int,
) -> dict[str, Any]:
    from z9mon.session import resolve_session

    session_dir, _, _ = resolve_session(session)
    index = require_module_index(session_dir)
    resolved = index.resolve(pid, address)
    return {
        "session": str(session_dir),
        "source": str(index.source),
        "pid": pid,
        "address": _hex(address),
        "resolved": resolved is not None,
        "mapping": resolved,
    }
