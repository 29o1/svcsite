from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from svcsite.adb import AdbClient, ProcessInfo
from svcsite.constants import LEGACY_MODULES_SCHEMA, MODULES_SCHEMA
from svcsite.hexutil import hex_str
from svcsite.errors import EXIT_DATA, SvcSiteError


def _module_name(path: str) -> str | None:
    normalized = path.removesuffix(" (deleted)")
    if not normalized:
        return None
    if normalized.startswith("["):
        return normalized
    return PurePosixPath(normalized).name or normalized


def _module_id(
    path: str | None,
    device: str | None,
    inode: int | None,
) -> str | None:
    if not path:
        return None
    normalized = path.removesuffix(" (deleted)")
    if normalized.startswith("["):
        return f"special:{normalized}"
    if device and inode is not None:
        return f"file:{device}:{inode}:{normalized}"
    return f"file:{normalized}"


@dataclass(frozen=True)
class _IndexedMapping:
    start: int
    end: int
    file_offset: int
    mapping: dict[str, Any]


@dataclass(frozen=True)
class _ProcessSnapshot:
    snapshot_id: Any
    starts: tuple[int, ...]
    mappings: tuple[_IndexedMapping, ...]


def parse_proc_maps(raw: str) -> tuple[dict[str, Any], ...]:
    mappings: list[dict[str, Any]] = []
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
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
            continue
        if end <= start:
            continue
        mappings.append(
            {
                "start": hex_str(start),
                "end": hex_str(end),
                "size": hex_str(end - start),
                "permissions": permissions,
                "file_offset": hex_str(offset),
                "device": device,
                "inode": inode,
                "path": path or None,
                "module": _module_name(path),
                "module_id": _module_id(path, device, inode),
            }
        )
    return tuple(mappings)


def capture_maps_snapshot(
    adb: AdbClient,
    *,
    uid: int,
    maps_dir: Path,
    snapshot_id: str,
    warnings: list[dict[str, Any]],
    only_pids: Iterable[int] | None = None,
    wait_seconds: float = 0.0,
) -> set[int]:
    import time

    wanted = set(only_pids) if only_pids is not None else None
    deadline = time.monotonic() + wait_seconds
    processes: list[ProcessInfo] = []
    process_lookup_failed = False
    while True:
        try:
            processes = adb.processes_for_uid(uid)
        except SvcSiteError as exc:
            warnings.append(
                {
                    "code": exc.code,
                    "phase": snapshot_id,
                    "evidence_valid": True,
                }
            )
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
        warnings.append(
            {
                "code": "MAPS_DIRECTORY_FAILED",
                "phase": snapshot_id,
                "evidence_valid": True,
            }
        )
        return set()
    captured_pids: set[int] = set()
    for process in processes:
        try:
            raw = adb.read_process_maps(process.pid)
            raw_path = (maps_dir / f"{snapshot_id}-{process.pid}.maps").resolve()
            raw_path.write_text(raw, encoding="utf-8")
        except SvcSiteError as exc:
            warnings.append(
                {
                    "code": exc.code,
                    "phase": snapshot_id,
                    "pid": process.pid,
                    "evidence_valid": True,
                }
            )
            continue
        except OSError:
            warnings.append(
                {
                    "code": "MAPS_WRITE_FAILED",
                    "phase": snapshot_id,
                    "pid": process.pid,
                    "evidence_valid": True,
                }
            )
            continue
        captured_pids.add(process.pid)

    if wanted is not None and not process_lookup_failed:
        for pid in sorted(wanted - captured_pids):
            warnings.append(
                {
                    "code": "MAPS_UNAVAILABLE",
                    "phase": snapshot_id,
                    "pid": pid,
                    "evidence_valid": True,
                }
            )
    elif wanted is None and not processes and not process_lookup_failed:
        warnings.append(
            {
                "code": "PROCESS_NOT_FOUND",
                "phase": snapshot_id,
                "uid": uid,
                "evidence_valid": True,
            }
        )

    return captured_pids


class ModuleIndex:
    def __init__(self, source: Path, document: dict[str, Any]) -> None:
        self.source = source
        snapshots = document.get("snapshots")
        if document.get("schema_version") not in {
            MODULES_SCHEMA,
            LEGACY_MODULES_SCHEMA,
        } or not isinstance(snapshots, list):
            raise SvcSiteError(
                "MODULES_INVALID",
                "modules.json has an unsupported structure",
                EXIT_DATA,
                {"path": str(source)},
            )
        self._by_pid = self._build_index(snapshots)
        self._resolve_cached = lru_cache(maxsize=32768)(
            self._resolve_uncached
        )

    @staticmethod
    def _build_index(
        snapshots: list[Any],
    ) -> dict[int, tuple[_ProcessSnapshot, ...]]:
        by_pid: dict[int, list[_ProcessSnapshot]] = {}
        for snapshot in reversed(snapshots):
            if not isinstance(snapshot, dict):
                continue
            processes = snapshot.get("processes")
            if not isinstance(processes, list):
                continue
            for process in processes:
                if not isinstance(process, dict) or not isinstance(
                    process.get("pid"), int
                ):
                    continue
                indexed: list[_IndexedMapping] = []
                mappings = process.get("mappings")
                if not isinstance(mappings, list):
                    continue
                for mapping in mappings:
                    if not isinstance(mapping, dict):
                        continue
                    try:
                        start = int(str(mapping["start"]), 0)
                        end = int(str(mapping["end"]), 0)
                        file_offset = int(str(mapping["file_offset"]), 0)
                    except (KeyError, TypeError, ValueError):
                        continue
                    if end <= start:
                        continue
                    indexed.append(
                        _IndexedMapping(start, end, file_offset, mapping)
                    )
                indexed.sort(key=lambda item: item.start)
                if not indexed:
                    continue
                pid = process["pid"]
                by_pid.setdefault(pid, []).append(
                    _ProcessSnapshot(
                        snapshot.get("snapshot_id"),
                        tuple(item.start for item in indexed),
                        tuple(indexed),
                    )
                )
        return {pid: tuple(items) for pid, items in by_pid.items()}

    @classmethod
    def from_session(cls, session_dir: Path) -> ModuleIndex | None:
        source = session_dir / "modules.json"
        if not source.is_file():
            return cls.from_maps_dir(session_dir)
        try:
            document = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SvcSiteError(
                "MODULES_INVALID",
                "modules.json could not be read",
                EXIT_DATA,
                {"path": str(source), "reason": str(exc)},
            ) from exc
        if not isinstance(document, dict):
            raise SvcSiteError(
                "MODULES_INVALID",
                "modules.json must contain a JSON object",
                EXIT_DATA,
                {"path": str(source)},
            )
        return cls(source, document)

    @classmethod
    def from_maps_dir(cls, session_dir: Path) -> ModuleIndex | None:
        """Build an index from raw maps/ snapshots ({snapshot}-{pid}.maps).

        Filenames sort alphabetically into capture order (post-launch,
        pre-stop, recovery), matching the legacy modules.json layout.
        """

        maps_dir = session_dir / "maps"
        if not maps_dir.is_dir():
            return None
        snapshots: list[dict[str, Any]] = []
        snapshots_by_id: dict[str, dict[str, Any]] = {}
        for raw_path in sorted(maps_dir.glob("*.maps")):
            stem = raw_path.name.removesuffix(".maps")
            snapshot_id, _, pid_text = stem.rpartition("-")
            if not snapshot_id or not pid_text.isdigit():
                continue
            try:
                raw = raw_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise SvcSiteError(
                    "MODULES_INVALID",
                    "maps snapshot could not be read",
                    EXIT_DATA,
                    {"path": str(raw_path), "reason": str(exc)},
                ) from exc
            snapshot = snapshots_by_id.get(snapshot_id)
            if snapshot is None:
                snapshot = {
                    "snapshot_id": snapshot_id,
                    "processes": [],
                }
                snapshots_by_id[snapshot_id] = snapshot
                snapshots.append(snapshot)
            snapshot["processes"].append(
                {
                    "pid": int(pid_text),
                    "mappings": list(parse_proc_maps(raw)),
                }
            )
        if not snapshots:
            return None
        return cls(
            maps_dir,
            {
                "schema_version": MODULES_SCHEMA,
                "session_id": session_dir.name,
                "snapshots": snapshots,
            },
        )

    def resolve(self, pid: int, address: int) -> dict[str, Any] | None:
        return self._resolve_cached(pid, address)

    def _resolve_uncached(
        self,
        pid: int,
        address: int,
    ) -> dict[str, Any] | None:
        if address <= 0:
            return None
        for snapshot in self._by_pid.get(pid, ()):
            index = bisect_right(snapshot.starts, address) - 1
            if index < 0:
                continue
            mapping = snapshot.mappings[index]
            if address >= mapping.end:
                continue
            resolved = self._resolved_payload(mapping, address)
            return {
                "runtime": hex_str(address),
                "snapshot_id": snapshot.snapshot_id,
                **resolved,
            }
        return None

    @staticmethod
    def _resolved_payload(
        indexed: _IndexedMapping,
        address: int,
    ) -> dict[str, Any]:
        start = indexed.start
        file_offset = indexed.file_offset
        mapping = indexed.mapping
        module_base = start - file_offset
        if module_base < 0:
            module_base = start
        path = mapping.get("path")
        module_id = mapping.get("module_id")
        if not isinstance(module_id, str):
            module_id = _module_id(
                path if isinstance(path, str) else None,
                mapping.get("device")
                if isinstance(mapping.get("device"), str)
                else None,
                mapping.get("inode")
                if isinstance(mapping.get("inode"), int)
                else None,
            )
        return {
            "module": mapping.get("module"),
            "module_id": module_id,
            "path": path,
            "module_offset": hex_str(address - module_base),
        }
