from __future__ import annotations

from dataclasses import dataclass
import re
import time
from typing import Any, Sequence

from z9mon.adb import AdbClient
from z9mon.config import read_superkey
from z9mon.constants import (
    EVENT_PATH,
    KNOWN_SYSCALL_NAMES,
    KNOWN_SYSCALLS,
    MODULE_NAME,
    REVERSE_BASIC_SYSCALLS,
    SUPPORTED_SYSCALL_NUMBERS,
)
from z9mon.errors import EXIT_KPM, EXIT_USAGE, Z9MonError
from z9mon.kpm import KpmController, require_root
from z9mon.maps import build_modules_document, capture_maps_snapshot
from z9mon.session import (
    base_manifest,
    create_session_directory,
    sha256_file,
    summarize_event_file,
    utc_now,
    write_json,
)


_PACKAGE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")


@dataclass(frozen=True)
class CaptureOptions:
    device: str | None
    timeout: float
    key_file: str | None
    package: str
    duration: float
    syscalls: tuple[str, ...]
    target_mode: str
    output: str
    load_module: str | None
    kpm: str | None = None


def _module_version(status: dict[str, Any]) -> tuple[int, int]:
    version = str(status.get("version", ""))
    try:
        major, minor, *_ = (int(part) for part in version.split("."))
    except (TypeError, ValueError):
        return 0, 0
    return major, minor


def _module_supports_drain(status: dict[str, Any]) -> None:
    if _module_version(status) < (1, 1):
        version = str(status.get("version", ""))
        raise Z9MonError(
            "MODULE_VERSION_UNSUPPORTED",
            "loaded KPM does not support reliable stop-and-drain capture",
            EXIT_KPM,
            {"loaded_version": version or None, "required_version": "1.1.0"},
        )


def _wait_for_drain(
    controller: KpmController,
    timeout: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_status: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last_status = controller.status()
        if int(last_status.get("events_buffered", 0)) == 0:
            time.sleep(0.25)
            return last_status
        time.sleep(0.1)
    raise Z9MonError(
        "KPM_DRAIN_TIMEOUT",
        "KPM event buffer did not drain before the timeout",
        EXIT_KPM,
        {
            "timeout_seconds": timeout,
            "events_buffered": last_status.get("events_buffered"),
        },
    )


def _select_syscalls(
    controller: KpmController,
    requested: Sequence[str],
) -> tuple[list[int], dict[int, str]]:
    by_name = dict(KNOWN_SYSCALLS)
    by_number = dict(KNOWN_SYSCALL_NAMES)
    raw_values = list(requested)
    if not raw_values:
        raw_values = [name for name, _ in REVERSE_BASIC_SYSCALLS]

    selected: list[int] = []
    unknown: list[str] = []
    unsupported: list[str] = []
    for raw_value in raw_values:
        value = raw_value.strip().removeprefix("sys_")
        if not value:
            continue
        if value.isdecimal():
            number = int(value)
            if not 0 <= number < 460:
                unknown.append(raw_value)
                continue
        elif value in by_name:
            number = by_name[value]
        else:
            resolved = controller.resolve_syscall(value)
            if resolved is None:
                unknown.append(raw_value)
                continue
            number = resolved
            by_name[value] = number
            by_number[number] = value
        if number not in SUPPORTED_SYSCALL_NUMBERS:
            unsupported.append(raw_value)
            continue
        if number not in selected:
            selected.append(number)

    if unknown:
        raise Z9MonError(
            "SYSCALL_UNKNOWN",
            "one or more syscall names are unknown",
            EXIT_USAGE,
            {"values": unknown},
        )
    if unsupported:
        raise Z9MonError(
            "SYSCALL_UNSUPPORTED",
            "requested syscall is not in the KPM's statically typed hook set",
            EXIT_USAGE,
            {"values": unsupported},
        )
    if not selected:
        raise Z9MonError(
            "SYSCALL_SET_EMPTY",
            "at least one syscall is required",
            EXIT_USAGE,
        )
    return selected, by_number


def _shell_value(adb: AdbClient, command: str) -> str:
    result = adb.shell(f"{command}\n")
    return result.stdout.strip() if result.returncode == 0 else ""


def _compact_warnings(
    warnings: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[int]] = {}
    compact: list[dict[str, Any]] = []
    for warning in warnings:
        phase = warning.get("phase")
        code = warning.get("code")
        pid = warning.get("pid")
        if not isinstance(phase, str) or not isinstance(code, str) or not isinstance(
            pid, int
        ):
            compact.append(warning)
            continue
        grouped.setdefault((phase, code), []).append(pid)
    for (phase, code), pids in grouped.items():
        compact.append(
            {
                "code": code,
                "phase": phase,
                "count": len(pids),
                "pids": pids[:5],
                "pids_truncated": len(pids) > 5,
                "evidence_valid": True,
            }
        )
    return compact


def run_capture(options: CaptureOptions) -> dict[str, Any]:
    if not _PACKAGE_PATTERN.fullmatch(options.package):
        raise Z9MonError(
            "PACKAGE_INVALID",
            "package name has an invalid format",
            EXIT_USAGE,
            {"package": options.package},
        )
    adb = AdbClient(timeout=options.timeout)
    serial = adb.resolve_serial(options.device)
    require_root(adb)
    key = read_superkey(options.key_file)
    controller = KpmController(adb, key.value)
    controller.locate_kpatch()

    module_load: dict[str, Any] | None = None
    module_deploy: dict[str, Any] | None = None
    if options.load_module:
        module_load = controller.replace_module(options.load_module)
    elif options.kpm:
        module_deploy = controller.ensure_module(options.kpm)
        if module_deploy["action"] != "current":
            module_load = module_deploy
    else:
        controller.require_loaded()

    initial_status = controller.status()
    _module_supports_drain(initial_status)
    if _module_version(initial_status) < (1, 4):
        controller.configure_legacy_capture()
    uid = adb.package_uid(options.package)
    syscall_numbers, syscall_names = _select_syscalls(
        controller,
        options.syscalls,
    )
    session_dir = create_session_directory(options.output, options.package)
    events_path = session_dir / "events.bin"
    manifest_path = session_dir / "manifest.json"
    summary_path = session_dir / "summary.json"
    modules_path = session_dir / "modules.json"
    maps_dir = session_dir / "maps"
    warnings: list[dict[str, Any]] = []
    maps_snapshots: list[dict[str, Any]] = []
    launch_result: dict[str, str] | None = None
    started_at = utc_now()
    monotonic_start = time.monotonic()
    monitoring_started = False
    final_status = initial_status

    try:
        controller.stop()
        _wait_for_drain(controller, options.timeout)
        adb.truncate_root_file(EVENT_PATH)
        controller.clear()
        controller.set_uid(uid)
        configured = controller.set_nrs(syscall_numbers)
        if int(configured.get("skipped", 0)) != 0:
            raise Z9MonError(
                "KPM_HOOK_INSTALL_FAILED",
                "KPM could not install every requested syscall hook",
                EXIT_KPM,
                {"response": configured},
            )

        if options.target_mode == "restart":
            adb.force_stop(options.package)

        controller.start()
        monitoring_started = True
        if options.target_mode in {"launch", "restart"}:
            launch_result = adb.launch_package(options.package)
        elif not adb.package_pids(options.package):
            warnings.append(
                {
                    "code": "TARGET_NOT_RUNNING",
                    "phase": "capture-start",
                    "evidence_valid": True,
                }
            )

        maps_snapshots.append(
            capture_maps_snapshot(
                adb,
                uid=uid,
                maps_dir=maps_dir,
                snapshot_id="post-launch",
                warnings=warnings,
                wait_seconds=1.5
                if options.target_mode in {"launch", "restart"}
                else 0.0,
            )
        )

        try:
            time.sleep(options.duration)
        except KeyboardInterrupt:
            warnings.append(
                {
                    "code": "CAPTURE_INTERRUPTED",
                    "phase": "capture",
                    "evidence_valid": True,
                }
            )
        maps_snapshots.append(
            capture_maps_snapshot(
                adb,
                uid=uid,
                maps_dir=maps_dir,
                snapshot_id="pre-stop",
                warnings=warnings,
            )
        )
    finally:
        if monitoring_started:
            controller.stop()
            final_status = _wait_for_drain(controller, options.timeout)

    adb.make_root_file_readable(EVENT_PATH)
    adb.pull(EVENT_PATH, events_path)
    summary, observed_pids = summarize_event_file(
        events_path,
        syscall_names,
        kernel_dropped=int(final_status.get("events_dropped", 0)),
    )
    write_json(summary_path, summary)

    ended_at = utc_now()
    target_pids = sorted(observed_pids)
    mapped_pids = {
        process["pid"]
        for snapshot in maps_snapshots
        for process in snapshot.get("processes", [])
        if isinstance(process, dict) and isinstance(process.get("pid"), int)
    }
    missing_pids = set(target_pids) - mapped_pids
    if missing_pids:
        maps_snapshots.append(
            capture_maps_snapshot(
                adb,
                uid=uid,
                maps_dir=maps_dir,
                snapshot_id="recovery",
                warnings=warnings,
                only_pids=missing_pids,
            )
        )
    modules_document = build_modules_document(session_dir.name, maps_snapshots)
    modules_written = True
    try:
        write_json(modules_path, modules_document)
    except OSError:
        modules_written = False
        warnings.append(
            {
                "code": "MODULES_WRITE_FAILED",
                "phase": "modules",
                "evidence_valid": True,
            }
        )
    mapped_pids = sorted(
        {
            process["pid"]
            for snapshot in maps_snapshots
            for process in snapshot.get("processes", [])
            if isinstance(process, dict) and isinstance(process.get("pid"), int)
        }
    )
    maps_directory = str(maps_dir.resolve()) if maps_dir.is_dir() else None
    selected_syscalls = [
        {"nr": number, "name": syscall_names.get(number, f"sys_{number}")}
        for number in syscall_numbers
    ]
    manifest = {
        **base_manifest(),
        "session_id": session_dir.name,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": round(time.monotonic() - monotonic_start, 3),
        "device": {
            "serial": serial,
            "model": _shell_value(adb, "getprop ro.product.model"),
            "android_version": _shell_value(adb, "getprop ro.build.version.release"),
            "abi": _shell_value(adb, "getprop ro.product.cpu.abi"),
            "kernel_release": _shell_value(adb, "uname -r"),
        },
        "target": {
            "package": options.package,
            "uid": uid,
            "observed_pids": target_pids,
            "mapped_pids": mapped_pids,
        },
        "capture": {
            "selection": "custom" if options.syscalls else "reverse-basic",
            "syscalls": selected_syscalls,
            "target_mode": options.target_mode,
            "launch_result": launch_result,
        },
        "module": {
            "name": MODULE_NAME,
            "version": final_status.get("version"),
            "load": module_load,
            "deploy": module_deploy,
            "final_status": final_status,
        },
        "artifacts": {
            "events": {
                "path": str(events_path),
                "size": events_path.stat().st_size,
                "sha256": sha256_file(events_path),
            },
            "summary": {"path": str(summary_path)},
            "modules": {
                "path": str(modules_path) if modules_written else None,
                "snapshot_count": len(maps_snapshots),
                "mapped_pids": mapped_pids,
            },
            "maps": {"directory": maps_directory},
        },
        "warnings": warnings,
    }
    write_json(manifest_path, manifest)

    return {
        "session_id": session_dir.name,
        "session": str(session_dir),
        "device": serial,
        "package": options.package,
        "uid": uid,
        "summary": summary,
        "artifacts": {
            "manifest": str(manifest_path),
            "events": str(events_path),
            "summary": str(summary_path),
            "modules": str(modules_path) if modules_written else None,
            "maps": maps_directory,
        },
        "warnings": _compact_warnings(warnings),
    }
