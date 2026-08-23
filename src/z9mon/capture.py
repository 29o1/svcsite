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
from z9mon.maps import capture_maps_snapshot
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
    package: str | None
    duration: float
    syscalls: tuple[str, ...]
    target_mode: str
    output: str
    kpm: str | None = None
    pid: int | None = None


def _module_version(status: dict[str, Any]) -> tuple[int, int]:
    version = str(status.get("version", ""))
    try:
        major, minor, *_ = (int(part) for part in version.split("."))
    except (TypeError, ValueError):
        return 0, 0
    return major, minor


def _require_module_version(status: dict[str, Any]) -> None:
    if _module_version(status) < (1, 5):
        version = str(status.get("version", ""))
        raise Z9MonError(
            "MODULE_VERSION_UNSUPPORTED",
            "loaded KPM is too old for this CLI; converge the module with --kpm",
            EXIT_KPM,
            {"loaded_version": version or None, "required_version": "1.5.0"},
        )


def _select_target(options: CaptureOptions) -> tuple[str, str | int]:
    selectors = [
        (kind, value)
        for kind, value in (
            ("package", options.package),
            ("pid", options.pid),
        )
        if value is not None
    ]
    if len(selectors) != 1:
        raise Z9MonError(
            "TARGET_SELECTION_INVALID",
            "exactly one of package or pid is required",
            EXIT_USAGE,
        )

    kind, value = selectors[0]
    if kind == "package":
        if not isinstance(value, str) or not _PACKAGE_PATTERN.fullmatch(value):
            raise Z9MonError(
                "PACKAGE_INVALID",
                "package name has an invalid format",
                EXIT_USAGE,
                {"package": value},
            )
    elif (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > 2_147_483_647
    ):
        raise Z9MonError(
            "TARGET_SELECTION_INVALID",
            f"{kind} has an invalid value",
            EXIT_USAGE,
            {kind: value},
        )

    if kind == "pid" and options.target_mode != "attach":
        raise Z9MonError(
            "TARGET_MODE_UNSUPPORTED",
            "pid targets support attach mode only",
            EXIT_USAGE,
            {"target": kind, "target_mode": options.target_mode},
        )
    return kind, value


def _resolve_target(
    adb: AdbClient,
    kind: str,
    value: str | int,
) -> dict[str, Any]:
    if kind == "package":
        package = str(value)
        return {
            "kind": kind,
            "package": package,
            "uid": adb.package_uid(package),
        }
    if kind == "pid":
        process = adb.process(int(value))
        return {
            "kind": kind,
            "pid": process.pid,
            "uid": process.uid,
            "name": process.name,
        }
    raise AssertionError(f"unsupported target kind: {kind}")


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
    target_kind, target_value = _select_target(options)
    adb = AdbClient(timeout=options.timeout)
    serial = adb.resolve_serial(options.device)
    require_root(adb)
    key = read_superkey(options.key_file)
    controller = KpmController(adb, key.value)
    controller.locate_kpatch()

    module_deploy: dict[str, Any] | None = None
    if options.kpm:
        module_deploy = controller.ensure_module(options.kpm)
    else:
        controller.require_loaded()

    initial_status = controller.status()
    _require_module_version(initial_status)
    target = _resolve_target(adb, target_kind, target_value)
    uid = int(target["uid"])
    syscall_numbers, syscall_names = _select_syscalls(
        controller,
        options.syscalls,
    )
    target_label = (
        str(target["package"])
        if target_kind == "package"
        else f"{target_kind}-{target_value}"
    )
    session_dir = create_session_directory(options.output, target_label)
    events_path = session_dir / "events.bin"
    manifest_path = session_dir / "manifest.json"
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
        if target_kind == "pid":
            controller.set_pid(int(target["pid"]))
        configured = controller.set_nrs(syscall_numbers)
        if int(configured.get("skipped", 0)) != 0:
            raise Z9MonError(
                "KPM_HOOK_INSTALL_FAILED",
                "KPM could not install every requested syscall hook",
                EXIT_KPM,
                {"response": configured},
            )

        package = target.get("package")
        if options.target_mode == "restart" and isinstance(package, str):
            adb.force_stop(package)

        monitoring_started = True
        controller.start()
        if options.target_mode in {"launch", "restart"} and isinstance(package, str):
            launch_result = adb.launch_package(package)
        elif isinstance(package, str) and not adb.package_pids(package):
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
                only_pids={int(target["pid"])} if target_kind == "pid" else None,
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
                only_pids={int(target["pid"])} if target_kind == "pid" else None,
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
            **target,
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
            "deploy": module_deploy,
            "final_status": final_status,
        },
        "summary": summary,
        "artifacts": {
            "events": {
                "path": str(events_path),
                "size": events_path.stat().st_size,
                "sha256": sha256_file(events_path),
            },
            "maps": {
                "directory": maps_directory,
                "snapshot_count": len(maps_snapshots),
                "mapped_pids": mapped_pids,
            },
        },
        "warnings": warnings,
    }
    write_json(manifest_path, manifest)

    return {
        "session_id": session_dir.name,
        "session": str(session_dir),
        "device": serial,
        "target": target,
        "package": target.get("package"),
        "pid": target.get("pid"),
        "uid": uid,
        "summary": summary,
        "artifacts": {
            "manifest": str(manifest_path),
            "events": str(events_path),
            "maps": maps_directory,
        },
        "warnings": _compact_warnings(warnings),
    }
