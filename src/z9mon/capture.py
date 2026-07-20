from __future__ import annotations

from dataclasses import dataclass
import re
import time
from pathlib import Path
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
from z9mon.protocol import parse_events
from z9mon.session import (
    base_manifest,
    build_summary,
    create_session_directory,
    sha256_file,
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
    preset: str
    syscalls: tuple[str, ...]
    launch: bool
    restart: bool
    output: str
    load_module: str | None


def _module_supports_drain(status: dict[str, Any]) -> None:
    version = str(status.get("version", ""))
    try:
        major, minor, *_ = (int(part) for part in version.split("."))
    except (TypeError, ValueError):
        major, minor = 0, 0
    if (major, minor) < (1, 1):
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


def _syscall_table() -> tuple[dict[str, int], dict[int, str]]:
    by_name = dict(KNOWN_SYSCALLS)
    by_number = dict(KNOWN_SYSCALL_NAMES)
    return by_name, by_number


def _select_syscalls(
    controller: KpmController,
    preset: str,
    requested: Sequence[str],
) -> tuple[list[int], dict[int, str]]:
    by_name, by_number = _syscall_table()
    raw_values = list(requested)
    if not raw_values:
        if preset != "reverse-basic":
            raise Z9MonError(
                "PRESET_UNKNOWN",
                "unknown capture preset",
                EXIT_USAGE,
                {"preset": preset, "available": ["reverse-basic"]},
            )
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

    module_load: dict[str, str] | None = None
    if options.load_module:
        module_load = controller.replace_module(options.load_module)
    else:
        controller.require_loaded()

    initial_status = controller.status()
    _module_supports_drain(initial_status)
    uid = adb.package_uid(options.package)
    syscall_numbers, syscall_names = _select_syscalls(
        controller,
        options.preset,
        options.syscalls,
    )
    session_dir = create_session_directory(options.output, options.package)
    events_path = session_dir / "events.bin"
    manifest_path = session_dir / "manifest.json"
    summary_path = session_dir / "summary.json"
    warnings: list[str] = []
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
        controller.writer_binary()
        controller.disable_filp_open()
        controller.set_uid(uid)
        configured = controller.set_nrs(syscall_numbers)
        if int(configured.get("skipped", 0)) != 0:
            raise Z9MonError(
                "KPM_HOOK_INSTALL_FAILED",
                "KPM could not install every requested syscall hook",
                EXIT_KPM,
                {"response": configured},
            )

        controller.start()
        monitoring_started = True
        if options.restart:
            adb.force_stop(options.package)
        if options.launch or options.restart:
            launch_result = adb.launch_package(options.package)
        elif not adb.package_pids(options.package):
            warnings.append("target package was not running when capture started")

        try:
            time.sleep(options.duration)
        except KeyboardInterrupt:
            warnings.append("capture was stopped by an interrupt")
    finally:
        if monitoring_started:
            controller.stop()
            final_status = _wait_for_drain(controller, options.timeout)

    adb.make_root_file_readable(EVENT_PATH)
    adb.pull(EVENT_PATH, events_path)
    raw_events = events_path.read_bytes()
    parsed = parse_events(raw_events)
    summary = build_summary(
        parsed,
        syscall_names,
        kernel_dropped=int(final_status.get("events_dropped", 0)),
    )
    write_json(summary_path, summary)

    ended_at = utc_now()
    target_pids = sorted({event.tgid for event in parsed.events})
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
        },
        "capture": {
            "preset": options.preset if not options.syscalls else None,
            "syscalls": selected_syscalls,
            "launch": options.launch,
            "restart": options.restart,
            "launch_result": launch_result,
        },
        "module": {
            "name": MODULE_NAME,
            "version": final_status.get("version"),
            "load": module_load,
            "final_status": final_status,
        },
        "artifacts": {
            "events": {
                "path": str(events_path),
                "size": len(raw_events),
                "sha256": sha256_file(events_path),
            },
            "summary": {"path": str(summary_path)},
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
        },
        "warnings": warnings,
    }
