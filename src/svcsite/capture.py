from __future__ import annotations

# Recovery boundaries retain errors until cleanup and artifact saving finish.
# ruff: noqa: BLE001

from dataclasses import dataclass
import re
import time
from typing import Any, Sequence

from svcsite.adb import AdbClient
from svcsite.config import read_superkey
from svcsite.constants import (
    EVENT_PATH,
    KNOWN_SYSCALL_NAMES,
    KNOWN_SYSCALLS,
    MODULE_NAME,
    REVERSE_BASIC_SYSCALLS,
    SESSION_SCHEMA,
    SUPPORTED_SYSCALL_NUMBERS,
)
from svcsite.errors import EXIT_DATA, EXIT_INTERNAL, EXIT_KPM, EXIT_USAGE, SvcSiteError
from svcsite.kpm import KpmController, require_root
from svcsite.maps import capture_maps_snapshot
from svcsite.session import (
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
    if _module_version(status) < (1, 8):
        version = str(status.get("version", ""))
        raise SvcSiteError(
            "MODULE_VERSION_UNSUPPORTED",
            "loaded KPM is too old for this CLI; converge the module with --kpm",
            EXIT_KPM,
            {"loaded_version": version or None, "required_version": "1.8.0"},
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
        raise SvcSiteError(
            "TARGET_SELECTION_INVALID",
            "exactly one of package or pid is required",
            EXIT_USAGE,
        )

    kind, value = selectors[0]
    if kind == "package":
        if not isinstance(value, str) or not _PACKAGE_PATTERN.fullmatch(value):
            raise SvcSiteError(
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
        raise SvcSiteError(
            "TARGET_SELECTION_INVALID",
            f"{kind} has an invalid value",
            EXIT_USAGE,
            {kind: value},
        )

    if kind == "pid" and options.target_mode != "attach":
        raise SvcSiteError(
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
        buffered = last_status.get("events_buffered")
        if (
            type(last_status.get("enabled")) is not bool
            or type(buffered) is not int
            or buffered < 0
        ):
            raise SvcSiteError(
                "KPM_STATUS_INVALID",
                "KPM status must report enabled and a non-negative events_buffered",
                EXIT_KPM,
                {"status": last_status},
            )
        if last_status["enabled"]:
            raise SvcSiteError(
                "KPM_MONITORING_ENABLED",
                "KPM monitoring remained enabled after stop",
                EXIT_KPM,
                {"status": last_status},
            )
        if buffered == 0:
            time.sleep(0.25)
            return last_status
        time.sleep(0.1)
    raise SvcSiteError(
        "KPM_DRAIN_TIMEOUT",
        "KPM event buffer did not drain before the timeout",
        EXIT_KPM,
        {
            "timeout_seconds": timeout,
            "events_buffered": last_status.get("events_buffered"),
            "status": last_status,
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
        raise SvcSiteError(
            "SYSCALL_UNKNOWN",
            "one or more syscall names are unknown",
            EXIT_USAGE,
            {"values": unknown},
        )
    if unsupported:
        raise SvcSiteError(
            "SYSCALL_UNSUPPORTED",
            "requested syscall is not in the KPM's statically typed hook set",
            EXIT_USAGE,
            {"values": unsupported},
        )
    if not selected:
        raise SvcSiteError(
            "SYSCALL_SET_EMPTY",
            "at least one syscall is required",
            EXIT_USAGE,
        )
    return selected, by_number


def _shell_value(
    adb: AdbClient,
    command: str,
    field: str,
    warnings: list[dict[str, Any]],
) -> str:
    try:
        result = adb.shell(f"{command}\n")
        if result.returncode == 0:
            return result.stdout.strip()
        code = "DEVICE_METADATA_FAILED"
    except SvcSiteError as exc:
        code = exc.code
    warnings.append(
        {
            "code": code,
            "phase": "device-metadata",
            "field": field,
            "evidence_valid": True,
        }
    )
    return ""


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
    mapped_pid_set: set[int] = set()
    maps_snapshot_count = 0
    launch_result: dict[str, str] | None = None
    started_at = utc_now()
    monotonic_start = time.monotonic()
    monitoring_started = False
    final_status: dict[str, Any] | None = None
    events_reset = False
    summary: dict[str, Any] = {}
    observed_pids: set[int] = set()
    events_artifact: dict[str, Any] | None = None
    failures: list[dict[str, str]] = []
    error: SvcSiteError | None = None

    def record_failure(exc: Exception | KeyboardInterrupt, phase: str) -> None:
        nonlocal error
        if isinstance(exc, SvcSiteError):
            failure = exc
        elif isinstance(exc, KeyboardInterrupt):
            failure = SvcSiteError("INTERRUPTED", "capture was interrupted", 130)
        elif isinstance(exc, OSError):
            failure = SvcSiteError(
                "CAPTURE_IO_FAILED", "capture artifact I/O failed", EXIT_DATA
            )
        else:
            failure = SvcSiteError(
                "INTERNAL_ERROR",
                "unexpected capture error",
                EXIT_INTERNAL,
                {"exception": type(exc).__name__},
            )
        if error is None:
            error = failure
        # Persist codes and phases, never arbitrary exception text or device output.
        failures.append({"code": failure.code, "phase": phase})

    phase = "initial-stop"
    try:
        controller.stop()
        phase = "initial-drain"
        final_status = _wait_for_drain(controller, options.timeout)
        phase = "reset-events"
        adb.truncate_root_file(EVENT_PATH)
        events_reset = True
        phase = "configure"
        controller.clear()
        controller.set_uid(uid)
        if target_kind == "pid":
            controller.set_pid(int(target["pid"]))
        configured = controller.set_nrs(syscall_numbers)
        if int(configured.get("skipped", 0)) != 0:
            raise SvcSiteError(
                "KPM_HOOK_INSTALL_FAILED",
                "KPM could not install every requested syscall hook",
                EXIT_KPM,
                {"response": configured},
            )

        package = target.get("package")
        if options.target_mode == "restart" and isinstance(package, str):
            phase = "target-stop"
            adb.force_stop(package)

        phase = "monitor-start"
        monitoring_started = True
        controller.start()
        if options.target_mode in {"launch", "restart"} and isinstance(package, str):
            phase = "target-launch"
            launch_result = adb.launch_package(package)
        elif isinstance(package, str):
            phase = "target-lookup"
            if not adb.package_pids(package):
                warnings.append(
                    {
                        "code": "TARGET_NOT_RUNNING",
                        "phase": "capture-start",
                        "evidence_valid": True,
                    }
                )

        phase = "post-launch-maps"
        mapped_pid_set.update(
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
        maps_snapshot_count += 1

        phase = "capture"
        try:
            deadline = time.monotonic() + options.duration
            poll = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.5, remaining))
                if time.monotonic() >= deadline:
                    break
                # PID capture has no additional processes to discover.
                if target_kind == "pid":
                    continue
                poll += 1
                previous_timeout = adb.timeout
                try:
                    # Bound each optional probe below the normal CLI timeout.
                    adb.timeout = min(previous_timeout, 2.0)
                    mapped_pid_set.update(
                        capture_maps_snapshot(
                            adb,
                            uid=uid,
                            maps_dir=maps_dir,
                            snapshot_id=f"post-launch-poll-{poll:06d}",
                            warnings=warnings,
                            exclude_pids=mapped_pid_set,
                        )
                    )
                    maps_snapshot_count += 1
                finally:
                    adb.timeout = previous_timeout
        except KeyboardInterrupt:
            warnings.append(
                {
                    "code": "CAPTURE_INTERRUPTED",
                    "phase": "capture",
                    "evidence_valid": True,
                }
            )
        phase = "pre-stop-maps"
        mapped_pid_set.update(
            capture_maps_snapshot(
                adb,
                uid=uid,
                maps_dir=maps_dir,
                snapshot_id="pre-stop",
                warnings=warnings,
                only_pids={int(target["pid"])} if target_kind == "pid" else None,
            )
        )
        maps_snapshot_count += 1
    except (Exception, KeyboardInterrupt) as exc:
        record_failure(exc, phase)

    if monitoring_started:
        final_status = None
        phase = "final-stop"
        try:
            controller.stop()
            phase = "final-drain"
            final_status = _wait_for_drain(controller, options.timeout)
        except (Exception, KeyboardInterrupt) as exc:
            record_failure(exc, phase)

    if error is not None:
        # A failed stop/drain must not leave the initial status labeled as final.
        try:
            final_status = controller.status()
        except (Exception, KeyboardInterrupt) as exc:
            final_status = None
            record_failure(exc, "final-status")

    if events_reset:
        phase = "events-readable"
        try:
            adb.make_root_file_readable(EVENT_PATH)
            phase = "events-pull"
            adb.pull(EVENT_PATH, events_path)
        except (Exception, KeyboardInterrupt) as exc:
            record_failure(exc, phase)
        # A failed pull may still leave a useful partial file.
        phase = "events-summary"
        try:
            if not events_path.is_file():
                raise SvcSiteError(
                    "EVENTS_NOT_FOUND", "capture events were not saved", EXIT_DATA
                )
            events_artifact = {"path": str(events_path)}
            summary, observed_pids = summarize_event_file(
                events_path,
                syscall_names,
                kernel_dropped=(
                    final_status.get("events_dropped") if final_status else None
                ),
            )
            phase = "events-fingerprint"
            events_artifact.update(
                size=events_path.stat().st_size,
                sha256=sha256_file(events_path),
            )
        except (Exception, KeyboardInterrupt) as exc:
            record_failure(exc, phase)

    target_pids = sorted(observed_pids)
    missing_pids = observed_pids - mapped_pid_set
    if missing_pids:
        try:
            mapped_pid_set.update(
                capture_maps_snapshot(
                    adb,
                    uid=uid,
                    maps_dir=maps_dir,
                    snapshot_id="recovery",
                    warnings=warnings,
                    only_pids=missing_pids,
                )
            )
            maps_snapshot_count += 1
        except (Exception, KeyboardInterrupt) as exc:
            record_failure(exc, "recovery-maps")

    device = {"serial": serial}
    if error is None:
        try:
            for field, command in (
                ("model", "getprop ro.product.model"),
                ("android_version", "getprop ro.build.version.release"),
                ("abi", "getprop ro.product.cpu.abi"),
                ("kernel_release", "uname -r"),
            ):
                device[field] = _shell_value(adb, command, field, warnings)
        except (Exception, KeyboardInterrupt) as exc:
            record_failure(exc, "device-metadata")

    ended_at = utc_now()
    mapped_pids = sorted(mapped_pid_set)
    maps_directory = str(maps_dir.resolve()) if maps_dir.is_dir() else None
    selected_syscalls = [
        {"nr": number, "name": syscall_names.get(number, f"sys_{number}")}
        for number in syscall_numbers
    ]
    manifest = {
        "schema_version": SESSION_SCHEMA,
        "session_id": session_dir.name,
        "status": (
            "failed" if error else "interrupted"
            if any(w["code"] == "CAPTURE_INTERRUPTED" for w in warnings)
            else "complete"
        ),
        "failures": failures,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": round(time.monotonic() - monotonic_start, 3),
        "device": device,
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
            "version": initial_status.get("version"),
            "initial_status": initial_status,
            "deploy": module_deploy,
            "final_status": final_status,
        },
        "summary": summary,
        "artifacts": {
            "events": events_artifact,
            "maps": {
                "directory": maps_directory,
                "snapshot_count": maps_snapshot_count,
                "mapped_pids": mapped_pids,
            },
        },
        "warnings": warnings,
    }
    try:
        write_json(manifest_path, manifest)
    except (Exception, KeyboardInterrupt) as exc:
        record_failure(exc, "manifest-write")
    if error is not None:
        raise SvcSiteError(
            error.code,
            error.message,
            error.exit_code,
            {
                **error.details,
                "session": str(session_dir),
                "manifest": str(manifest_path),
                "failures": failures,
                "final_status": final_status,
            },
        ) from error

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
