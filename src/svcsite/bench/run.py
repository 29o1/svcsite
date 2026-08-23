"""Bench run orchestration: module convergence, trials, query timing, reports.

A bench run converges the KPM module to the requested build, executes a
fixed number of bounded captures against a controlled fixture app, derives
evidence-quality and integrity metrics per trial, benchmarks query latency
on the median session, and writes a fingerprinted report.  Reports never
contain the SuperKey.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time
from typing import Any

from svcsite import __version__
from svcsite.adb import AdbClient
from svcsite.bench.aggregate import aggregate, median_session
from svcsite.bench.metrics import percentile
from svcsite.bench.quality import compute_quality_metrics
from svcsite.bench.report import git_info, report_markdown
from svcsite.capture import CaptureOptions, run_capture
from svcsite.config import read_superkey
from svcsite.constants import BENCH_SCHEMA
from svcsite.errors import EXIT_DATA, SvcSiteError
from svcsite.kpm import KpmController, require_root
from svcsite.session import write_json


@dataclass(frozen=True)
class BenchOptions:
    device: str | None
    timeout: float
    key_file: str | None
    package: str
    kpm: str | None
    duration: float
    trials: int
    output: str
    keep_sessions: bool
    query_iterations: int
    target_mode: str


def _progress(message: str) -> None:
    print(f"bench: {message}", file=sys.stderr)


def _query_environment() -> dict[str, str]:
    environment = dict(os.environ)
    source_root = str(Path(__file__).resolve().parents[2])
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_root if not existing else source_root + os.pathsep + existing
    )
    return environment


_QUERY_ARGUMENTS = ("--syscall", "openat", "--limit", "50")


def time_query(
    session: Path,
    iterations: int,
) -> dict[str, Any]:
    """Time CLI query subprocesses; enforces the single-JSON stdout contract."""

    timings: list[float] = []
    for _ in range(iterations):
        command = [
            sys.executable,
            "-m",
            "svcsite",
            "query",
            str(session),
            *_QUERY_ARGUMENTS,
            "--json",
        ]
        started = time.perf_counter()
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=_query_environment(),
            timeout=120,
        )
        elapsed = (time.perf_counter() - started) * 1000.0
        if result.returncode != 0:
            raise SvcSiteError(
                "BENCH_QUERY_FAILED",
                "bench query subprocess failed",
                EXIT_DATA,
                {"stderr": result.stderr[-500:]},
            )
        try:
            json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SvcSiteError(
                "BENCH_QUERY_CONTRACT",
                "bench query output was not one JSON object",
                EXIT_DATA,
                {"reason": str(exc)},
            ) from exc
        timings.append(elapsed)
    return {
        "p50_ms": round(statistics.median(timings), 1),
        "p95_ms": round(percentile(timings, 0.95), 1),
        "timings_ms": [round(value, 1) for value in timings],
    }


def run_bench(options: BenchOptions) -> dict[str, Any]:
    adb = AdbClient(timeout=options.timeout)
    serial = adb.resolve_serial(options.device)
    require_root(adb)
    key = read_superkey(options.key_file)
    controller = KpmController(adb, key.value)
    controller.locate_kpatch()

    deploy: dict[str, Any] | None = None
    if options.kpm:
        deploy = controller.ensure_module(options.kpm)
        _progress(
            f"module action={deploy['action']} "
            f"sha256={deploy['sha256'][:12]}"
        )
    else:
        controller.require_loaded()
    initial_status = controller.status()
    loaded_version = initial_status.get("version")
    _progress(f"loaded module version {loaded_version}")

    output_root = Path(options.output).expanduser().resolve()
    sessions_root = output_root / "sessions"
    sessions_root.mkdir(parents=True, exist_ok=True)
    git = git_info()
    generated_at = datetime.now(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        + "-"
        + ((git or {}).get("sha") or "nogit")[:8]
    )

    trials: list[dict[str, Any]] = []
    for index in range(options.trials):
        result = run_capture(
            CaptureOptions(
                device=serial,
                timeout=options.timeout,
                key_file=options.key_file,
                package=options.package,
                duration=options.duration,
                syscalls=(),
                target_mode=options.target_mode,
                output=str(sessions_root),
                kpm=None,
            )
        )
        session_dir = Path(result["session"])
        metrics = compute_quality_metrics(session_dir)
        manifest_path = session_dir / "manifest.json"
        manifest: dict[str, Any] = {}
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            manifest = {}
        final_status = (
            manifest.get("module", {}).get("final_status", {})
            if isinstance(manifest.get("module"), dict)
            else {}
        )
        buffered = int(final_status.get("events_buffered", -1))
        enabled = bool(final_status.get("enabled", True))
        contract_ok = buffered == 0 and not enabled
        if not contract_ok:
            raise SvcSiteError(
                "BENCH_CONTRACT_VIOLATION",
                "capture trial finished with monitoring enabled or events buffered",
                EXIT_DATA,
                {"session": str(session_dir), "final_status": final_status},
            )
        trials.append(
            {
                "session_id": result["session_id"],
                "session": str(session_dir),
                "duration_seconds": manifest.get("duration_seconds"),
                "events": metrics["counts"]["events"],
                "evidence_frames": metrics["counts"]["frames"],
                "evidence": metrics["evidence"],
                "integrity": metrics["integrity"],
                "contract_ok": True,
            }
        )
        _progress(
            f"trial {index + 1}/{options.trials} session={result['session_id']} "
            f"events={metrics['counts']['events']}"
        )

    kept = median_session(trials)
    kept_path = Path(kept["session"])
    _progress(f"keeping median session {kept['session_id']}")
    if not options.keep_sessions:
        for trial in trials:
            if trial["session_id"] != kept["session_id"]:
                shutil.rmtree(trial["session"], ignore_errors=True)

    _progress("benchmarking query")
    query_timing = time_query(kept_path, options.query_iterations)

    aggregate_data, noise = aggregate(trials, query_timing, kept["events"])

    fingerprint = {
        "generated_at": generated_at,
        "svcsite_version": __version__,
        "python_version": platform.python_version(),
        "git": git,
        "device": {
            "serial": serial,
            "model": adb.getprop("ro.product.model"),
            "android_version": adb.getprop("ro.build.version.release"),
            "abi": adb.getprop("ro.product.cpu.abi"),
            "kernel_release": adb.shell("uname -r\n").stdout.strip(),
        },
        "module": {
            "kpm_local_path": options.kpm,
            "kpm_sha256": (deploy or {}).get("sha256"),
            "loaded_version": loaded_version,
            "deploy_action": (deploy or {}).get("action"),
        },
        "parameters": {
            "package": options.package,
            "duration": options.duration,
            "trials": options.trials,
            "target_mode": options.target_mode,
            "query_iterations": options.query_iterations,
        },
    }
    report = {
        "schema_version": BENCH_SCHEMA,
        "run_id": run_id,
        "fingerprint": fingerprint,
        "trials": [
            {
                key: trial[key]
                for key in (
                    "session_id",
                    "session",
                    "duration_seconds",
                    "events",
                    "evidence",
                    "integrity",
                    "contract_ok",
                )
            }
            for trial in trials
        ],
        "aggregate": aggregate_data,
        "noise": noise,
        "query_timing": query_timing,
        "session": str(kept_path),
    }

    report_dir = output_root / run_id
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.json"
    markdown_path = report_dir / "report.md"
    write_json(report_path, report)
    markdown_path.write_text(
        report_markdown(run_id, fingerprint, aggregate_data, noise),
        encoding="utf-8",
    )
    _progress(f"report {report_path}")
    return {
        "run_id": run_id,
        "report": str(report_path),
        "markdown": str(markdown_path),
        "session": str(kept_path),
        "fingerprint": fingerprint,
        "aggregate": aggregate_data,
        "noise": noise,
    }
