"""Benchmark runs and noise-aware report comparison.

A bench run converges the KPM module to the requested build, executes a
fixed number of bounded captures against a controlled fixture app, derives
evidence-quality and integrity metrics per trial, benchmarks query latency
on the median session, and writes a fingerprinted report.  Reports never
contain the SuperKey.  Verdicts in comparisons only claim a change when
the delta exceeds the trial noise band, so scheduler jitter on the device
does not turn into false improvements.
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
from typing import Any, Callable, Sequence

from z9mon import __version__
from z9mon.adb import AdbClient
from z9mon.capture import CaptureOptions, run_capture
from z9mon.config import read_superkey, resolve_kpm_path
from z9mon.constants import BENCH_SCHEMA
from z9mon.errors import EXIT_DATA, Z9MonError
from z9mon.kpm import KpmController, require_root
from z9mon.maps import ModuleIndex
from z9mon.protocol import open_event_stream
from z9mon.query import _event_callsites
from z9mon.session import write_json


# (aggregate key, display label, unit, higher_is_better; None marks context)
METRIC_SPECS: tuple[tuple[str, str, str, bool | None], ...] = (
    ("performance.query_events_p50_ms", "query events p50", "ms", False),
    ("performance.query_events_per_10k_ms", "query events /10k events", "ms", False),
    ("performance.query_stats_p50_ms", "query stats p50", "ms", False),
    ("performance.query_stats_per_10k_ms", "query stats /10k events", "ms", False),
    ("performance.query_callsites_p50_ms", "query callsites p50", "ms", False),
    (
        "performance.query_callsites_per_10k_ms",
        "query callsites /10k events",
        "ms",
        False,
    ),
    ("performance.capture_wall_p50_s", "capture wall p50", "s", False),
    ("evidence.callsite_resolve_rate", "callsite resolve rate", "rate", True),
    ("evidence.frame_resolve_rate", "frame resolve rate", "rate", True),
    ("evidence.module_attribution_rate", "module attribution", "rate", True),
    ("evidence.backtrace_depth_median", "backtrace depth median", "count", True),
    ("evidence.backtrace_depth_p90", "backtrace depth p90", "count", True),
    ("evidence.unique_callsites", "unique callsites", "count", True),
    ("evidence.signal_ratio", "signal ratio", "ratio", True),
    ("counts.events", "events per trial", "count", None),
    ("integrity.kernel_dropped", "kernel dropped", "count", False),
    ("integrity.sequence_gaps", "sequence gaps", "count", False),
    ("integrity.sequence_missing", "sequence missing", "count", False),
    ("integrity.parser_invalid", "parser invalid records", "count", False),
)


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


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = round(fraction * (len(ordered) - 1))
    return float(ordered[max(0, min(index, len(ordered) - 1))])


def iqr(values: Sequence[float]) -> float:
    return percentile(values, 0.75) - percentile(values, 0.25)


def _lookup(aggregate: dict[str, Any], key: str) -> Any:
    node: Any = aggregate
    for part in key.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def format_metric_value(value: Any, unit: str) -> str:
    if value is None:
        return "-"
    if unit == "ms":
        return f"{value:.1f}"
    if unit == "s":
        return f"{value:.2f}"
    if unit == "rate":
        return f"{value * 100:.1f}%"
    if unit == "ratio":
        return f"{value:.4f}"
    return str(int(value))


def _progress(message: str) -> None:
    print(f"bench: {message}", file=sys.stderr)


def compute_quality_metrics(session_dir: str | Path) -> dict[str, Any]:
    """Derive evidence-quality and integrity metrics from session artifacts."""

    session = Path(session_dir)
    module_index = ModuleIndex.from_session(session)
    total = 0
    resolved_events = 0
    attributed_events = 0
    frames_total = 0
    frames_resolved = 0
    depths: list[int] = []
    unique_callsites: set[tuple[int, str | None, str | None]] = set()

    with open_event_stream(session / "events.bin") as stream:
        for event in stream:
            total += 1
            depth = len(event.backtrace)
            depths.append(depth)
            frames_total += depth
            callsites = (
                _event_callsites(event, module_index) if module_index else []
            )
            if callsites:
                resolved_events += 1
            attributed = False
            for callsite in callsites:
                resolved = callsite["resolved"]
                if callsite["frame"] == "backtrace":
                    frames_resolved += 1
                if str(resolved.get("module_id", "")).startswith("file:"):
                    attributed = True
                unique_callsites.add(
                    (
                        event.nr,
                        resolved.get("module_id"),
                        resolved.get("module_offset"),
                    )
                )
            if attributed:
                attributed_events += 1
        parser_quality = stream.quality()

    summary: dict[str, Any] = {}
    summary_path = session / "summary.json"
    if summary_path.is_file():
        try:
            loaded = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                summary = loaded
        except (OSError, json.JSONDecodeError):
            summary = {}
    sequence = summary.get("sequence", {})
    parser = summary.get("parser", parser_quality)

    resolution_available = module_index is not None
    return {
        "counts": {"events": total, "frames": frames_total},
        "evidence": {
            "callsite_resolve_rate": (
                round(resolved_events / total, 4)
                if total and resolution_available
                else None
            ),
            "frame_resolve_rate": (
                round(frames_resolved / frames_total, 4)
                if frames_total and resolution_available
                else None
            ),
            "module_attribution_rate": (
                round(attributed_events / total, 4)
                if total and resolution_available
                else None
            ),
            "backtrace_depth_median": int(statistics.median(depths))
            if depths
            else None,
            "backtrace_depth_p90": int(percentile(depths, 0.9)) if depths else None,
            "unique_callsites": len(unique_callsites) if resolution_available else None,
            "signal_ratio": (
                round(len(unique_callsites) / total, 4)
                if total and resolution_available
                else None
            ),
            "address_resolution_available": resolution_available,
        },
        "integrity": {
            "kernel_dropped": int(summary.get("kernel_dropped", 0)),
            "sequence_gaps": int(sequence.get("gaps", 0)),
            "sequence_missing": int(sequence.get("missing", 0)),
            "parser_invalid": int(parser.get("invalid_records", 0)),
        },
    }


def _git_info() -> dict[str, Any] | None:
    root = Path(__file__).resolve().parents[2]
    try:
        sha = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if sha.returncode != 0:
            return None
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return {
            "sha": sha.stdout.strip(),
            "dirty": bool(status.stdout.strip()),
        }
    except (OSError, subprocess.TimeoutExpired):
        return None


def _query_environment() -> dict[str, str]:
    environment = dict(os.environ)
    source_root = str(Path(__file__).resolve().parents[1])
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_root if not existing else source_root + os.pathsep + existing
    )
    return environment


_QUERY_MODES: dict[str, tuple[str, ...]] = {
    "events": ("--mode", "events", "--syscall", "openat", "--limit", "50"),
    "stats": ("--mode", "stats", "--limit", "50"),
    "callsites": ("--mode", "callsites", "--limit", "50"),
}


def time_query_mode(
    session: Path,
    mode: str,
    iterations: int,
) -> dict[str, Any]:
    """Time CLI query subprocesses; enforces the single-JSON stdout contract."""

    arguments = _QUERY_MODES[mode]
    timings: list[float] = []
    for _ in range(iterations):
        command = [
            sys.executable,
            "-m",
            "z9mon",
            "query",
            str(session),
            *arguments,
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
            raise Z9MonError(
                "BENCH_QUERY_FAILED",
                "bench query subprocess failed",
                EXIT_DATA,
                {"mode": mode, "stderr": result.stderr[-500:]},
            )
        try:
            json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise Z9MonError(
                "BENCH_QUERY_CONTRACT",
                "bench query output was not one JSON object",
                EXIT_DATA,
                {"mode": mode, "reason": str(exc)},
            ) from exc
        timings.append(elapsed)
    return {
        "p50_ms": round(statistics.median(timings), 1),
        "p95_ms": round(percentile(timings, 0.95), 1),
        "timings_ms": [round(value, 1) for value in timings],
    }


def _median_session(trials: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(trials, key=lambda trial: trial["events"])
    return ordered[len(ordered) // 2]


def _aggregate(
    trials: list[dict[str, Any]],
    query_timings: dict[str, dict[str, Any]],
    events_total: int,
) -> tuple[dict[str, Any], dict[str, float]]:
    evidence: dict[str, Any] = {}
    for key in trials[0]["evidence"]:
        values = [
            trial["evidence"][key]
            for trial in trials
            if trial["evidence"].get(key) is not None
        ]
        median = statistics.median(values) if values else None
        evidence[key] = (
            round(median, 4) if isinstance(median, float) else median
        )
    integrity = {
        key: max(trial["integrity"].get(key, 0) for trial in trials)
        for key in trials[0]["integrity"]
    }
    counts = {
        "events": int(statistics.median([trial["events"] for trial in trials])),
        "frames": int(
            statistics.median([trial["evidence_frames"] for trial in trials])
        ),
    }
    walls = [trial["duration_seconds"] for trial in trials]

    performance: dict[str, Any] = {
        "capture_wall_p50_s": round(statistics.median(walls), 2),
    }
    for mode, timing in query_timings.items():
        performance[f"query_{mode}_p50_ms"] = timing["p50_ms"]
        performance[f"query_{mode}_p95_ms"] = timing["p95_ms"]
        performance[f"query_{mode}_per_10k_ms"] = (
            round(timing["p50_ms"] * 10000.0 / events_total, 1)
            if events_total
            else None
        )

    noise: dict[str, float] = {}
    for key in trials[0]["evidence"]:
        values = [
            trial["evidence"][key]
            for trial in trials
            if isinstance(trial["evidence"].get(key), (int, float))
            and not isinstance(trial["evidence"].get(key), bool)
        ]
        if len(values) > 1:
            noise[f"evidence.{key}"] = round(iqr(values), 4)
    for key in trials[0]["integrity"]:
        noise[f"integrity.{key}"] = 0.0
    noise["counts.events"] = round(
        iqr([float(trial["events"]) for trial in trials]), 1
    )
    noise["performance.capture_wall_p50_s"] = round(iqr(walls), 2)
    for mode, timing in query_timings.items():
        # The band keeps run-to-run scheduler jitter out of the verdicts:
        # within-run IQR alone underestimates it, so include the upper tail.
        timings = timing["timings_ms"]
        band = max(iqr(timings), percentile(timings, 0.95) - statistics.median(timings))
        noise[f"performance.query_{mode}_p50_ms"] = round(band, 1)
        if events_total:
            noise[f"performance.query_{mode}_per_10k_ms"] = round(
                band * 10000.0 / events_total, 1
            )

    return (
        {
            "performance": performance,
            "evidence": evidence,
            "integrity": integrity,
            "counts": counts,
        },
        noise,
    )


def _report_markdown(
    run_id: str,
    fingerprint: dict[str, Any],
    aggregate: dict[str, Any],
    noise: dict[str, float],
) -> str:
    git = fingerprint.get("git") or {}
    module = fingerprint.get("module") or {}
    device = fingerprint.get("device") or {}
    parameters = fingerprint.get("parameters") or {}
    lines = [
        f"# z9mon bench report — {run_id}",
        "",
        f"- generated: `{fingerprint.get('generated_at')}`",
        f"- z9mon: `{fingerprint.get('z9mon_version')}`"
        f" git `{(git.get('sha') or 'n/a')[:12]}"
        f"{' (dirty)' if git.get('dirty') else ''}`",
        f"- device: `{device.get('model')}` ({device.get('android_version')},"
        f" `{device.get('abi')}`) serial `{device.get('serial')}`",
        f"- module: loaded `{module.get('loaded_version')}`"
        f" deploy `{module.get('deploy_action')}`"
        f" sha256 `{str(module.get('kpm_sha256') or '-')[:12]}`",
        f"- workload: `{parameters.get('package')}`"
        f" {parameters.get('duration')}s x {parameters.get('trials')} trials"
        f" ({parameters.get('target_mode')})",
        "",
        "| metric | value | noise |",
        "|---|---|---|",
    ]
    for key, label, unit, _ in METRIC_SPECS:
        value = format_metric_value(_lookup(aggregate, key), unit)
        band_value = noise.get(key)
        band = (
            format_metric_value(band_value, unit)
            if band_value is not None
            else "-"
        )
        lines.append(f"| {label} ({unit}) | {value} | {band} |")
    return "\n".join(lines) + "\n"


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
    git = _git_info()
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
                load_module=None,
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
            raise Z9MonError(
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

    kept = _median_session(trials)
    kept_path = Path(kept["session"])
    _progress(f"keeping median session {kept['session_id']}")
    if not options.keep_sessions:
        for trial in trials:
            if trial["session_id"] != kept["session_id"]:
                shutil.rmtree(trial["session"], ignore_errors=True)

    _progress("benchmarking query modes")
    query_timings = {
        mode: time_query_mode(kept_path, mode, options.query_iterations)
        for mode in _QUERY_MODES
    }

    aggregate, noise = _aggregate(trials, query_timings, kept["events"])

    fingerprint = {
        "generated_at": generated_at,
        "z9mon_version": __version__,
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
        "aggregate": aggregate,
        "noise": noise,
        "query_timings": query_timings,
        "session": str(kept_path),
    }

    report_dir = output_root / run_id
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.json"
    markdown_path = report_dir / "report.md"
    write_json(report_path, report)
    markdown_path.write_text(
        _report_markdown(run_id, fingerprint, aggregate, noise), encoding="utf-8"
    )
    _progress(f"report {report_path}")
    return {
        "run_id": run_id,
        "report": str(report_path),
        "markdown": str(markdown_path),
        "session": str(kept_path),
        "fingerprint": fingerprint,
        "aggregate": aggregate,
        "noise": noise,
    }


def _load_report(path_value: str) -> dict[str, Any]:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise Z9MonError(
            "BENCH_REPORT_NOT_FOUND",
            "bench report was not found",
            EXIT_DATA,
            {"path": str(path)},
        )
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Z9MonError(
            "BENCH_REPORT_INVALID",
            "bench report could not be read",
            EXIT_DATA,
            {"path": str(path), "reason": str(exc)},
        ) from exc
    if not isinstance(report, dict) or report.get("schema_version") != BENCH_SCHEMA:
        raise Z9MonError(
            "BENCH_REPORT_INVALID",
            "bench report has an unsupported schema",
            EXIT_DATA,
            {"path": str(path)},
        )
    return report


def _verdict(
    delta: Any,
    noise: float,
    higher_is_better: bool | None,
) -> str:
    if higher_is_better is None:
        return "context"
    if delta is None:
        return "missing"
    magnitude = abs(delta)
    if noise:
        if magnitude <= noise:
            return "flat"
    elif delta == 0:
        return "flat"
    improved = delta > 0 if higher_is_better else delta < 0
    return "improved" if improved else "regressed"


def compare_reports(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    base_aggregate = baseline.get("aggregate", {})
    cand_aggregate = candidate.get("aggregate", {})
    base_noise = baseline.get("noise", {})
    cand_noise = candidate.get("noise", {})

    rows: list[dict[str, Any]] = []
    for key, label, unit, higher_is_better in METRIC_SPECS:
        base_value = _lookup(base_aggregate, key)
        cand_value = _lookup(cand_aggregate, key)
        if base_value is None or cand_value is None:
            delta = None
            relative = None
        else:
            delta = cand_value - base_value
            relative = (
                delta / base_value
                if isinstance(base_value, (int, float)) and base_value != 0
                else None
            )
        noise = max(
            base_noise.get(key, 0.0) or 0.0,
            cand_noise.get(key, 0.0) or 0.0,
        )
        rows.append(
            {
                "metric": key,
                "label": label,
                "unit": unit,
                "baseline": base_value,
                "candidate": cand_value,
                "delta": delta,
                "delta_relative": round(relative, 4)
                if relative is not None
                else None,
                "noise": noise,
                "verdict": _verdict(delta, noise, higher_is_better),
            }
        )

    base_print = baseline.get("fingerprint", {})
    cand_print = candidate.get("fingerprint", {})
    compared_fields = (
        ("git.sha", "git"),
        ("module.loaded_version", "module version"),
        ("module.kpm_sha256", "kpm sha256"),
        ("device.serial", "device"),
        ("parameters.package", "package"),
        ("parameters.duration", "duration"),
    )
    context: dict[str, Any] = {}
    differences: list[str] = []
    for path_key, name in compared_fields:
        base_value = _lookup(base_print, path_key)
        cand_value = _lookup(cand_print, path_key)
        context[name] = {"baseline": base_value, "candidate": cand_value}
        if base_value != cand_value:
            differences.append(name)

    warnings: list[str] = []
    if "package" in differences:
        warnings.append("packages differ; evidence metrics are not comparable")
    if "duration" in differences:
        warnings.append("capture durations differ; event counts are not comparable")

    verdicts = [row["verdict"] for row in rows]
    return {
        "baseline": baseline.get("run_id"),
        "candidate": candidate.get("run_id"),
        "rows": rows,
        "context": context,
        "differences": differences,
        "warnings": warnings,
        "summary": {
            "improved": verdicts.count("improved"),
            "regressed": verdicts.count("regressed"),
            "flat": verdicts.count("flat"),
            "missing": verdicts.count("missing"),
        },
    }


def render_compare_table(comparison: dict[str, Any]) -> str:
    headers = ("metric", "baseline", "candidate", "delta", "noise", "verdict")
    table: list[list[str]] = []
    for row in comparison["rows"]:
        relative = row["delta_relative"]
        if row["delta"] is None:
            delta_text = "-"
        elif relative is not None:
            delta_text = f"{relative * 100:+.1f}%"
        else:
            delta_text = f"{row['delta']:+}"
        table.append(
            [
                f"{row['label']} ({row['unit']})",
                format_metric_value(row["baseline"], row["unit"]),
                format_metric_value(row["candidate"], row["unit"]),
                delta_text,
                format_metric_value(row["noise"], row["unit"]),
                row["verdict"],
            ]
        )
    widths = [
        max(len(row[column]) for row in (*table, list(headers)))
        for column in range(len(headers))
    ]
    lines = [
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    ]
    lines.append("  ".join("-" * width for width in widths))
    for row in table:
        lines.append(
            "  ".join(
                cell.ljust(widths[index]) for index, cell in enumerate(row)
            )
        )
    summary = comparison.get("summary", {})
    lines.append("")
    lines.append(
        f"verdicts: {summary.get('improved', 0)} improved, "
        f"{summary.get('regressed', 0)} regressed, "
        f"{summary.get('flat', 0)} flat"
    )
    for warning in comparison.get("warnings", []):
        lines.append(f"warning: {warning}")
    return "\n".join(lines)


def run_compare(baseline_path: str, candidate_path: str) -> dict[str, Any]:
    baseline = _load_report(baseline_path)
    candidate = _load_report(candidate_path)
    comparison = compare_reports(baseline, candidate)
    comparison["baseline_report"] = str(Path(baseline_path).resolve())
    comparison["candidate_report"] = str(Path(candidate_path).resolve())
    return comparison
