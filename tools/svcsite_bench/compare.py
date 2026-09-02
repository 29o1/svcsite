"""Noise-aware comparison of two bench reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from svcsite.errors import EXIT_DATA, SvcSiteError
from tools.svcsite_bench.constants import BENCH_SCHEMA
from tools.svcsite_bench.metrics import METRIC_SPECS, format_metric_value, lookup


def _load_report(path_value: str) -> dict[str, Any]:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise SvcSiteError(
            "BENCH_REPORT_NOT_FOUND",
            "bench report was not found",
            EXIT_DATA,
            {"path": str(path)},
        )
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SvcSiteError(
            "BENCH_REPORT_INVALID",
            "bench report could not be read",
            EXIT_DATA,
            {"path": str(path), "reason": str(exc)},
        ) from exc
    if not isinstance(report, dict) or report.get("schema_version") != BENCH_SCHEMA:
        raise SvcSiteError(
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
        base_value = lookup(base_aggregate, key)
        cand_value = lookup(cand_aggregate, key)
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
        base_value = lookup(base_print, path_key)
        cand_value = lookup(cand_print, path_key)
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
