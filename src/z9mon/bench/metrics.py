"""Metric specs and shared statistics helpers for bench runs and reports."""

from __future__ import annotations

from typing import Any, Sequence

# (aggregate key, display label, unit, higher_is_better; None marks context)
METRIC_SPECS: tuple[tuple[str, str, str, bool | None], ...] = (
    ("performance.query_p50_ms", "query p50", "ms", False),
    ("performance.query_per_10k_ms", "query /10k events", "ms", False),
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


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = round(fraction * (len(ordered) - 1))
    return float(ordered[max(0, min(index, len(ordered) - 1))])


def iqr(values: Sequence[float]) -> float:
    return percentile(values, 0.75) - percentile(values, 0.25)


def lookup(aggregate: dict[str, Any], key: str) -> Any:
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
