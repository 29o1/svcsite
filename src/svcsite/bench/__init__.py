"""Benchmark runs and noise-aware report comparison.

Verdicts in comparisons only claim a change when the delta exceeds the
trial noise band, so scheduler jitter on the device does not turn into
false improvements.
"""

from __future__ import annotations

from svcsite.bench.aggregate import aggregate, median_session
from svcsite.bench.compare import (
    compare_reports,
    render_compare_table,
    run_compare,
)
from svcsite.bench.metrics import (
    METRIC_SPECS,
    format_metric_value,
    iqr,
    percentile,
)
from svcsite.bench.quality import compute_quality_metrics
from svcsite.bench.run import BenchOptions, run_bench, time_query

__all__ = [
    "BenchOptions",
    "METRIC_SPECS",
    "aggregate",
    "compare_reports",
    "compute_quality_metrics",
    "format_metric_value",
    "iqr",
    "median_session",
    "percentile",
    "render_compare_table",
    "run_bench",
    "run_compare",
    "time_query",
]
