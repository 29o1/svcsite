"""Trial aggregation and noise bands for bench reports."""

from __future__ import annotations

import statistics
from typing import Any

from z9mon.bench.metrics import iqr, percentile


def median_session(trials: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(trials, key=lambda trial: trial["events"])
    return ordered[len(ordered) // 2]


def aggregate(
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
