import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_protocol import make_event
from z9mon.bench import (
    aggregate as _aggregate,
    compare_reports,
    compute_quality_metrics,
    format_metric_value,
    iqr,
    percentile,
    render_compare_table,
)
from z9mon.commands.bench import main as bench_main
from z9mon.constants import BENCH_SCHEMA, MODULES_SCHEMA


class StatHelperTests(unittest.TestCase):
    def test_percentile_uses_nearest_rank(self) -> None:
        self.assertEqual(percentile([1, 2, 3, 4, 5], 0.5), 3.0)
        self.assertEqual(percentile([1, 2, 3, 4], 0.5), 3.0)
        self.assertEqual(percentile([], 0.9), 0.0)

    def test_iqr_covers_middle_half(self) -> None:
        self.assertEqual(iqr([1, 2, 3, 4, 5]), 2.0)

    def test_formats_values_by_unit(self) -> None:
        self.assertEqual(format_metric_value(12.34, "ms"), "12.3")
        self.assertEqual(format_metric_value(3.456, "s"), "3.46")
        self.assertEqual(format_metric_value(0.7238, "rate"), "72.4%")
        self.assertEqual(format_metric_value(0.0012, "ratio"), "0.0012")
        self.assertEqual(format_metric_value(9, "count"), "9")
        self.assertEqual(format_metric_value(None, "ms"), "-")


def write_session(directory: Path) -> Path:
    session = Path(directory, "session")
    session.mkdir()
    (session / "events.bin").write_bytes(
        make_event(seq=1, tgid=100, backtrace=(0x5000, 0x6000))
        + make_event(seq=2, tgid=100, backtrace=(0x5000, 0x6000))
        + make_event(seq=3, nr=63, tgid=100, backtrace=(0x9000,))
    )
    (session / "manifest.json").write_text(
        json.dumps(
            {
                "summary": {
                    "kernel_dropped": 0,
                    "sequence": {"gaps": 0, "missing": 0},
                    "parser": {"invalid_records": 0, "skipped_bytes": 0},
                },
            }
        ),
        encoding="utf-8",
    )
    (session / "modules.json").write_text(
        json.dumps(
            {
                "schema_version": MODULES_SCHEMA,
                "session_id": "bench-fixture",
                "snapshots": [
                    {
                        "snapshot_id": "pre-stop",
                        "captured_at": "2026-08-16T00:00:00.000Z",
                        "processes": [
                            {
                                "pid": 100,
                                "mappings": [
                                    {
                                        "start": "0x1000",
                                        "end": "0xA000",
                                        "file_offset": "0x0",
                                        "permissions": "r-xp",
                                        "path": "/data/app/libfixture.so",
                                        "module": "libfixture.so",
                                        "module_id": "file:bench:libfixture.so",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return session


class QualityMetricsTests(unittest.TestCase):
    def test_computes_resolution_and_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metrics = compute_quality_metrics(write_session(Path(directory)))

        self.assertEqual(metrics["counts"]["events"], 3)
        self.assertEqual(metrics["evidence"]["callsite_resolve_rate"], 1.0)
        self.assertLessEqual(metrics["evidence"]["frame_resolve_rate"], 1.0)
        self.assertGreater(metrics["evidence"]["unique_callsites"], 0)
        self.assertEqual(metrics["evidence"]["backtrace_depth_median"], 2)
        self.assertTrue(metrics["evidence"]["address_resolution_available"])
        self.assertEqual(
            metrics["integrity"],
            {
                "kernel_dropped": 0,
                "sequence_gaps": 0,
                "sequence_missing": 0,
                "parser_invalid": 0,
            },
        )

    def test_session_without_modules_reports_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = write_session(Path(directory))
            (session / "modules.json").unlink()

            metrics = compute_quality_metrics(session)

        self.assertFalse(metrics["evidence"]["address_resolution_available"])
        self.assertIsNone(metrics["evidence"]["callsite_resolve_rate"])


def make_report(
    aggregate: dict,
    noise: dict | None = None,
    *,
    run_id: str = "run",
    fingerprint: dict | None = None,
) -> dict:
    return {
        "schema_version": BENCH_SCHEMA,
        "run_id": run_id,
        "fingerprint": fingerprint
        or {
            "git": {"sha": "a" * 40, "dirty": False},
            "module": {"loaded_version": "1.4.0"},
            "device": {"serial": "same"},
            "parameters": {
                "package": "io.z9null.tracefixture",
                "duration": 15,
            },
        },
        "aggregate": aggregate,
        "noise": noise or {},
    }


BASELINE_AGGREGATE = {
    "performance": {
        "query_p50_ms": 900.0,
        "capture_wall_p50_s": 42.0,
    },
    "evidence": {
        "callsite_resolve_rate": 0.70,
        "unique_callsites": 120,
        "backtrace_depth_median": 5,
    },
    "counts": {"events": 10000},
    "integrity": {
        "kernel_dropped": 0,
        "sequence_gaps": 0,
        "sequence_missing": 0,
        "parser_invalid": 0,
    },
}


class AggregateNoiseTests(unittest.TestCase):
    def test_timing_noise_includes_tail_and_per_10k(self) -> None:
        trials = [
            {
                "duration_seconds": 12.0,
                "events": 10000,
                "evidence_frames": 30000,
                "evidence": {"callsite_resolve_rate": 1.0},
                "integrity": {"kernel_dropped": 0},
            },
            {
                "duration_seconds": 13.0,
                "events": 10100,
                "evidence_frames": 30300,
                "evidence": {"callsite_resolve_rate": 1.0},
                "integrity": {"kernel_dropped": 0},
            },
        ]
        timing = {
            "p50_ms": 61.0,
            "p95_ms": 90.0,
            "timings_ms": [58, 60, 61, 62, 90],
        }

        aggregate, noise = _aggregate(trials, timing, 10000)

        self.assertEqual(noise["performance.query_p50_ms"], 29.0)
        self.assertEqual(noise["performance.query_per_10k_ms"], 29.0)
        self.assertEqual(aggregate["performance"]["query_per_10k_ms"], 61.0)


class CompareTests(unittest.TestCase):
    def test_large_deltas_outside_noise_get_verdicts(self) -> None:
        candidate = make_report(
            {
                **BASELINE_AGGREGATE,
                "performance": {
                    "query_p50_ms": 600.0,
                    "capture_wall_p50_s": 42.0,
                },
                "evidence": {
                    "callsite_resolve_rate": 0.90,
                    "unique_callsites": 120,
                    "backtrace_depth_median": 5,
                },
            }
        )
        baseline = make_report(BASELINE_AGGREGATE)

        comparison = compare_reports(baseline, candidate)

        by_metric = {row["metric"]: row for row in comparison["rows"]}
        self.assertEqual(
            by_metric["performance.query_p50_ms"]["verdict"], "improved"
        )
        self.assertEqual(
            by_metric["evidence.callsite_resolve_rate"]["verdict"], "improved"
        )
        self.assertEqual(
            by_metric["evidence.unique_callsites"]["verdict"], "flat"
        )
        self.assertEqual(by_metric["counts.events"]["verdict"], "context")
        self.assertEqual(comparison["summary"]["improved"], 2)
        self.assertEqual(comparison["differences"], [])

    def test_deltas_inside_noise_band_stay_flat(self) -> None:
        candidate = make_report(
            {
                **BASELINE_AGGREGATE,
                "evidence": {
                    "callsite_resolve_rate": 0.72,
                    "unique_callsites": 120,
                    "backtrace_depth_median": 5,
                },
            }
        )
        baseline = make_report(BASELINE_AGGREGATE, {"evidence.callsite_resolve_rate": 0.05})

        comparison = compare_reports(baseline, candidate)

        by_metric = {row["metric"]: row for row in comparison["rows"]}
        self.assertEqual(
            by_metric["evidence.callsite_resolve_rate"]["verdict"], "flat"
        )

    def test_regressions_and_missing_metrics(self) -> None:
        candidate = make_report(
            {
                **BASELINE_AGGREGATE,
                "performance": {"query_p50_ms": 1200.0},
                "evidence": {
                    "callsite_resolve_rate": 0.70,
                    "unique_callsites": 120,
                    "backtrace_depth_median": 5,
                },
            }
        )

        comparison = compare_reports(make_report(BASELINE_AGGREGATE), candidate)

        by_metric = {row["metric"]: row for row in comparison["rows"]}
        self.assertEqual(
            by_metric["performance.query_p50_ms"]["verdict"], "regressed"
        )
        self.assertEqual(
            by_metric["performance.capture_wall_p50_s"]["verdict"], "missing"
        )
        self.assertEqual(comparison["summary"]["regressed"], 1)

    def test_table_renders_rows_and_summary(self) -> None:
        candidate = make_report(
            {
                **BASELINE_AGGREGATE,
                "evidence": {
                    "callsite_resolve_rate": 0.90,
                    "unique_callsites": 120,
                    "backtrace_depth_median": 5,
                },
            }
        )

        table = render_compare_table(
            compare_reports(make_report(BASELINE_AGGREGATE), candidate)
        )

        self.assertIn("callsite resolve rate (rate)", table)
        self.assertIn("70.0%", table)
        self.assertIn("90.0%", table)
        self.assertIn("improved", table)
        self.assertIn("verdicts:", table)


class CompareCliTests(unittest.TestCase):
    def test_compare_command_emits_single_json_and_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory, "baseline.json")
            candidate_path = Path(directory, "candidate.json")
            baseline_path.write_text(
                json.dumps(make_report(BASELINE_AGGREGATE, run_id="base")), encoding="utf-8"
            )
            candidate_path.write_text(
                json.dumps(
                    make_report(
                        {
                            **BASELINE_AGGREGATE,
                            "evidence": {
                                "callsite_resolve_rate": 0.90,
                                "unique_callsites": 120,
                                "backtrace_depth_median": 5,
                            },
                        },
                        run_id="cand",
                    )
                ),
                encoding="utf-8",
            )

            stream = io.StringIO()
            with redirect_stdout(stream):
                with patch("sys.stderr", new=io.StringIO()):
                    exit_code = bench_main(
                        [
                            "compare",
                            str(baseline_path),
                            str(candidate_path),
                            "--json",
                        ]
                    )

            payload = json.loads(stream.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "bench.compare")
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["data"]["summary"]["improved"], 1)

    def test_missing_report_has_stable_error(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            with patch("sys.stderr", new=io.StringIO()):
                exit_code = bench_main(
                    ["compare", "/missing/a.json", "/missing/b.json", "--json"]
                )

        payload = json.loads(stream.getvalue())
        self.assertEqual(exit_code, 40)
        self.assertEqual(payload["error"]["code"], "BENCH_REPORT_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
