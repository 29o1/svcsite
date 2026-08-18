"""Golden schema checks over a frozen synthetic session.

These assertions keep the agent-facing query contract stable: every mode
must keep its mandatory fields, aggregate modes must never embed event
objects, and the same frozen input must always produce the same output.
Additive fields stay allowed; removals and mode leakage fail here.
"""

import json
from pathlib import Path
import tempfile
import unittest

from test_protocol import make_event
from z9mon.constants import MODULES_SCHEMA
from z9mon.query import run_query


COMMON_KEYS = (
    "session",
    "source",
    "mode",
    "filters",
    "limit",
    "counts",
    "quality",
    "address_resolution",
)


def frozen_session(directory: Path, *, version: int = 2) -> Path:
    session = Path(directory, "session")
    session.mkdir()
    (session / "events.bin").write_bytes(
        make_event(seq=1, tgid=100, version=version)
        + make_event(seq=2, nr=63, tgid=100, desc=b"ordinary read", version=version)
        + make_event(seq=3, tgid=100, backtrace=(0x5000,), version=version)
    )
    (session / "manifest.json").write_text(
        json.dumps(
            {
                "capture": {
                    "syscalls": [
                        {"nr": 56, "name": "openat"},
                        {"nr": 63, "name": "read"},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    (session / "modules.json").write_text(
        json.dumps(
            {
                "schema_version": MODULES_SCHEMA,
                "session_id": "golden",
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
                                        "end": "0x7000",
                                        "file_offset": "0x0",
                                        "permissions": "r-xp",
                                        "path": "/data/app/libfixture.so",
                                        "module": "libfixture.so",
                                        "module_id": "file:golden:libfixture.so",
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


def query(session: Path, **overrides):
    arguments = {
        "session": str(session),
        "mode": "events",
        "syscalls": (),
        "pid": None,
        "tid": None,
        "contains": None,
        "limit": 5,
    }
    arguments.update(overrides)
    return run_query(**arguments)


class GoldenSchemaTests(unittest.TestCase):
    def test_events_mode_keeps_mandatory_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = query(frozen_session(Path(directory)))

            for key in (*COMMON_KEYS, "detail", "events"):
                self.assertIn(key, result)
            for key in ("total", "matched", "returned", "truncated"):
                self.assertIsInstance(result["counts"][key], int)
            self.assertEqual(
                sorted(result["events"][0]),
                sorted(
                    (
                        "seq",
                        "syscall",
                        "process",
                        "registers",
                        "backtrace",
                        "backtrace_callsites",
                        "backtrace_callsites_resolved",
                        "description",
                    )
                ),
            )

    def test_stats_mode_keeps_mandatory_fields_and_hides_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = query(frozen_session(Path(directory)), mode="stats", limit=10)

            for key in (*COMMON_KEYS, "stats", "module_counts"):
                self.assertIn(key, result)
            self.assertNotIn("events", result)
            for key in ("by_syscall", "by_pid", "by_module"):
                self.assertIn(key, result["stats"])
            for key in ("unique", "returned", "truncated"):
                self.assertIsInstance(result["module_counts"][key], int)

    def test_callsites_mode_keeps_mandatory_fields_and_hides_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = query(
                frozen_session(Path(directory)),
                mode="callsites",
                module_ids=("file:golden:libfixture.so",),
            )

            for key in (*COMMON_KEYS, "callsites", "callsite_counts"):
                self.assertIn(key, result)
            self.assertNotIn("events", result)
            self.assertGreater(result["callsite_counts"]["unique"], 0)
            for key in ("count", "syscall", "module_id", "module_offset", "sample"):
                self.assertIn(key, result["callsites"][0])

    def test_frozen_session_output_is_deterministic(self) -> None:
        def snapshot() -> dict:
            with tempfile.TemporaryDirectory() as directory:
                session = frozen_session(Path(directory))
                return {
                    mode: query(session, mode=mode, limit=50)
                    for mode in ("events", "stats", "callsites")
                }

        def normalize(result: dict) -> str:
            for entry in result.values():
                entry.pop("session", None)
                entry.pop("source", None)
                entry.get("address_resolution", {}).pop("source", None)
            return json.dumps(result, sort_keys=True)

        self.assertEqual(normalize(snapshot()), normalize(snapshot()))

    def test_binary_v1_session_remains_queryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = query(frozen_session(Path(directory), version=1))

            self.assertEqual(result["counts"]["total"], 3)
            self.assertEqual(len(result["events"][0]["backtrace"]), 2)
            self.assertEqual(result["quality"]["parser"]["invalid_records"], 0)


if __name__ == "__main__":
    unittest.main()
