import json
from pathlib import Path
import tempfile
import unittest

from test_protocol import make_event
from z9mon.constants import MODULES_SCHEMA
from z9mon.query import run_query


class QueryTests(unittest.TestCase):
    def test_filters_and_limits_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "events.bin").write_bytes(
                make_event(seq=1, nr=56)
                + make_event(seq=2, nr=63, desc=b"ordinary read")
                + make_event(seq=3, nr=56)
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

            result = run_query(
                session=str(session),
                mode="events",
                syscalls=("openat",),
                pid=None,
                tid=None,
                contains="/proc/",
                limit=1,
            )

        self.assertEqual(result["counts"]["matched"], 2)
        self.assertEqual(result["counts"]["returned"], 1)
        self.assertEqual(result["counts"]["truncated"], 1)
        self.assertEqual(result["events"][0]["syscall"]["name"], "openat")

    def test_stats_omits_event_objects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "events.bin").write_bytes(make_event())

            result = run_query(
                session=str(session),
                mode="stats",
                syscalls=(),
                pid=None,
                tid=None,
                contains=None,
                limit=100,
            )

        self.assertEqual(result["counts"]["matched"], 1)
        self.assertNotIn("events", result)

    def test_enriches_addresses_when_modules_are_available(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "events.bin").write_bytes(make_event(tgid=100))
            (session / "modules.json").write_text(
                json.dumps(
                    {
                        "schema_version": MODULES_SCHEMA,
                        "session_id": "fixture",
                        "snapshots": [
                            {
                                "snapshot_id": "pre-stop",
                                "captured_at": "2026-07-21T00:00:00.000Z",
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

            result = run_query(
                session=str(session),
                syscalls=(),
                pid=None,
                tid=None,
                contains=None,
                limit=1,
                mode="events",
                detail="full",
            )

        event = result["events"][0]
        self.assertTrue(result["address_resolution"]["available"])
        self.assertEqual(
            event["registers"]["pc_resolved"]["module"],
            "libfixture.so",
        )
        self.assertEqual(
            event["registers"]["pc_resolved"]["module_id"],
            "file:/data/app/libfixture.so",
        )
        self.assertEqual(
            event["registers"]["caller_resolved"]["module_offset"],
            "0x1000",
        )
        self.assertEqual(event["registers"]["caller_callsite"], "0x1ffc")
        self.assertEqual(
            event["registers"]["caller_callsite_resolved"]["module_offset"],
            "0xffc",
        )
        self.assertEqual(event["backtrace_callsites"], ["0x4ffc", "0x5ffc"])
        self.assertEqual(
            event["backtrace_callsites_resolved"][0]["module_offset"],
            "0x3ffc",
        )

    def test_compact_detail_omits_duplicate_return_address_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "events.bin").write_bytes(make_event(tgid=100))
            (session / "modules.json").write_text(
                json.dumps(
                    {
                        "schema_version": MODULES_SCHEMA,
                        "session_id": "fixture",
                        "snapshots": [
                            {
                                "snapshot_id": "pre-stop",
                                "processes": [
                                    {
                                        "pid": 100,
                                        "mappings": [
                                            {
                                                "start": "0x1000",
                                                "end": "0x7000",
                                                "file_offset": "0x0",
                                                "path": "/data/app/libfixture.so",
                                                "module": "libfixture.so",
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

            result = run_query(
                session=str(session),
                syscalls=(),
                pid=None,
                tid=None,
                contains=None,
                limit=1,
                mode="events",
            )

        event = result["events"][0]
        self.assertNotIn("caller_resolved", event["registers"])
        self.assertNotIn("backtrace_resolved", event)
        self.assertEqual(
            event["backtrace_callsites_resolved"][0]["module_offset"],
            "0x3ffc",
        )
        self.assertNotIn(
            "mapping_start", event["backtrace_callsites_resolved"][0]
        )

    def test_filters_and_ranks_callsites_by_module_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "events.bin").write_bytes(
                make_event(seq=1, tgid=100)
                + make_event(seq=2, tgid=100)
                + make_event(seq=3, nr=63, tgid=100, backtrace=(0x9000,))
            )
            (session / "modules.json").write_text(
                json.dumps(
                    {
                        "schema_version": MODULES_SCHEMA,
                        "session_id": "fixture",
                        "snapshots": [
                            {
                                "snapshot_id": "pre-stop",
                                "processes": [
                                    {
                                        "pid": 100,
                                        "mappings": [
                                            {
                                                "start": "0x1000",
                                                "end": "0x7000",
                                                "file_offset": "0x0",
                                                "path": "/data/app/libfixture.so",
                                                "module": "libfixture.so",
                                                "module_id": "file:fixture",
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

            result = run_query(
                session=str(session),
                syscalls=(),
                pid=None,
                tid=None,
                contains=None,
                limit=10,
                mode="callsites",
                module_ids=("file:fixture",),
            )

        self.assertEqual(result["counts"]["matched"], 3)
        self.assertNotIn("events", result)
        self.assertGreater(result["callsite_counts"]["unique"], 0)
        self.assertEqual(result["callsites"][0]["count"], 2)
        self.assertEqual(result["callsites"][0]["module_id"], "file:fixture")

    def test_old_session_remains_queryable_without_modules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "events.bin").write_bytes(
                make_event(backtrace=(0x1000, 0x2000, 0x5000))
            )

            result = run_query(
                session=str(session),
                syscalls=(),
                pid=None,
                tid=None,
                contains=None,
                limit=1,
                mode="events",
            )

        self.assertFalse(result["address_resolution"]["available"])
        self.assertNotIn("pc_resolved", result["events"][0]["registers"])
        self.assertEqual(
            result["events"][0]["registers"]["caller_callsite"],
            "0x1ffc",
        )
        self.assertEqual(
            result["events"][0]["backtrace_callsites"],
            [None, "0x1ffc", "0x4ffc"],
        )


if __name__ == "__main__":
    unittest.main()
