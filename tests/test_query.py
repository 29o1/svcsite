import json
from pathlib import Path
import tempfile
import unittest

from test_protocol import make_event
from svcsite.constants import MODULES_SCHEMA
from svcsite.query import run_query


class QueryTests(unittest.TestCase):
    def test_return_address_callsite_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "events.bin").write_bytes(
                make_event(
                    caller=3,
                    backtrace=(0x1000, 3, 4, 0x2000),
                )
            )

            result = run_query(
                session=str(session),
                syscalls=(),
                pid=None,
                tid=None,
                contains=None,
                limit=1,
            )

        event = result["events"][0]
        self.assertIsNone(event["registers"]["caller_callsite"])
        self.assertEqual(
            event["backtrace_callsites"],
            [None, None, "0x0", "0x1ffc"],
        )

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
                syscalls=("openat",),
                pid=None,
                tid=None,
                contains="/proc/",
                limit=1,
            )

        self.assertEqual(result["counts"]["matched"], 2)
        self.assertEqual(result["counts"]["events_returned"], 1)
        self.assertEqual(result["counts"]["events_truncated"], 1)
        self.assertEqual(result["events"][0]["syscall"]["name"], "openat")

    def test_unified_result_contains_events_and_callsites(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "events.bin").write_bytes(make_event())

            result = run_query(
                session=str(session),
                syscalls=(),
                pid=None,
                tid=None,
                contains=None,
                limit=100,
            )

        self.assertEqual(result["counts"]["matched"], 1)
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["callsites"], [])

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
        self.assertNotIn("caller_resolved", event["registers"])
        self.assertNotIn("backtrace_resolved", event)
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
                module_ids=("file:fixture",),
            )

        self.assertEqual(result["counts"]["matched"], 3)
        self.assertEqual(len(result["events"]), 3)
        self.assertGreater(result["counts"]["callsites_unique"], 0)
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
