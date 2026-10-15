import gc
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
import weakref

from svcsite.adb import ProcessInfo
from svcsite.constants import MODULES_SCHEMA
from svcsite.maps import ModuleIndex, capture_maps_snapshot, parse_proc_maps


MAPS_TEXT = """7000000000-7000010000 r-xp 00001000 103:02 42 /data/app/libtarget.so
7000010000-7000011000 rw-p 00000000 00:00 0 [anon:fixture]
"""


def modules_document() -> dict:
    mappings = parse_proc_maps(MAPS_TEXT)
    return {
        "schema_version": MODULES_SCHEMA,
        "session_id": "fixture",
        "snapshots": [
            {
                "snapshot_id": "post-launch",
                "captured_at": "2026-07-21T00:00:00.000Z",
                "processes": [
                    {
                        "pid": 123,
                        "uid": 10300,
                        "name": "io.target",
                        "maps_path": "/tmp/123.maps",
                        "mapping_count": len(mappings),
                        "mappings": list(mappings),
                    }
                ],
            }
        ],
    }


class ProcMapsTests(unittest.TestCase):
    def test_resolve_cache_does_not_keep_index_alive(self) -> None:
        index = ModuleIndex(Path("fixture-modules.json"), modules_document())

        self.assertIs(
            index.resolve(123, 0x7000000234),
            index.resolve(123, 0x7000000234),
        )
        reference = weakref.ref(index)
        del index
        gc.collect()

        self.assertIsNone(reference())

    def test_capture_snapshot_returns_written_pids_and_raw_maps(self) -> None:
        class FakeAdb:
            def processes_for_uid(self, uid: int) -> list[ProcessInfo]:
                return [ProcessInfo(pid=123, uid=uid, name="io.target")]

            def read_process_maps(self, pid: int) -> str:
                return MAPS_TEXT

        with tempfile.TemporaryDirectory() as directory:
            maps_dir = Path(directory, "maps")
            warnings: list[dict] = []

            captured = capture_maps_snapshot(
                FakeAdb(),
                uid=10300,
                maps_dir=maps_dir,
                snapshot_id="post-launch",
                warnings=warnings,
            )

            raw = (maps_dir / "post-launch-123.maps").read_text(encoding="utf-8")

        self.assertEqual(captured, {123})
        self.assertEqual(raw, MAPS_TEXT)
        self.assertEqual(warnings, [])

    def test_empty_snapshot_is_not_counted_as_mapped(self) -> None:
        adb = Mock()
        adb.processes_for_uid.return_value = [ProcessInfo(123, 10300, "io.target")]
        adb.read_process_maps.return_value = ""
        with tempfile.TemporaryDirectory() as directory:
            warnings = []
            captured = capture_maps_snapshot(
                adb, uid=10300, maps_dir=Path(directory),
                snapshot_id="poll", warnings=warnings,
            )
            self.assertEqual(captured, set())
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertEqual(warnings[0]["code"], "MAPS_EMPTY")

    def test_parses_module_and_anonymous_mapping(self) -> None:
        mappings = parse_proc_maps(MAPS_TEXT)

        self.assertEqual(len(mappings), 2)
        self.assertEqual(mappings[0]["module"], "libtarget.so")
        self.assertEqual(
            mappings[0]["module_id"],
            "file:103:02:42:/data/app/libtarget.so",
        )
        self.assertEqual(mappings[1]["module"], "[anon:fixture]")

    def test_resolves_runtime_address_to_module_offset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "modules.json")
            path.write_text(json.dumps(modules_document()), encoding="utf-8")
            index = ModuleIndex.from_session(Path(directory))

            resolved = index.resolve(123, 0x7000000234) if index else None

        self.assertIsNotNone(resolved)
        self.assertEqual(
            resolved,
            {
                "runtime": "0x7000000234",
                "snapshot_id": "post-launch",
                "module": "libtarget.so",
                "module_id": "file:103:02:42:/data/app/libtarget.so",
                "path": "/data/app/libtarget.so",
                "module_offset": "0x1234",
            },
        )

    def test_reads_legacy_modules_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "modules.json")
            document = modules_document()
            document["schema_version"] = "z9mon.modules.v1"
            path.write_text(json.dumps(document), encoding="utf-8")

            index = ModuleIndex.from_session(Path(directory))
            resolved = index.resolve(123, 0x7000000234) if index else None

        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["module_offset"], "0x1234")

    def test_index_builds_from_raw_maps_dir_without_modules_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            maps_dir = session / "maps"
            maps_dir.mkdir()
            (maps_dir / "post-launch-123.maps").write_text(
                MAPS_TEXT, encoding="utf-8"
            )
            (maps_dir / "pre-stop-123.maps").write_text(
                MAPS_TEXT, encoding="utf-8"
            )

            index = ModuleIndex.from_session(session)
            resolved = index.resolve(123, 0x7000000234) if index else None

        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["module_id"], "file:103:02:42:/data/app/libtarget.so")
        self.assertEqual(resolved["module_offset"], "0x1234")
        self.assertEqual(index.source, maps_dir)

    def test_later_snapshot_wins_when_pids_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            maps_dir = session / "maps"
            maps_dir.mkdir()
            (maps_dir / "post-launch-123.maps").write_text(
                MAPS_TEXT, encoding="utf-8"
            )
            (maps_dir / "pre-stop-123.maps").write_text(
                "7000000000-7000010000 r-xp 00001000 103:02 43 /data/app/other.so\n",
                encoding="utf-8",
            )

            index = ModuleIndex.from_session(session)
            resolved = index.resolve(123, 0x7000000234) if index else None

        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["module"], "other.so")
        self.assertEqual(resolved["snapshot_id"], "pre-stop")

    def test_same_basename_has_distinct_module_ids(self) -> None:
        mappings = parse_proc_maps(
            "1000-2000 r-xp 00000000 103:02 11 /data/app/one/base.apk\n"
            "3000-4000 r-xp 00000000 103:02 12 /data/app/two/base.apk\n"
        )

        self.assertEqual(
            [mapping["module"] for mapping in mappings],
            ["base.apk", "base.apk"],
        )
        self.assertNotEqual(
            mappings[0]["module_id"],
            mappings[1]["module_id"],
        )


if __name__ == "__main__":
    unittest.main()
