import hashlib
from pathlib import Path
import tempfile
import unittest

from z9mon.adb import CommandResult
from z9mon.errors import Z9MonError
from z9mon.kpm import KpmController, parse_json_payload


class FakeAdb:
    def __init__(self, results: list[CommandResult]) -> None:
        self.results = list(results)
        self.commands: list[str] = []
        self.timeout = 15.0

    def root_shell(self, command: str) -> CommandResult:
        self.commands.append(command)
        return self.results.pop(0)

    def push(self, local_path, remote_path: str) -> None:
        self.commands.append(f"push {local_path} {remote_path}")


class ParseKpmPayloadTests(unittest.TestCase):
    def test_uses_last_json_object(self) -> None:
        payload = parse_json_payload(
            'diagnostic {"ok":false}\n{"ok":true,"enabled":false}\n'
        )
        self.assertEqual(payload, {"ok": True, "enabled": False})

    def test_keeps_outer_object_when_it_contains_nested_objects(self) -> None:
        payload = parse_json_payload(
            '{"ok":true,"hooks":[{"nr":56},{"nr":57}]}'
        )

        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["hooks"]), 2)

    def test_invalid_response_has_stable_error(self) -> None:
        with self.assertRaises(Z9MonError) as context:
            parse_json_payload("not-json")

        self.assertEqual(context.exception.code, "KPM_INVALID_RESPONSE")


class KpmControllerTests(unittest.TestCase):
    def test_status_locates_kpatch_and_parses_response(self) -> None:
        adb = FakeAdb(
            [
                CommandResult(0, "/data/adb/ap/bin/kpatch\n", ""),
                CommandResult(0, '{"ok":true,"enabled":false}\n', ""),
            ]
        )
        controller = KpmController(adb, "test-secret")

        payload = controller.status()

        self.assertEqual(payload["enabled"], False)
        self.assertEqual(controller.kpatch_path, "/data/adb/ap/bin/kpatch")

    def test_command_failure_redacts_superkey(self) -> None:
        adb = FakeAdb(
            [
                CommandResult(0, "/data/adb/ap/bin/kpatch\n", ""),
                CommandResult(1, "", "invalid test-secret"),
                CommandResult(0, "z9null_monitor\n", ""),
            ]
        )
        controller = KpmController(adb, "test-secret")

        with self.assertRaises(Z9MonError) as context:
            controller.status()

        self.assertEqual(context.exception.code, "KPM_COMMAND_FAILED")
        self.assertNotIn("test-secret", str(context.exception.details))
        self.assertIn("***", context.exception.details["stderr"])

    def test_missing_module_has_stable_error(self) -> None:
        adb = FakeAdb(
            [
                CommandResult(0, "/data/local/tmp/kpatch\n", ""),
                CommandResult(0, "", ""),
            ]
        )
        controller = KpmController(adb, "test-secret")

        with self.assertRaises(Z9MonError) as context:
            controller.require_loaded()

        self.assertEqual(context.exception.code, "MODULE_NOT_LOADED")
        self.assertIn("--kpm", context.exception.details["hint"])

    def test_sets_exact_pid_filter(self) -> None:
        adb = FakeAdb([CommandResult(0, '{"ok":true,"target_pid":1687}', "")])
        controller = KpmController(adb, "test-secret")
        controller.kpatch_path = "/data/local/tmp/kpatch"

        payload = controller.set_pid(1687)

        self.assertEqual(payload["target_pid"], 1687)
        self.assertIn("'pid 1687'", adb.commands[0])


class EnsureModuleTests(unittest.TestCase):
    def _kpm_file(self, directory: str) -> tuple[Path, str]:
        path = Path(directory, "z9null_monitor.kpm")
        payload = b"fixture-module-bytes"
        path.write_bytes(payload)
        return path, hashlib.sha256(payload).hexdigest()

    def test_skips_replacement_when_deployed_marker_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self._kpm_file(directory)
            adb = FakeAdb(
                [
                    CommandResult(0, "/data/local/tmp/kpatch\n", ""),
                    CommandResult(0, "z9null_monitor\n", ""),
                    CommandResult(0, digest + "\n", ""),
                ]
            )
            controller = KpmController(adb, "test-secret")

            outcome = controller.ensure_module(path)

        self.assertEqual(outcome["action"], "current")
        self.assertEqual(outcome["sha256"], digest)
        self.assertFalse(any("unload" in c for c in adb.commands))
        self.assertFalse(any("kpm load" in c for c in adb.commands))

    def test_replaces_module_when_marker_differs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self._kpm_file(directory)
            adb = FakeAdb(
                [
                    CommandResult(0, "/data/local/tmp/kpatch\n", ""),
                    CommandResult(0, "z9null_monitor\n", ""),
                    CommandResult(0, "0" * 64 + "\n", ""),
                    CommandResult(0, "z9null_monitor\n", ""),
                    CommandResult(0, "", ""),
                    CommandResult(0, "", ""),
                    CommandResult(0, "z9null_monitor\n", ""),
                    CommandResult(0, "name=z9null_monitor\nversion=1.4.0\n", ""),
                    CommandResult(0, "", ""),
                ]
            )
            controller = KpmController(adb, "test-secret")

            outcome = controller.ensure_module(path)

        self.assertEqual(outcome["action"], "replaced")
        self.assertEqual(outcome["sha256"], digest)
        self.assertTrue(outcome["marker_written"])
        self.assertTrue(any("unload" in c for c in adb.commands))
        self.assertTrue(any("kpm load" in c for c in adb.commands))
        self.assertTrue(any(digest in c for c in adb.commands))

    def test_loads_module_when_none_is_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self._kpm_file(directory)
            adb = FakeAdb(
                [
                    CommandResult(0, "/data/local/tmp/kpatch\n", ""),
                    CommandResult(0, "", ""),
                    CommandResult(0, "", ""),
                    CommandResult(0, "", ""),
                    CommandResult(0, "z9null_monitor\n", ""),
                    CommandResult(0, "name=z9null_monitor\nversion=1.4.0\n", ""),
                    CommandResult(0, "", ""),
                ]
            )
            controller = KpmController(adb, "test-secret")

            outcome = controller.ensure_module(path)

        self.assertEqual(outcome["action"], "loaded")
        self.assertFalse(any("unload" in c for c in adb.commands))

    def test_missing_kpm_file_has_stable_error(self) -> None:
        controller = KpmController(FakeAdb([]), "test-secret")

        with self.assertRaises(Z9MonError) as context:
            controller.ensure_module("/nonexistent/z9null_monitor.kpm")

        self.assertEqual(context.exception.code, "KPM_FILE_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
