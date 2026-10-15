import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from svcsite.adb import CommandResult
from svcsite.errors import SvcSiteError
from svcsite.kpm import KpmController, parse_json_payload


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
        with self.assertRaises(SvcSiteError) as context:
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
                CommandResult(0, "svcsite\n", ""),
            ]
        )
        controller = KpmController(adb, "test-secret")

        with self.assertRaises(SvcSiteError) as context:
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

        with self.assertRaises(SvcSiteError) as context:
            controller.require_loaded()

        self.assertEqual(context.exception.code, "MODULE_NOT_LOADED")
        self.assertIn("--kpm", context.exception.details["hint"])

    def test_hook_configuration_extends_timeout_and_restores_on_failure(self) -> None:
        for timeout in (15.0, 90.0):
            for fail in (False, True):
                with self.subTest(timeout=timeout, fail=fail):
                    adb = FakeAdb([])
                    adb.timeout = timeout
                    controller = KpmController(adb, "test-secret")
                    def configure(command, timeout=timeout, fail=fail, adb=adb):
                        self.assertEqual(adb.timeout, max(timeout, 60.0))
                        self.assertEqual(command, "set_nrs 65,209")
                        if fail:
                            raise OSError("fixture failure")
                        return {"ok": True}
                    with patch.object(controller, "ctl0", side_effect=configure):
                        if fail:
                            with self.assertRaises(OSError):
                                controller.set_nrs([65, 209])
                        else:
                            self.assertTrue(controller.set_nrs([65, 209])["ok"])
                    self.assertEqual(adb.timeout, timeout)

    def test_configuration_errors_keep_stable_codes_and_failed_syscall(self) -> None:
        for code in ("KPM_CONTROL_BUSY", "KPM_MONITORING_ENABLED",
                     "KPM_SYSCALL_SELECTION_INVALID", "SYSCALL_UNSUPPORTED",
                     "KPM_HOOK_INSTALL_FAILED"):
            with self.subTest(code=code):
                adb = FakeAdb([CommandResult(0, '{"ok":false,"code":"'+code+'","nr":65}', "")])
                controller = KpmController(adb, "test-secret")
                controller.kpatch_path = "/data/local/tmp/kpatch"
                with self.assertRaises(SvcSiteError) as error:
                    controller.set_nrs([65])
                self.assertEqual(error.exception.code, code)
                self.assertEqual(error.exception.details, {"syscall_nr": 65})
                self.assertEqual(adb.timeout, 15.0)

    def test_sets_exact_pid_filter(self) -> None:
        adb = FakeAdb([CommandResult(0, '{"ok":true,"target_pid":1687}', "")])
        controller = KpmController(adb, "test-secret")
        controller.kpatch_path = "/data/local/tmp/kpatch"

        payload = controller.set_pid(1687)

        self.assertEqual(payload["target_pid"], 1687)
        self.assertIn("'pid 1687'", adb.commands[0])


class EnsureModuleTests(unittest.TestCase):
    def _kpm_file(self, directory: str) -> tuple[Path, str]:
        path = Path(directory, "svcsite.kpm")
        payload = b"fixture-module-bytes"
        path.write_bytes(payload)
        return path, hashlib.sha256(payload).hexdigest()

    def test_skips_replacement_when_deployed_marker_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self._kpm_file(directory)
            adb = FakeAdb(
                [
                    CommandResult(0, "/data/local/tmp/kpatch\n", ""),
                    CommandResult(0, "svcsite\n", ""),
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
                    CommandResult(0, "svcsite\n", ""),
                    CommandResult(0, "0" * 64 + "\n", ""),
                    CommandResult(0, "svcsite\n", ""),
                    CommandResult(0, "", ""),
                    CommandResult(0, "", ""),
                    CommandResult(0, "svcsite\n", ""),
                    CommandResult(0, "name=svcsite\nversion=1.4.0\n", ""),
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
                    CommandResult(0, "svcsite\n", ""),
                    CommandResult(0, "name=svcsite\nversion=1.4.0\n", ""),
                    CommandResult(0, "", ""),
                ]
            )
            controller = KpmController(adb, "test-secret")

            outcome = controller.ensure_module(path)

        self.assertEqual(outcome["action"], "loaded")
        self.assertFalse(any("unload" in c for c in adb.commands))

    def test_migrates_legacy_module_before_loading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self._kpm_file(directory)
            adb = FakeAdb(
                [
                    CommandResult(0, "/data/local/tmp/kpatch\n", ""),
                    CommandResult(0, "z9null_monitor\n", ""),
                    CommandResult(0, "z9null_monitor\n", ""),
                    CommandResult(0, "", ""),
                    CommandResult(0, "", ""),
                    CommandResult(0, "svcsite\n", ""),
                    CommandResult(0, "name=svcsite\nversion=1.5.0\n", ""),
                    CommandResult(0, "", ""),
                ]
            )
            controller = KpmController(adb, "test-secret")

            outcome = controller.ensure_module(path)

        self.assertEqual(outcome["action"], "loaded")
        self.assertTrue(any("unload z9null_monitor" in c for c in adb.commands))
        self.assertTrue(any("kpm load" in c for c in adb.commands))

    def test_missing_kpm_file_has_stable_error(self) -> None:
        controller = KpmController(FakeAdb([]), "test-secret")

        with self.assertRaises(SvcSiteError) as context:
            controller.ensure_module("/nonexistent/svcsite.kpm")

        self.assertEqual(context.exception.code, "KPM_FILE_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
