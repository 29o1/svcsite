import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from test_capture import capture_options
from test_protocol import make_event

from svcsite.adb import AdbClient, CommandResult, ProcessInfo
from svcsite.capture import _wait_for_drain, run_capture
from svcsite.cli import main
from svcsite.errors import EXIT_DEVICE, EXIT_ENVIRONMENT, EXIT_KPM, SvcSiteError
from svcsite.kpm import KpmController
from svcsite.query import run_query


class DrainTests(unittest.TestCase):
    def test_rejects_missing_or_malformed_status_fields(self):
        for status in (
            {},
            {"enabled": False},
            {"events_buffered": 0},
            {"enabled": 0, "events_buffered": 0},
            {"enabled": False, "events_buffered": False},
            {"enabled": False, "events_buffered": "0"},
            {"enabled": False, "events_buffered": -1},
        ):
            with self.subTest(status=status):
                controller = Mock(status=Mock(return_value=status))
                with self.assertRaises(SvcSiteError) as caught:
                    _wait_for_drain(controller, 1)
                self.assertEqual(caught.exception.code, "KPM_STATUS_INVALID")

    def test_rejects_enabled_monitor_with_empty_buffer(self):
        controller = Mock(
            status=Mock(return_value={"enabled": True, "events_buffered": 0})
        )
        with self.assertRaises(SvcSiteError) as caught:
            _wait_for_drain(controller, 1)
        self.assertEqual(caught.exception.code, "KPM_MONITORING_ENABLED")

    def test_waits_until_stopped_buffer_drains(self):
        controller = Mock()
        controller.status.side_effect = [
            {"enabled": False, "events_buffered": 3},
            {"enabled": False, "events_buffered": 0},
        ]
        with patch("svcsite.capture.time.sleep"):
            self.assertEqual(_wait_for_drain(controller, 1)["events_buffered"], 0)

    def test_timeout_preserves_last_observed_status(self):
        status = {"enabled": False, "events_buffered": 3}
        controller = Mock(status=Mock(return_value=status))
        with (
            patch("svcsite.capture.time.monotonic", side_effect=[0, 0, 2]),
            patch("svcsite.capture.time.sleep"),
            self.assertRaises(SvcSiteError) as caught,
        ):
            _wait_for_drain(controller, 1)
        self.assertEqual(caught.exception.code, "KPM_DRAIN_TIMEOUT")
        self.assertEqual(caught.exception.details["status"], status)


class CaptureLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.options = capture_options(output=str(self.root))
        self.timeline = []
        self.state = {
            "version": "1.8.0",
            "enabled": False,
            "events_buffered": 0,
            "events_dropped": 0,
        }
        self.adb = Mock(spec=AdbClient)
        self.adb.timeout = self.options.timeout
        self.adb.resolve_serial.return_value = "fixture"
        self.adb.package_uid.return_value = 10300
        self.adb.package_pids.return_value = [100]
        self.adb.processes_for_uid.return_value = [ProcessInfo(100, 10300, "io.target")]
        self.adb.read_process_maps.side_effect = self.read_maps
        self.adb.shell.return_value = CommandResult(0, "fixture\n", "")
        self.adb.pull.side_effect = self.pull
        self.controller = Mock(spec=KpmController)
        self.controller.status.side_effect = lambda: dict(self.state)
        self.controller.set_nrs.return_value = {"skipped": 0}
        self.controller.start.side_effect = self.start
        self.controller.stop.side_effect = self.stop
        for name, value in (
            ("AdbClient", self.adb),
            ("KpmController", self.controller),
            ("read_superkey", SimpleNamespace(value="fixture-secret")),
        ):
            self.enterContext(patch(f"svcsite.capture.{name}", return_value=value))
        self.enterContext(patch("svcsite.capture.require_root"))
        self.now = 0.0
        self.enterContext(patch("svcsite.capture.time.monotonic", side_effect=lambda: self.now))
        self.sleep = self.enterContext(patch("svcsite.capture.time.sleep", side_effect=self.advance))

    def advance(self, seconds):
        self.now += seconds


    def start(self):
        self.timeline.append("start")
        self.state["enabled"] = True

    def stop(self):
        self.timeline.append("stop")
        self.state["enabled"] = False

    def read_maps(self, pid):
        self.timeline.append("maps")
        return "1000-7000 r-xp 00000000 103:02 1 /fixture/libsample.so\n"

    def pull(self, remote, local):
        self.timeline.append("pull")
        Path(local).write_bytes(make_event(tgid=100, uid=10300))

    def read_manifest(self):
        manifests = list(self.root.glob("*/manifest.json"))
        self.assertEqual(len(manifests), 1)
        text = manifests[0].read_text()
        self.assertNotIn("fixture-secret", text)
        return json.loads(text)

    def assert_failure(self, code, phase, **overrides):
        options = capture_options(output=str(self.root), **overrides)
        with self.assertRaises(SvcSiteError) as caught:
            run_capture(options)
        self.assertEqual(caught.exception.code, code)
        self.assertTrue(Path(caught.exception.details["manifest"]).is_absolute())
        manifest = self.read_manifest()
        self.assertEqual(manifest["status"], "failed")
        self.assertIn({"code": code, "phase": phase}, manifest["failures"])
        return manifest

    def test_capture_stops_after_both_maps_snapshots_and_returns_queryable_events(self):
        result = run_capture(self.options)
        manifest = self.read_manifest()
        self.assertEqual(
            self.timeline, ["stop", "start", "maps", "maps", "stop", "pull"]
        )
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["failures"], [])
        self.assertFalse(manifest["module"]["final_status"]["enabled"])
        self.assertEqual(manifest["module"]["final_status"]["events_buffered"], 0)
        query = run_query(
            session=result["session"],
            syscalls=(),
            pid=None,
            tid=None,
            contains=None,
            limit=1,
        )
        self.assertEqual(query["counts"]["total"], 1)
        self.assertTrue(query["address_resolution"]["available"])

    def test_poll_captures_process_that_exits_before_final_snapshot(self):
        parent = ProcessInfo(100, 10300, "io.target")
        child = ProcessInfo(101, 10300, "io.target:child")
        self.adb.processes_for_uid.side_effect = [[parent], [parent, child], [parent]]
        result = run_capture(self.options)
        manifest = self.read_manifest()
        self.assertEqual(manifest["target"]["mapped_pids"], [100, 101])
        self.assertTrue((Path(result["session"]) / "maps/post-launch-poll-000001-101.maps").is_file())
        self.assertEqual([c.args[0] for c in self.adb.read_process_maps.call_args_list], [100, 101, 100])
        self.assertEqual(self.adb.timeout, self.options.timeout)

    def test_poll_timeout_remains_optional_and_restores_adb_timeout(self):
        self.adb.processes_for_uid.side_effect = [
            [ProcessInfo(100, 10300, "io.target")],
            SvcSiteError("ADB_TIMEOUT", "fixture", EXIT_ENVIRONMENT),
            [ProcessInfo(100, 10300, "io.target")],
        ]
        result = run_capture(self.options)
        self.assertEqual(self.read_manifest()["status"], "complete")
        self.assertEqual(self.adb.timeout, self.options.timeout)
        self.assertIn("ADB_TIMEOUT", {w["code"] for w in result["warnings"]})
        self.assertFalse(self.state["enabled"])

    def test_metadata_timeout_is_a_warning_and_manifest_is_saved(self):
        self.adb.shell.side_effect = SvcSiteError(
            "ADB_TIMEOUT", "fixture", EXIT_ENVIRONMENT
        )
        result = run_capture(self.options)
        manifest = self.read_manifest()
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(result["summary"]["event_count"], 1)
        self.assertEqual(
            {w["field"] for w in result["warnings"]},
            {"model", "android_version", "abi", "kernel_release"},
        )
        self.assertTrue(all(w["code"] == "ADB_TIMEOUT" for w in result["warnings"]))

    def test_nonzero_metadata_exit_is_a_warning(self):
        self.adb.shell.return_value = CommandResult(1, "", "fixture-secret")
        result = run_capture(self.options)
        self.assertEqual(self.read_manifest()["device"]["model"], "")
        self.assertTrue(
            all(w["code"] == "DEVICE_METADATA_FAILED" for w in result["warnings"])
        )

    def test_maps_failure_preserves_syscall_evidence(self):
        self.adb.read_process_maps.side_effect = SvcSiteError(
            "MAPS_READ_FAILED", "fixture", EXIT_DEVICE
        )
        result = run_capture(self.options)
        self.assertEqual(result["summary"]["event_count"], 1)
        self.assertEqual(self.read_manifest()["status"], "complete")
        self.assertIn("MAPS_READ_FAILED", {w["code"] for w in result["warnings"]})

    def test_interrupt_during_capture_keeps_existing_partial_success_contract(self):
        def sleep(seconds):
            if seconds == 0.5:
                raise KeyboardInterrupt
            self.advance(seconds)

        self.sleep.side_effect = sleep
        result = run_capture(self.options)
        self.assertEqual(self.read_manifest()["status"], "interrupted")
        self.assertEqual(result["summary"]["event_count"], 1)
        self.assertEqual(self.controller.stop.call_count, 2)

    def test_start_failure_still_stops_and_saves_evidence(self):
        def start():
            self.start()
            raise SvcSiteError("KPM_COMMAND_FAILED", "fixture", EXIT_KPM)

        self.controller.start.side_effect = start
        manifest = self.assert_failure("KPM_COMMAND_FAILED", "monitor-start")
        self.assertEqual(self.controller.stop.call_count, 2)
        self.assertFalse(manifest["module"]["final_status"]["enabled"])
        self.assertEqual(manifest["summary"]["event_count"], 1)

    def test_target_lookup_failure_records_its_phase_and_stops(self):
        self.adb.package_pids.side_effect = SvcSiteError(
            "PID_LOOKUP_FAILED", "fixture", EXIT_DEVICE
        )
        manifest = self.assert_failure("PID_LOOKUP_FAILED", "target-lookup")
        self.assertEqual(self.controller.stop.call_count, 2)
        self.assertFalse(manifest["module"]["final_status"]["enabled"])

    def test_interrupt_outside_wait_saves_failed_session(self):
        self.adb.read_process_maps.side_effect = KeyboardInterrupt
        manifest = self.assert_failure("INTERRUPTED", "post-launch-maps")
        self.assertFalse(manifest["module"]["final_status"]["enabled"])
        self.assertEqual(manifest["summary"]["event_count"], 1)

    def test_launch_error_survives_cleanup_error(self):
        self.adb.launch_package.side_effect = SvcSiteError(
            "APP_LAUNCH_FAILED", "fixture", EXIT_DEVICE
        )

        def stop():
            if self.controller.stop.call_count == 2:
                raise SvcSiteError("KPM_COMMAND_FAILED", "fixture", EXIT_KPM)
            self.stop()

        self.controller.stop.side_effect = stop
        manifest = self.assert_failure(
            "APP_LAUNCH_FAILED", "target-launch", target_mode="launch"
        )
        self.assertIn(
            {"code": "KPM_COMMAND_FAILED", "phase": "final-stop"}, manifest["failures"]
        )
        self.assertTrue(manifest["module"]["final_status"]["enabled"])
        self.assertEqual(manifest["summary"]["event_count"], 1)

    def test_initial_drain_failure_does_not_pull_previous_session_events(self):
        self.state.pop("events_buffered")
        manifest = self.assert_failure("KPM_STATUS_INVALID", "initial-drain")
        self.adb.truncate_root_file.assert_not_called()
        self.adb.pull.assert_not_called()
        self.assertIsNone(manifest["artifacts"]["events"])

    def test_final_enabled_status_is_not_reported_as_success(self):
        def stop():
            if self.controller.stop.call_count == 1:
                self.stop()

        self.controller.stop.side_effect = stop
        manifest = self.assert_failure("KPM_MONITORING_ENABLED", "final-drain")
        self.assertTrue(manifest["module"]["final_status"]["enabled"])
        self.assertEqual(manifest["summary"]["event_count"], 1)

    def test_unavailable_final_status_is_unknown_not_initial_state(self):
        def stop():
            if self.controller.stop.call_count == 2:
                self.controller.status.side_effect = SvcSiteError(
                    "ADB_TIMEOUT", "fixture", EXIT_ENVIRONMENT
                )
                raise SvcSiteError("KPM_COMMAND_FAILED", "fixture", EXIT_KPM)
            self.stop()

        self.controller.stop.side_effect = stop
        manifest = self.assert_failure("KPM_COMMAND_FAILED", "final-stop")
        self.assertIsNone(manifest["module"]["final_status"])
        self.assertIsNone(manifest["summary"]["kernel_dropped"])

    def test_final_drain_timeout_still_saves_evidence(self):
        def stop():
            self.stop()
            if self.controller.stop.call_count == 2:
                self.state["events_buffered"] = 3

        self.controller.stop.side_effect = stop
        timeout = SvcSiteError("KPM_DRAIN_TIMEOUT", "fixture", EXIT_KPM)
        with patch(
            "svcsite.capture._wait_for_drain", side_effect=[dict(self.state), timeout]
        ):
            manifest = self.assert_failure("KPM_DRAIN_TIMEOUT", "final-drain")
        self.assertEqual(manifest["module"]["final_status"]["events_buffered"], 3)
        self.assertEqual(manifest["summary"]["event_count"], 1)

    def test_failed_pull_keeps_partial_file_and_parser_quality(self):
        def pull(remote, local):
            Path(local).write_bytes(make_event() + make_event(seq=2)[:20])
            raise SvcSiteError("ADB_PULL_FAILED", "fixture", EXIT_ENVIRONMENT)

        self.adb.pull.side_effect = pull
        manifest = self.assert_failure("ADB_PULL_FAILED", "events-pull")
        self.assertEqual(manifest["summary"]["event_count"], 1)
        self.assertEqual(manifest["summary"]["parser"]["truncated_bytes"], 20)
        self.assertTrue(Path(manifest["artifacts"]["events"]["path"]).is_file())

    def test_unexpected_capture_error_does_not_expose_exception_text(self):
        self.adb.read_process_maps.side_effect = ValueError("fixture-secret")
        manifest = self.assert_failure("INTERNAL_ERROR", "post-launch-maps")
        self.assertFalse(manifest["module"]["final_status"]["enabled"])

    def test_manifest_write_failure_preserves_events_and_has_stable_code(self):
        with (
            patch("svcsite.capture.write_json", side_effect=OSError("fixture-secret")),
            self.assertRaises(SvcSiteError) as caught,
        ):
            run_capture(self.options)
        self.assertEqual(caught.exception.code, "CAPTURE_IO_FAILED")
        self.assertEqual(
            caught.exception.details["failures"][-1]["phase"], "manifest-write"
        )
        self.assertTrue(
            (Path(caught.exception.details["session"]) / "events.bin").is_file()
        )
        self.assertNotIn("fixture-secret", str(caught.exception.details))

    def test_cli_failure_still_emits_one_json_object_with_recovery_path(self):
        self.controller.start.side_effect = SvcSiteError(
            "KPM_COMMAND_FAILED", "fixture", EXIT_KPM
        )
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(
                [
                    "capture",
                    "--package",
                    "io.target",
                    "--output",
                    str(self.root),
                    "--json",
                ]
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(output.getvalue().count("\n"), 1)
        self.assertEqual(code, EXIT_KPM)
        self.assertTrue(Path(payload["error"]["details"]["manifest"]).is_file())


if __name__ == "__main__":
    unittest.main()
