import unittest

from svcsite.capture import (
    CaptureOptions,
    _compact_warnings,
    _module_version,
    _require_module_version,
    _resolve_target,
    _select_syscalls,
    _select_target,
)
from svcsite.adb import ProcessInfo
from svcsite.errors import SvcSiteError


class FakeController:
    def resolve_syscall(self, name: str) -> int | None:
        return {"write": 64, "getpid": 172}.get(name)


class FakeAdb:
    def package_uid(self, package: str) -> int:
        return 10300

    def process(self, pid: int) -> ProcessInfo:
        return ProcessInfo(pid=pid, uid=0, name="oracle")


def capture_options(**overrides) -> CaptureOptions:
    values = {
        "device": None,
        "timeout": 15.0,
        "key_file": None,
        "package": "io.target",
        "duration": 1.0,
        "syscalls": (),
        "target_mode": "attach",
        "output": "./captures",
        "kpm": None,
        "pid": None,
    }
    values.update(overrides)
    return CaptureOptions(**values)


class CaptureSelectionTests(unittest.TestCase):
    def test_compacts_repeated_pid_map_warnings(self) -> None:
        compact = _compact_warnings(
            [
                {
                    "phase": "recovery",
                    "code": "MAPS_UNAVAILABLE",
                    "pid": 10,
                    "evidence_valid": True,
                },
                {
                    "phase": "recovery",
                    "code": "MAPS_UNAVAILABLE",
                    "pid": 11,
                    "evidence_valid": True,
                },
                {
                    "code": "TARGET_NOT_RUNNING",
                    "phase": "capture-start",
                    "evidence_valid": True,
                },
            ]
        )

        self.assertEqual(len(compact), 2)
        self.assertEqual(compact[0]["code"], "TARGET_NOT_RUNNING")
        self.assertEqual(compact[1]["code"], "MAPS_UNAVAILABLE")
        self.assertEqual(compact[1]["count"], 2)
        self.assertEqual(compact[1]["pids"], [10, 11])

    def test_reverse_basic_preset_is_deterministic(self) -> None:
        numbers, names = _select_syscalls(FakeController(), ())

        self.assertEqual(numbers[0:3], [56, 57, 63])
        self.assertEqual(names[203], "connect")

    def test_resolves_custom_supported_syscall_with_small_kpm_lookup(self) -> None:
        numbers, names = _select_syscalls(
            FakeController(),
            ("openat", "write"),
        )

        self.assertEqual(numbers, [56, 64])
        self.assertEqual(names[64], "write")

    def test_rejects_module_older_than_1_8(self) -> None:
        with self.assertRaises(SvcSiteError) as context:
            _require_module_version({"version": "1.7.0"})

        self.assertEqual(context.exception.code, "MODULE_VERSION_UNSUPPORTED")
        self.assertIn("--kpm", context.exception.message)

    def test_accepts_module_1_8_and_newer(self) -> None:
        _require_module_version({"version": "1.8.0"})
        _require_module_version({"version": "2.0.1"})

    def test_unparseable_version_counts_as_too_old(self) -> None:
        self.assertEqual(_module_version({"version": "dev"}), (0, 0))

    def test_rejects_untyped_dynamic_syscall_before_capture(self) -> None:
        with self.assertRaises(SvcSiteError) as context:
            _select_syscalls(FakeController(), ("getpid",))

        self.assertEqual(context.exception.code, "SYSCALL_UNSUPPORTED")

    def test_selects_exact_pid_target(self) -> None:
        options = capture_options(package=None, pid=1687)

        self.assertEqual(_select_target(options), ("pid", 1687))
        self.assertEqual(
            _resolve_target(FakeAdb(), "pid", 1687),
            {"kind": "pid", "pid": 1687, "uid": 0, "name": "oracle"},
        )

    def test_rejects_multiple_targets(self) -> None:
        with self.assertRaises(SvcSiteError) as context:
            _select_target(capture_options(pid=1687))

        self.assertEqual(context.exception.code, "TARGET_SELECTION_INVALID")

    def test_pid_target_rejects_launch_mode(self) -> None:
        with self.assertRaises(SvcSiteError) as context:
            _select_target(
                capture_options(package=None, pid=1687, target_mode="launch")
            )

        self.assertEqual(context.exception.code, "TARGET_MODE_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
