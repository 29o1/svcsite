import unittest

from z9mon.capture import _compact_warnings, _module_supports_drain, _select_syscalls
from z9mon.errors import Z9MonError


class FakeController:
    def resolve_syscall(self, name: str) -> int | None:
        return {"write": 64, "getpid": 172}.get(name)


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

    def test_rejects_module_without_stop_and_drain(self) -> None:
        with self.assertRaises(Z9MonError) as context:
            _module_supports_drain({"version": "1.0.0"})

        self.assertEqual(context.exception.code, "MODULE_VERSION_UNSUPPORTED")

    def test_rejects_untyped_dynamic_syscall_before_capture(self) -> None:
        with self.assertRaises(Z9MonError) as context:
            _select_syscalls(FakeController(), ("getpid",))

        self.assertEqual(context.exception.code, "SYSCALL_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
