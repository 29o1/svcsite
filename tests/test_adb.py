import unittest
from unittest.mock import patch

from z9mon.adb import (
    AdbClient,
    parse_adb_devices,
    parse_package_uid,
    parse_uid_processes,
)


class ParsePackageUidTests(unittest.TestCase):
    def test_reads_single_uid(self) -> None:
        self.assertEqual(
            parse_package_uid("package:io.target uid:10300\n", "io.target"),
            10300,
        )

    def test_multi_user_install_returns_primary_uid(self) -> None:
        output = "package:com.real.app uid:10294,1010294,1410294\n"

        self.assertEqual(parse_package_uid(output, "com.real.app"), 10294)

    def test_prefix_package_does_not_match(self) -> None:
        output = "package:com.real.app.extra uid:10294\n"

        self.assertIsNone(parse_package_uid(output, "com.real.app"))


class ParseAdbDevicesTests(unittest.TestCase):
    def test_parses_ready_and_unavailable_devices(self) -> None:
        output = """List of devices attached
SERIAL_A\tdevice product:oriole
SERIAL_B\tunauthorized

"""
        self.assertEqual(
            parse_adb_devices(output),
            {"SERIAL_A": "device", "SERIAL_B": "unauthorized"},
        )

    def test_ignores_daemon_messages_and_blank_lines(self) -> None:
        output = """* daemon started successfully
List of devices attached

"""
        self.assertEqual(parse_adb_devices(output), {})

    @patch("z9mon.adb.subprocess.run")
    def test_root_command_is_sent_over_stdin(self, run_mock) -> None:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = ""
        client = AdbClient(serial="SERIAL", executable="/usr/bin/true")

        client.root_shell("kpatch test-secret kpm ctl0 module status")

        command = run_mock.call_args.args[0]
        input_text = run_mock.call_args.kwargs["input"]
        self.assertNotIn("test-secret", " ".join(command))
        self.assertIn("test-secret", input_text)

    def test_filters_processes_by_numeric_uid(self) -> None:
        processes = parse_uid_processes(
            "  PID UID NAME\n101 10300 io.target\n102 10300 io.target:remote\n103 1000 system_server\n",
            10300,
        )

        self.assertEqual([process.pid for process in processes], [101, 102])
        self.assertEqual(processes[1].name, "io.target:remote")


if __name__ == "__main__":
    unittest.main()
