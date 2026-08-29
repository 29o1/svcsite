import io
import json
import unittest

from svcsite.errors import EXIT_DEVICE, EXIT_INTERNAL, SvcSiteError
from svcsite.output import (
    error_payload,
    execute_operation,
    success_payload,
    write_payload,
)


class OutputTests(unittest.TestCase):
    def execute(self, action) -> tuple[int, dict, str]:
        stream = io.StringIO()
        exit_code = execute_operation(
            "initial",
            compact=False,
            prepare=lambda: ("prepared", True, action),
            stream=stream,
        )
        return exit_code, json.loads(stream.getvalue()), stream.getvalue()

    def test_execute_operation_success_uses_prepared_context(self) -> None:
        exit_code, payload, rendered = self.execute(lambda: {"value": 7})

        self.assertEqual(exit_code, 0)
        self.assertEqual(rendered.count("\n"), 1)
        self.assertEqual(payload["operation"], "prepared")
        self.assertEqual(payload["data"]["value"], 7)

    def test_execute_operation_preserves_domain_error(self) -> None:
        def fail() -> dict:
            raise SvcSiteError(
                "DEVICE_NOT_FOUND",
                "device missing",
                EXIT_DEVICE,
            )

        exit_code, payload, _ = self.execute(fail)

        self.assertEqual(exit_code, EXIT_DEVICE)
        self.assertEqual(payload["operation"], "prepared")
        self.assertEqual(payload["error"]["code"], "DEVICE_NOT_FOUND")

    def test_execute_operation_normalizes_interrupt(self) -> None:
        def interrupt() -> dict:
            raise KeyboardInterrupt

        exit_code, payload, _ = self.execute(interrupt)

        self.assertEqual(exit_code, 130)
        self.assertEqual(payload["error"]["code"], "INTERRUPTED")

    def test_execute_operation_normalizes_internal_error(self) -> None:
        def fail() -> dict:
            raise ValueError("fixture")

        exit_code, payload, _ = self.execute(fail)

        self.assertEqual(exit_code, EXIT_INTERNAL)
        self.assertEqual(payload["error"]["code"], "INTERNAL_ERROR")
        self.assertEqual(payload["error"]["details"]["exception"], "ValueError")

    def test_compact_output_is_one_json_line(self) -> None:
        stream = io.StringIO()
        write_payload(success_payload("doctor", {"device": "SERIAL"}), stream, compact=True)

        rendered = stream.getvalue()
        self.assertEqual(rendered.count("\n"), 1)
        self.assertTrue(json.loads(rendered)["ok"])

    def test_error_payload_contains_stable_code(self) -> None:
        error = SvcSiteError(
            "DEVICE_NOT_FOUND",
            "device missing",
            EXIT_DEVICE,
            {"device": "SERIAL"},
        )

        payload = error_payload("doctor", error)

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "DEVICE_NOT_FOUND")

    def test_success_moves_operation_warnings_to_envelope(self) -> None:
        payload = success_payload(
            "capture",
            {"session": "/tmp/session", "warnings": ["MAPS_UNAVAILABLE"]},
        )

        self.assertEqual(payload["warnings"], ["MAPS_UNAVAILABLE"])
        self.assertNotIn("warnings", payload["data"])


if __name__ == "__main__":
    unittest.main()
