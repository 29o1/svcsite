import io
import json
import unittest

from svcsite.errors import EXIT_DEVICE, SvcSiteError
from svcsite.output import error_payload, success_payload, write_payload


class OutputTests(unittest.TestCase):
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
