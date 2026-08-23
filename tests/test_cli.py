import io
import json
from contextlib import redirect_stdout
import unittest

from z9mon.cli import main


class CliTests(unittest.TestCase):
    def test_removed_query_mode_is_a_one_line_usage_error(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(["query", "/missing", "--mode", "stats", "--json"])

        self.assertEqual(stream.getvalue().count("\n"), 1)
        payload = json.loads(stream.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["error"]["code"], "USAGE_ERROR")

    def test_usage_error_is_json(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(["doctor", "--timeout", "0", "--json"])

        payload = json.loads(stream.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["operation"], "doctor")
        self.assertEqual(payload["error"]["code"], "USAGE_ERROR")

    def test_capture_requires_exactly_one_target(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(
                ["capture", "--package", "io.target", "--pid", "1687", "--json"]
            )

        payload = json.loads(stream.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["error"]["code"], "USAGE_ERROR")


if __name__ == "__main__":
    unittest.main()
