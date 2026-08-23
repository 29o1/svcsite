import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from svcsite.config import read_superkey
from svcsite.errors import SvcSiteError


class ReadSuperKeyTests(unittest.TestCase):
    def test_reads_0600_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_file = Path(directory, "superkey")
            key_file.write_text("test-secret\n", encoding="utf-8")
            os.chmod(key_file, 0o600)

            secret = read_superkey(key_file, {})

            self.assertEqual(secret.value, "test-secret")
            self.assertEqual(secret.source, f"file:{key_file}")

    def test_rejects_group_or_other_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_file = Path(directory, "superkey")
            key_file.write_text("test-secret\n", encoding="utf-8")
            os.chmod(key_file, 0o644)

            with self.assertRaises(SvcSiteError) as context:
                read_superkey(key_file, {})

            self.assertEqual(context.exception.code, "SUPERKEY_FILE_PERMISSIONS")

    def test_uses_environment_as_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_default = Path(directory, "missing")
            with patch("svcsite.config.DEFAULT_KEY_FILE", missing_default):
                secret = read_superkey(environ={"SVCSITE_SUPERKEY": "env-secret"})

        self.assertEqual(secret.value, "env-secret")
        self.assertEqual(secret.source, "env:SVCSITE_SUPERKEY")

    def test_missing_configuration_has_stable_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_default = Path(directory, "missing")
            with patch("svcsite.config.DEFAULT_KEY_FILE", missing_default):
                with self.assertRaises(SvcSiteError) as context:
                    read_superkey(environ={})

        self.assertEqual(context.exception.code, "SUPERKEY_NOT_CONFIGURED")
if __name__ == "__main__":
    unittest.main()
