import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from z9mon.config import read_config, read_superkey, resolve_kpm_path
from z9mon.errors import Z9MonError


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

            with self.assertRaises(Z9MonError) as context:
                read_superkey(key_file, {})

            self.assertEqual(context.exception.code, "SUPERKEY_FILE_PERMISSIONS")

    def test_uses_environment_as_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_default = Path(directory, "missing")
            with patch("z9mon.config.DEFAULT_KEY_FILE", missing_default):
                secret = read_superkey(environ={"Z9MON_SUPERKEY": "env-secret"})

        self.assertEqual(secret.value, "env-secret")
        self.assertEqual(secret.source, "env:Z9MON_SUPERKEY")

    def test_missing_configuration_has_stable_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_default = Path(directory, "missing")
            with patch("z9mon.config.DEFAULT_KEY_FILE", missing_default):
                with self.assertRaises(Z9MonError) as context:
                    read_superkey(environ={})

        self.assertEqual(context.exception.code, "SUPERKEY_NOT_CONFIGURED")


class ConfigFileTests(unittest.TestCase):
    def test_missing_config_file_is_empty(self) -> None:
        self.assertEqual(read_config(Path("/nonexistent/z9mon-config.json")), {})

    def test_invalid_json_has_stable_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_file = Path(directory, "config.json")
            config_file.write_text("{not json", encoding="utf-8")

            with self.assertRaises(Z9MonError) as context:
                read_config(config_file)

            self.assertEqual(context.exception.code, "CONFIG_INVALID")

    def test_resolves_kpm_path_from_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_file = Path(directory, "config.json")
            config_file.write_text(
                json.dumps({"kpm_path": "/tmp/z9null_monitor.kpm"}),
                encoding="utf-8",
            )

            self.assertEqual(
                resolve_kpm_path(None, config_file=config_file),
                "/tmp/z9null_monitor.kpm",
            )

    def test_explicit_kpm_flag_beats_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_file = Path(directory, "config.json")
            config_file.write_text(
                json.dumps({"kpm_path": "/tmp/from-config.kpm"}),
                encoding="utf-8",
            )

            self.assertEqual(
                resolve_kpm_path("/tmp/explicit.kpm", config_file=config_file),
                "/tmp/explicit.kpm",
            )

    def test_no_kpm_anywhere_resolves_to_none(self) -> None:
        self.assertIsNone(resolve_kpm_path(None, environ={}))


if __name__ == "__main__":
    unittest.main()
