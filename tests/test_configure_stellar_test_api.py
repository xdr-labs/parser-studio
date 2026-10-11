"""Security and CLI tests for local Stellar Cyber test API configuration."""

import importlib.util
import io
import json
import os
import pathlib
import stat
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "configure_stellar_test_api.py"
spec = importlib.util.spec_from_file_location("configure_stellar_test_api", SCRIPT)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


class StellarTestApiConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.path = pathlib.Path(self.tmp.name) / "parser-studio" / "stellar-test-api.json"

    def test_https_url_canonicalization(self):
        self.assertEqual(config.normalize_dp_url("https://dp.example.test/"), "https://dp.example.test")
        self.assertEqual(
            config.normalize_dp_url("https://dp.example.test:8443/connect/api/v1/"),
            "https://dp.example.test:8443",
        )

    def test_reject_unsafe_url_components(self):
        for url in (
            "http://dp.example.test",
            "https://user:password@dp.example.test",
            "https://dp.example.test/?key=secret",
            "https://dp.example.test/#fragment",
            "https://dp.example.test/other",
            "file:///etc/passwd",
            "https://dp.example.test\\evil",
            "https://",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                config.normalize_dp_url(url)

    def test_persistent_permissions_and_expected_schema(self):
        saved = config.save_config(
            "https://dp.example.test", "a-test-tenant", "test-only-api-token", self.path
        )
        self.assertEqual(saved, self.path)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(
            json.loads(self.path.read_text(encoding="utf-8")),
            {
                "dp_url": "https://dp.example.test",
                "cust_id": "a-test-tenant",
                "api_key": "test-only-api-token",
            },
        )

    def test_no_secret_printed_on_configure_or_status(self):
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch("sys.stdin.isatty", return_value=True),
            mock.patch("builtins.input", side_effect=["https://dp.example.test", "tenant-A"]),
            mock.patch.object(config.getpass, "getpass", return_value="do-not-log-this-secret"),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            self.assertEqual(config.main([]), 0)
            self.assertEqual(config.main(["--status"]), 0)
        self.assertIn("저장", out.getvalue())
        self.assertNotIn("do-not-log-this-secret", out.getvalue() + err.getvalue())

    def test_requires_interactive_terminal_before_reading_secret(self):
        with mock.patch("sys.stdin.isatty", return_value=False):
            self.assertNotEqual(config.main([]), 0)
        self.assertFalse(self.path.exists())

    def test_does_not_replace_existing_credentials_without_confirmation(self):
        config.save_config("https://one.example.test", "tenant", "original-key", self.path)
        with (
            mock.patch("sys.stdin.isatty", return_value=True),
            mock.patch("builtins.input", side_effect=["n"]),
        ):
            self.assertNotEqual(config.main([]), 0)
        self.assertEqual(json.loads(self.path.read_text())["api_key"], "original-key")

    def test_can_rotate_credentials_after_confirmation(self):
        config.save_config("https://one.example.test", "tenant", "original-key", self.path)
        with (
            mock.patch("sys.stdin.isatty", return_value=True),
            mock.patch("builtins.input", side_effect=["y", "https://two.example.test", "other"]),
            mock.patch.object(config.getpass, "getpass", return_value="replacement-key"),
        ):
            self.assertEqual(config.main([]), 0)
        self.assertEqual(json.loads(self.path.read_text())["api_key"], "replacement-key")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_rejects_symlink_for_secret_file(self):
        self.path.parent.mkdir(mode=0o700)
        destination = pathlib.Path(self.tmp.name) / "outside.json"
        destination.write_text("do-not-change")
        self.path.symlink_to(destination)
        with self.assertRaises((OSError, ValueError)):
            config.save_config("https://dp.example.test", "tenant", "token", self.path)
        self.assertEqual(destination.read_text(), "do-not-change")

    def test_rejects_insecure_existing_directory(self):
        self.path.parent.mkdir(mode=0o755)
        self.path.parent.chmod(0o755)
        with self.assertRaises((OSError, ValueError)):
            config.save_config("https://dp.example.test", "tenant", "token", self.path)
        self.assertFalse(self.path.exists())

    def test_rejects_empty_secrets_and_invalid_tenant(self):
        for cust_id, key in (("", "token"), ("bad\\ntenant", "token"), ("tenant", ""), ("tenant", "  ")):
            with self.subTest(cust_id=cust_id, key=bool(key)), self.assertRaises(ValueError):
                config.save_config("https://dp.example.test", cust_id, key, self.path)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
