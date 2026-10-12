"""Standard-library security regression tests: all secrets are synthetic."""
from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
import importlib.util
from io import StringIO
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name("configure-target.py")
spec = importlib.util.spec_from_file_location("target_configure", SOURCE)
assert spec and spec.loader
config = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = config
spec.loader.exec_module(config)

TEST_KEY = "synthetic_example_only_N3v3rUse"
TEST_URL = "https://dp-test.example.invalid"
TEST_SENSOR_IP = "192.0.2.34"


def synthetic():
    return {
        "schema": config.SCHEMA,
        "dp": {
            "url": TEST_URL,
            "tenant_id": "tenant_test_123",
            "api_key": TEST_KEY,
        },
        "sensor": {"ip": TEST_SENSOR_IP, "port": 5514, "protocol": "udp"},
        "parser": {"preferred_listener_port": 22150, "port_verified": False},
        "deployment": {"automatic_apply_enabled": False},
    }


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ps-target-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent = self.root / ".tmp"
        self.private = self.parent / "stellar-target"
        self.file = self.private / "connection.json"
        self.patchers = [
            patch.object(config, "PARENT", self.parent),
            patch.object(config, "PRIVATE_DIR", self.private),
            patch.object(config, "PROFILE_PATH", self.file),
        ]
        for p in self.patchers:
            p.start()
            self.addCleanup(p.stop)

    def test_canonical_profile_and_private_mode(self):
        profile = synthetic()
        self.assertEqual(config.validate_profile(profile), profile)
        config.save_profile(profile)
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)
        self.assertEqual(config.read_profile(), profile)
        self.assertNotIn("Bearer", self.file.read_text("utf-8"))
        self.assertFalse(profile["deployment"]["automatic_apply_enabled"])
        self.assertFalse(profile["parser"]["port_verified"])

    def test_https_and_sensor_literal_constraints(self):
        self.assertEqual(config.validate_url("https://192.168.25.41:8443"), "https://192.168.25.41:8443")
        self.assertEqual(config.validate_url("https://[2001:db8::23]:9443"), "https://[2001:db8::23]:9443")
        self.assertEqual(config.validate_sensor_ip("10.2.3.4"), "10.2.3.4")
        self.assertEqual(config.validate_sensor_ip("2001:db8::14"), "2001:db8::14")
        for bad in (
            "http://dp-test.example.invalid",
            "https://dp-test.example.invalid/base",
            "https://dp-test.example.invalid?key=secret",
            "https://dp-test.example.invalid#fragment",
            "https://user:secret@dp-test.example.invalid",
            "https://localhost", "https://evil..test",
            "https://dp-test.example.invalid:99999",
        ):
            with self.subTest(bad=bad), self.assertRaises(config.ProfileError):
                config.validate_url(bad)
        for bad in ("localhost", "127.0.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::3"):
            with self.subTest(bad=bad), self.assertRaises(config.ProfileError):
                config.validate_sensor_ip(bad)

    def test_unknown_fields_rejected_and_deployment_always_off(self):
        base = synthetic()
        for mutation in (
            lambda x: x["dp"].update({"access_token": "PRIVATE_JWT"}),
            lambda x: x["dp"].update({"api_key": "synthetic\nkey"}),
            lambda x: x["dp"].update({"tenant_id": "../other"}),
            lambda x: x["sensor"].update({"port": 65536}),
            lambda x: x["sensor"].update({"protocol": "http"}),
            lambda x: x["parser"].update({"preferred_listener_port": 80}),
            lambda x: x["parser"].update({"port_verified": True}),
            lambda x: x["deployment"].update({"automatic_apply_enabled": True}),
            lambda x: x.update({"unrecognized_key": "VALUE"}),
        ):
            with self.subTest(mutation=str(mutation)):
                import copy
                broken = copy.deepcopy(base)
                mutation(broken)
                with self.assertRaises(config.ProfileError):
                    config.validate_profile(broken)

    def test_existing_profile_requires_intentional_replace(self):
        first = synthetic()
        config.save_profile(first)
        original_bytes = self.file.read_bytes()
        with self.assertRaisesRegex(config.ProfileError, "EXISTING_PROFILE_REQUIRES_CONFIRMATION"):
            config.save_profile(first)
        self.assertEqual(self.file.read_bytes(), original_bytes)
        replacement = synthetic()
        replacement["sensor"]["port"] = 6514
        replacement["parser"]["preferred_listener_port"] = None
        config.save_profile(replacement, replace=True)
        self.assertEqual(config.read_profile(), replacement)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)

    def test_no_writable_directory_or_unsafe_target_file(self):
        self.parent.mkdir(mode=0o700)
        self.private.mkdir(mode=0o700)
        os.chmod(self.parent, 0o777)
        with self.assertRaisesRegex(config.ProfileError, "DIRECTORY_UNSAFE"):
            config.save_profile(synthetic())
        os.chmod(self.parent, 0o700)
        source = self.private / "source.txt"
        source.write_text("{}")
        self.file.symlink_to(source)
        with self.assertRaisesRegex(config.ProfileError, "FILE_UNSAFE"):
            config.save_profile(synthetic(), replace=True)
        self.file.unlink()
        self.file.write_text("{}")
        os.chmod(self.file, 0o644)
        with self.assertRaisesRegex(config.ProfileError, "FILE_UNSAFE"):
            config.save_profile(synthetic(), replace=True)

    def test_private_directory_symlink_rejected(self):
        self.parent.mkdir(mode=0o700)
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir(mode=0o700)
        self.private.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaisesRegex(config.ProfileError, "DIRECTORY_UNSAFE"):
            config.save_profile(synthetic())

    def test_secure_status_does_not_echo_any_secret_or_addresses(self):
        config.save_profile(synthetic())
        out = StringIO()
        with redirect_stdout(out):
            self.assertEqual(config.redacted_status(), 0)
        text = out.getvalue()
        for content in (TEST_KEY, TEST_URL, TEST_SENSOR_IP, "tenant_test_123"):
            self.assertNotIn(content, text)
        self.assertIn("PROFILE_VALID_PRIVATE", text)

    def test_prompt_requires_secret_injected_hidden_only_and_no_auto_apply(self):
        answers = iter([
            TEST_URL, "tenant_test_123", TEST_SENSOR_IP, "5514", "udp", "",
        ])
        seen = []
        def get_input(prompt):
            seen.append(prompt)
            return next(answers)
        printed = StringIO()
        with redirect_stdout(printed):
            profile = config.prompt_profile(
                input_fn=get_input,
                secret_fn=lambda _: TEST_KEY,
            )
        self.assertEqual(profile["dp"]["api_key"], TEST_KEY)
        self.assertIsNone(profile["parser"]["preferred_listener_port"])
        self.assertFalse(profile["deployment"]["automatic_apply_enabled"])
        self.assertNotIn(TEST_KEY, printed.getvalue())
        self.assertNotIn(TEST_KEY, " ".join(seen))

    def test_cli_without_tty_refuses_to_receive_secret_on_stdin(self):
        result = subprocess.run(
            [sys.executable, str(SOURCE)],
            input="INSECURE_EXAMPLE_KEY\n",
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("PROFILE_SETUP_INTERACTIVE_TTY_REQUIRED", result.stderr)
        self.assertNotIn("INSECURE_EXAMPLE_KEY", result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
