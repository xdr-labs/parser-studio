"""Standard-library security regression tests: all secrets are synthetic."""
from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
import importlib.util
from io import StringIO
import os
from pathlib import Path
import pty
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
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
ORIGINAL_HOME_PARENT = config.PARENT
ORIGINAL_PRIVATE_DIR = config.PRIVATE_DIR
ORIGINAL_PROFILE_PATH = config.PROFILE_PATH


def synthetic():
    return {
        "schema": config.SCHEMA,
        "dp": {
            "url": TEST_URL,
            "tenant_id": "tenant_test_123",
            "api_key": TEST_KEY,
        },
        "sensor": {"ip": TEST_SENSOR_IP, "port": 5514, "protocol": "udp"},
        "parser": {"preferred_listener_port": 5514, "port_verified": False},
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

    def test_default_private_target_is_outside_group_writable_git_worktree(self):
        self.assertEqual(ORIGINAL_HOME_PARENT, Path.home())
        self.assertEqual(ORIGINAL_PRIVATE_DIR.parent, Path.home())
        self.assertEqual(ORIGINAL_PRIVATE_DIR.name, ".parser-studio-secrets")
        self.assertEqual(ORIGINAL_PROFILE_PATH, ORIGINAL_PRIVATE_DIR / "connection.json")
        self.assertNotEqual(ORIGINAL_PRIVATE_DIR, config.BACKEND / ".tmp")
        with self.assertRaises(ValueError):
            ORIGINAL_PROFILE_PATH.relative_to(config.BACKEND)

    def test_group_writable_checkout_tmp_is_not_modified_by_safe_secret_setup(self):
        shared_checkout = self.root / "shared-parser-checkout"
        shared_tmp = shared_checkout / "backend" / ".tmp"
        shared_tmp.mkdir(parents=True, mode=0o775)
        os.chmod(shared_checkout, 0o775)
        os.chmod(shared_tmp, 0o775)
        safe_private = self.root / ".parser-studio-secrets"
        safe_file = safe_private / "connection.json"
        with (
            patch.object(config, "PARENT", self.root),
            patch.object(config, "PRIVATE_DIR", safe_private),
            patch.object(config, "PROFILE_PATH", safe_file),
        ):
            config.save_profile(synthetic())
            self.assertEqual(config.read_profile(), synthetic())
            self.assertEqual(stat.S_IMODE(safe_private.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(safe_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(shared_tmp.stat().st_mode), 0o775)
        self.assertEqual(list(shared_tmp.iterdir()), [])

    def test_home_parent_mode_0750_is_allowed_but_group_writable_parent_is_not(self):
        os.chmod(self.root, 0o750)
        private = self.root / ".parser-studio-secrets"
        with (
            patch.object(config, "PARENT", self.root),
            patch.object(config, "PRIVATE_DIR", private),
            patch.object(config, "PROFILE_PATH", private / "connection.json"),
        ):
            config.save_profile(synthetic())
            self.assertEqual(config.read_profile(), synthetic())
            os.chmod(self.root, 0o770)
            with self.assertRaisesRegex(config.ProfileError, "DIRECTORY_UNSAFE"):
                config.read_profile()
        os.chmod(self.root, 0o700)

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

    def test_one_sensor_ingest_port_equals_conf_port_and_legacy_blank_stays_supported(self):
        profile = synthetic()
        self.assertEqual(profile["sensor"]["port"], profile["parser"]["preferred_listener_port"])
        changed = synthetic()
        changed["parser"]["preferred_listener_port"] = 6800
        with self.assertRaisesRegex(config.ProfileError, "SENSOR_PARSER_PORT_MISMATCH"):
            config.validate_profile(changed)
        legacy = synthetic()
        legacy["parser"]["preferred_listener_port"] = None
        self.assertEqual(config.validate_profile(legacy), legacy)
        # Existing private profiles with old optional port unset inherit
        # their sensor port; no private file is rewritten on code upgrade.
        effective = (legacy["parser"]["preferred_listener_port"]
                     if legacy["parser"]["preferred_listener_port"] is not None
                     else legacy["sensor"]["port"])
        self.assertEqual(effective, legacy["sensor"]["port"])

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
            TEST_URL, "tenant_test_123", TEST_SENSOR_IP, "5514", "udp",
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
        self.assertEqual(profile["parser"]["preferred_listener_port"], profile["sensor"]["port"])
        self.assertFalse(profile["deployment"]["automatic_apply_enabled"])
        self.assertNotIn(TEST_KEY, printed.getvalue())
        self.assertNotIn(TEST_KEY, " ".join(seen))

    def test_real_cli_interactive_tty_saves_synthetic_profile_without_api_key_echo(self):
        # Full real CLI entrypoint against a temporary HOME (never the
        # operator's actual home or their existing credentials).
        home = self.root / "synthetic-home"
        home.mkdir(mode=0o700)
        prompts = [
            (b"DP HTTPS URL", TEST_URL),
            (b"Tenant ID", "tenant_test_123"),
            (b"DP User Scope API Key", TEST_KEY),
            (b"Modular Sensor IP", TEST_SENSOR_IP),
            (b"Sensor log receiver port", "5514"),
            (b"Transport protocol", "udp"),
        ]
        pid, terminal = pty.fork()
        if pid == 0:
            os.environ["HOME"] = str(home)
            os.execv(sys.executable, [sys.executable, str(SOURCE)])
        captured = bytearray()
        all_output = bytearray()
        sent = 0
        deadline = time.monotonic() + 12
        code = None
        try:
            while time.monotonic() < deadline:
                got, _, _ = select.select([terminal], [], [], 0.1)
                if got:
                    try:
                        piece = os.read(terminal, 4096)
                    except OSError:  # Linux PTY reports EIO after child exits
                        piece = b""
                    captured.extend(piece)
                    all_output.extend(piece)
                    if len(all_output) > 20000:
                        self.fail("Interactive setup emitted unexpected large output")
                if sent < len(prompts) and prompts[sent][0] in captured:
                    os.write(terminal, (prompts[sent][1] + "\n").encode("utf-8"))
                    sent += 1
                    captured.clear()
                child, wait = os.waitpid(pid, os.WNOHANG)
                if child == pid:
                    code = os.waitstatus_to_exitcode(wait)
                    break
            self.assertIsNotNone(code, "Synthetic interactive SSH setup hung")
            self.assertEqual(code, 0, "Synthetic setup failed before collecting all prompts")
            self.assertEqual(sent, len(prompts))
            target = home / ".parser-studio-secrets" / "connection.json"
            self.assertTrue(target.is_file())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
            parsed = __import__("json").loads(target.read_text("utf-8"))
            self.assertEqual(parsed, synthetic())
            self.assertNotIn(TEST_KEY.encode("utf-8"), bytes(all_output),
                             "Hidden key must never echo anywhere in the terminal transcript")
            checked = subprocess.run(
                [sys.executable, str(SOURCE), "--check"],
                env={**os.environ, "HOME": str(home)},
                text=True, capture_output=True, timeout=10, check=False,
            )
            self.assertEqual(checked.returncode, 0)
            self.assertIn("PROFILE_VALID_PRIVATE", checked.stdout)
            for private in (TEST_KEY, TEST_URL, TEST_SENSOR_IP, "tenant_test_123"):
                self.assertNotIn(private, checked.stdout + checked.stderr)
        finally:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except ProcessLookupError:
                pass
            except ChildProcessError:
                pass
            os.close(terminal)

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
