"""Offline regression tests for the safe User Scope parser API probe."""

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
from urllib import error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_stellar_test_api as api_probe


class ApiProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / "private"
        self.base.mkdir(mode=0o700)
        self.file = self.base / "stellar-test-api.json"
        self.profile = {"dp_url": "https://example.test", "cust_id": "tenant-A", "api_key": "local-test-only-key"}

    def save_profile(self):
        self.file.write_text(json.dumps(self.profile), encoding="utf-8")
        self.file.chmod(0o600)

    def test_private_config_permissions_and_contents(self):
        self.save_profile()
        self.assertEqual(api_probe.load_private_profile(self.file), {
            "host": "https://example.test",
            "tenant": "tenant-A",
            "key": "local-test-only-key",
        })

    def test_insecure_config_file_rejected(self):
        self.save_profile()
        self.file.chmod(0o644)
        with self.assertRaises(api_probe.UnsafeProfileError):
            api_probe.load_private_profile(self.file)

    def test_insecure_config_directory_rejected(self):
        self.save_profile()
        self.base.chmod(0o755)
        with self.assertRaises(api_probe.UnsafeProfileError):
            api_probe.load_private_profile(self.file)

    def test_symlink_config_rejected(self):
        dest = Path(self.temp.name) / "other.json"
        dest.write_text("{}")
        self.file.symlink_to(dest)
        with self.assertRaises(api_probe.UnsafeProfileError):
            api_probe.load_private_profile(self.file)

    def test_invalid_profile_and_http_rejected(self):
        self.save_profile()
        for data in (
            {"dp_url": "http://example.test", "cust_id": "a", "api_key": "token"},
            {"dp_url": "https://example.test", "cust_id": "a"},
        ):
            self.file.write_text(json.dumps(data))
            with self.assertRaises(api_probe.UnsafeProfileError):
                api_probe.load_private_profile(self.file)

    def test_user_scope_bearer_exchange_and_two_tenant_scoped_gets(self):
        calls = []
        def send(method, url, token):
            calls.append((method, url, token))
            if method == "POST":
                return 200, {"access_token": "short-lived-jwt"}
            if url.endswith("/custom_log_parsers?cust_id=tenant-A"):
                return 200, {"data": [{}, {}, {}, {}]}
            if url.endswith("/custom_log_parsers/parsers?cust_id=tenant-A"):
                return 200, {"data": [1, 2, 3]}
            raise AssertionError("Unexpected API call")

        result = api_probe.probe({"host": "https://example.test", "tenant": "tenant-A", "key": "local-test-only-key"}, send=send)
        self.assertEqual(calls[0], (
            "POST", "https://example.test/connect/api/v1/access_token", "local-test-only-key"
        ))
        self.assertEqual([x[0] for x in calls[1:]], ["GET", "GET"])
        self.assertTrue(all(x[2] == "short-lived-jwt" for x in calls[1:]))
        self.assertEqual([x["count"] for x in result["endpoints"]], [4, 3])
        self.assertEqual(result["auth"], {"status": 200, "jwt_exchanged": True})
        self.assertNotIn("local-test-only-key", repr(result))
        self.assertNotIn("short-lived-jwt", repr(result))

    def test_authentication_denied_aborts_before_get(self):
        calls = []
        def send(method, url, token):
            calls.append(method)
            return 403, None
        r = api_probe.probe({"host": "https://example.test", "tenant": "tenant", "key": "secret"}, send=send)
        self.assertEqual(calls, ["POST"])
        self.assertEqual(r["auth"]["status"], 403)
        self.assertFalse(r["auth"]["jwt_exchanged"])
        self.assertEqual(r["endpoints"], [])

    def test_missing_jwt_aborts(self):
        def send(method, url, token):
            return 200, {"unexpected": "schema"}
        r = api_probe.probe({"host": "https://example.test", "tenant": "tenant", "key": "secret"}, send=send)
        self.assertFalse(r["auth"]["jwt_exchanged"])
        self.assertEqual(r["endpoints"], [])

    def test_safe_get_schema_does_not_echo_records(self):
        def send(method, url, token):
            return (200, {"access_token": "jwt-secret"}) if method == "POST" else (
                200, {"data": [{"customer_sensitive": "never-output"}]}
            )
        r = api_probe.probe({"host": "https://example.test", "tenant": "tenant", "key": "local-secret"}, send=send)
        self.assertNotIn("customer_sensitive", repr(r))
        self.assertNotIn("never-output", repr(r))
        self.assertEqual([x["count"] for x in r["endpoints"]], [1, 1])

    def test_http_client_sends_bearer_and_rejects_redirects(self):
        calls = []
        class FakeResponse(io.BytesIO):
            status = 200
        class FakeOpener:
            def open(self, req, timeout):
                calls.append((req.get_method(), req.full_url, req.get_header("Authorization"), timeout))
                return FakeResponse(b'{"data":[]}')
        self.assertEqual(api_probe.request_json(
            "GET", "https://example.test/connect/api/v1/custom_log_parsers", "jwt",
            opener=FakeOpener()), (200, {"data": []}))
        self.assertEqual(calls[0][2], "Bearer jwt")
        self.assertEqual(api_probe.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://evil.test"), None)
        with self.assertRaises(ValueError):
            api_probe.request_json("DELETE", "https://example.test/anything", "jwt", opener=FakeOpener())
        with self.assertRaises(ValueError):
            api_probe.request_json("GET", "http://example.test/anything", "jwt", opener=FakeOpener())

    def test_http_error_body_is_never_parsed_or_exposed(self):
        class FakeOpener:
            def open(self, req, timeout):
                raise error.HTTPError(req.full_url, 403, "secret body", {}, io.BytesIO(b"private"))
        code, data = api_probe.request_json(
            "GET", "https://example.test/connect/api/v1/custom_log_parsers",
            "test-token", opener=FakeOpener())
        self.assertEqual((code, data), (403, None))


if __name__ == "__main__":
    unittest.main()
