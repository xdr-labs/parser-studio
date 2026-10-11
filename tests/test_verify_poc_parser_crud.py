"""Offline contract tests for the disposable POC parser-pair CRUD lifecycle."""

import base64
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verified_pair_fixture as pair
import verify_poc_parser_crud as crud


TEST = "customized_ps_api_crud_test_aabbcc"
PROFILE = {"host": crud.APPROVED_POC_HOST, "tenant": "tenant-A", "key": "mock-only-key"}


class FakeResponse:
    def __init__(self, code, data=None):
        self.status_code = code
        self.data = data
    def json(self):
        return self.data


class FakeClient:
    def __init__(self, *, create=200, update=200, delete=200, existing=None, occupied=None):
        self.responses = {"POST": create, "PUT": update, "DELETE": delete}
        self.existing = list(existing or [])
        self.occupied = list(occupied or [5523, 6018])
        self.calls = []
        self.created = False
        self.version = None
        self.delete_attempts = 0
    def post(self, url, **kwargs):
        if url.endswith("/access_token"):
            self.calls.append("AUTH")
            assert kwargs["headers"]["Authorization"] == "Bearer mock-only-key"
            return FakeResponse(200, {"access_token": "jwt-for-test-only"})
        self.calls.append("POST")
        assert url.endswith("/custom_log_parsers")
        assert kwargs["allow_redirects"] is False
        assert kwargs["data"]["parser_name"] == TEST
        assert kwargs["data"]["cust_id"] == "tenant-A"
        assert kwargs["data"]["version"] == "1.0.0"
        files = kwargs["files"]
        assert len(files) == 2
        assert [f[1][0] for f in files] == [TEST, TEST + ".conf"]
        assert files[0][1][1].startswith(b"# STELLAR_INIT_BEGIN")
        assert b"  port 7891" in files[1][1][1]
        self.created = self.responses["POST"] == 200
        if self.created:
            self.version = "1.0.0"
        return FakeResponse(self.responses["POST"], {"message": "Validation Failed"} if not self.created else {})
    def get(self, url, **kwargs):
        self.calls.append("CATALOG" if url.endswith("/parsers") else "GET")
        assert kwargs["params"]["cust_id"] == "tenant-A"
        assert kwargs["headers"]["Authorization"] == "Bearer jwt-for-test-only"
        if url.endswith("/parsers"):
            return FakeResponse(200, {"data": [{"port": x} for x in self.occupied]})
        rows = [{"parser_name": x, "cust_id": "tenant-A"} for x in self.existing]
        if self.created:
            rows.append({"parser_name": TEST, "cust_id": "tenant-A", "version": self.version})
        return FakeResponse(200, {"data": rows})
    def put(self, url, **kwargs):
        self.calls.append("PUT")
        assert url.endswith("/" + TEST)
        assert kwargs["data"]["version"] == "1.0.1"
        if self.responses["PUT"] == 200:
            self.version = "1.0.1"
        return FakeResponse(self.responses["PUT"], {})
    def delete(self, url, **kwargs):
        self.calls.append("DELETE")
        self.delete_attempts += 1
        assert url.endswith("/" + TEST)
        assert kwargs["params"]["cust_id"] == "tenant-A"
        if self.responses["DELETE"] == 200:
            self.created = False
        return FakeResponse(self.responses["DELETE"], {})
    def close(self):
        pass


def fake_fixtures():
    p = {"receiver": {"port": 7123}, "slug": "sample_syslog"}
    encoded = base64.b64encode(json.dumps(p).encode()).decode()
    ruby = "# STELLAR_INIT_BEGIN\n" + ("@parser_rule_set=JSON.parse(Base64.strict_decode64('" + encoded + "'))\n") + "# STELLAR_PARSE_BEGIN\n"
    conf = ("<source>\n  port 7123\n  @type customized_sample_syslog\n"
            "  tag customized_sample_syslog\n</source>\n"
            "<source>\n  port 7123\n  @type customized_sample_syslog\n"
            "  tag customized_sample_syslog\n</source>\n"
            "<match customized_sample_syslog.**>\n</match>\n")
    return {pair.FIXTURE_NAME: ruby, pair.FIXTURE_NAME + ".conf": conf}


class CrudLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.src = fake_fixtures()
        self.fixture_patch = patch.object(pair, "load_verified_fixture", side_effect=lambda fn: self.src[fn])
        self.fixture_patch.start()
        self.addCleanup(self.fixture_patch.stop)

    def test_synthetic_pair_has_two_matching_names_and_updated_source(self):
        files = pair.make_host_parser_pair(TEST, 7891, "1.0.0")
        self.assertEqual([x[1][0] for x in files], [TEST, TEST + ".conf"])
        self.assertEqual(files[1][1][1].decode().count("port 7891"), 2)
        self.assertNotIn("customized_sample_syslog", files[1][1][1].decode())
        ruby = files[0][1][1].decode()
        encoded = ruby.split("Base64.strict_decode64('", 1)[1].split("')", 1)[0]
        decoded = json.loads(base64.b64decode(encoded))
        self.assertEqual(decoded["receiver"]["port"], 7891)
        self.assertEqual(decoded["slug"], "ps_api_crud_test_aabbcc")

    def test_crud_succeeds_and_deleted_name_disappears(self):
        fake = FakeClient(existing=["untouched-prod-custom-parser"])
        result = crud.run_crud(PROFILE, session=fake, test_name=TEST, port=7891)
        self.assertEqual(result["create_http"], 200)
        self.assertTrue(result["create_confirmed"])
        self.assertEqual(result["update_http"], 200)
        self.assertTrue(result["update_verified"])
        self.assertEqual(result["delete_http"], 200)
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(result["baseline_count"], 1)
        self.assertEqual(result["final_count"], 1)
        self.assertEqual(result["residual_test_parsers"], 0)
        self.assertEqual(fake.calls.count("POST"), 1)
        self.assertEqual(fake.calls.count("PUT"), 1)
        self.assertEqual(fake.calls.count("DELETE"), 1)
        self.assertEqual(fake.existing, ["untouched-prod-custom-parser"])
        self.assertNotIn("mock-only-key", str(result))

    def test_create_422_leaves_no_residue_or_update(self):
        fake = FakeClient(create=422)
        result = crud.run_crud(PROFILE, session=fake, test_name=TEST)
        self.assertEqual(result["create_error_category"], "validation_failed")
        self.assertFalse(result["create_confirmed"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertNotIn("PUT", fake.calls)
        self.assertNotIn("DELETE", fake.calls)

    def test_update_403_still_deletes_test_parser(self):
        fake = FakeClient(update=403)
        report = crud.run_crud(PROFILE, session=fake, test_name=TEST)
        self.assertEqual(report["update_http"], 403)
        self.assertFalse(report["update_verified"])
        self.assertTrue(report["cleanup_confirmed"])
        self.assertIn("DELETE", fake.calls)

    def test_existing_name_aborts_before_any_write(self):
        fake = FakeClient(existing=[TEST])
        report = crud.run_crud(PROFILE, session=fake, test_name=TEST)
        self.assertEqual(report["error_type"], "SafeAbort")
        self.assertNotIn("POST", fake.calls)
        self.assertNotIn("PUT", fake.calls)
        self.assertNotIn("DELETE", fake.calls)

    def test_port_conflict_aborts_before_write(self):
        fake = FakeClient(occupied=[7891])
        report = crud.run_crud(PROFILE, session=fake, test_name=TEST)
        self.assertEqual(report["error_type"], "SafeAbort")
        self.assertNotIn("POST", fake.calls)

    def test_non_poc_and_non_test_name_are_denied(self):
        with self.assertRaises(crud.SafeAbort):
            crud.run_crud({**PROFILE, "host": "https://prod.example.com"}, session=FakeClient())
        with self.assertRaises(crud.SafeAbort):
            crud.run_crud(PROFILE, session=FakeClient(), test_name="customized_some_existing_parser")

    def test_server_error_diagnostics_redact_details(self):
        response = FakeResponse(422, {"message": "Validation Failed", "details": [{"msg":"missing parser/conf files"}]})
        self.assertEqual(crud.safe_category(response), "missing_or_wrong_pair_names")
        self.assertEqual(crud.safe_category(FakeResponse(403, {"unknown": "some tenant secret"})), "forbidden")

    def test_dry_run_does_not_open_secret(self):
        with patch.object(crud, "load_private_profile", side_effect=AssertionError("must not read")):
            self.assertEqual(crud.main([]), 0)

    def test_temporary_delete_failure_retries_and_cleans_up(self):
        class RetryDelete(FakeClient):
            def delete(self, url, **kwargs):
                if self.delete_attempts == 0:
                    self.delete_attempts += 1
                    self.calls.append("DELETE")
                    return FakeResponse(503, {})
                return super().delete(url, **kwargs)
        fake = RetryDelete()
        report = crud.run_crud(PROFILE, session=fake, test_name=TEST)
        self.assertTrue(report["cleanup_confirmed"])
        self.assertEqual(report["delete_http"], 200)
        self.assertEqual(fake.calls.count("DELETE"), 2)


if __name__ == "__main__":
    unittest.main()
