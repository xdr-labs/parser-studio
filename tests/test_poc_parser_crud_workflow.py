"""Isolated offline tests for the owner-approved test-tenant CRUD workflow."""

import pathlib
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import test_stellar_parser_crud as crud


class FakeResponse:
    def __init__(self, code, obj):
        self.status_code = code
        self._obj = obj
        self.headers = {"content-type": "application/json"}
    def json(self):
        return self._obj


class FakeSession:
    def __init__(self, *, create_status=200, modification_status=200, deletion_status=200, existing=None, existing_ports=None, persist_update=True):
        self.create_status = create_status
        self.modification_status = modification_status
        self.deletion_status = deletion_status
        self.existing = list(existing or [])
        self.existing_ports = list(existing_ports or [])
        self.persist_update = persist_update
        self.calls = []
        self.created_name = None
        self.version = None
        self.before = list(self.existing)

    def post(self, url, **kw):
        self.calls.append(("POST", url))
        if url.endswith("/access_token"):
            return FakeResponse(200, {"access_token": "fake-jwt"})
        assert url.endswith("/custom_log_parsers")
        fields = kw["data"]
        name = fields["parser_name"]
        self.created_name = name if self.create_status == 200 else None
        self.version = fields["version"] if self.create_status == 200 else None
        self.created_file = kw["files"]
        assert fields["cust_id"] == "tenant-A"
        assert all(item[0] == "file" for item in self.created_file)
        assert len(self.created_file) == 2
        assert [x[1][0] for x in self.created_file] == [name, name + ".conf"]
        assert b"bind 127.0.0.1" in self.created_file[1][1][1]
        assert b"port 7891" in self.created_file[1][1][1]
        assert b"@type null" in self.created_file[1][1][1]
        return FakeResponse(self.create_status, {"data": {"parser_name": name}} if self.create_status == 200 else {"detail": "forbidden"})

    def get(self, url, **kw):
        self.calls.append(("GET", url))
        assert kw["params"]["cust_id"] == "tenant-A"
        if url.endswith("/custom_log_parsers/parsers"):
            return FakeResponse(200, {"data": [{"port": p} for p in self.existing_ports]})
        records = [{"parser_name": x, "cust_id": "tenant-A"} for x in self.existing]
        if self.created_name:
            records.append({"parser_name": self.created_name, "cust_id": "tenant-A", "version": self.version})
        return FakeResponse(200, {"data": records})

    def put(self, url, **kw):
        self.calls.append(("PUT", url))
        assert self.created_name
        assert url.endswith("/" + self.created_name)
        assert kw["data"]["version"] == "1.0.1"
        assert kw["data"]["cust_id"] == "tenant-A"
        if self.modification_status == 200 and self.persist_update:
            self.version = kw["data"]["version"]
        return FakeResponse(self.modification_status, {"data": {"parser_name": self.created_name}})

    def delete(self, url, **kw):
        self.calls.append(("DELETE", url))
        assert self.created_name
        assert url.endswith("/" + self.created_name)
        assert kw["params"]["cust_id"] == "tenant-A"
        if self.deletion_status == 200:
            self.created_name = None
        return FakeResponse(self.deletion_status, {"data": "ok"})

    def close(self):
        return None


class CrudTests(unittest.TestCase):
    def setUp(self):
        self.profile = {"host": "https://poc-apac.stellarcyber.cloud", "tenant": "tenant-A", "key": "mock-api-key"}

    def test_schema_only_published_modular_pipeline(self):
        p = crud.make_modular_parser("ps_api_crud_test_aabbcc", 7891, "1.0.0")
        self.assertEqual(p["parser_name"], "ps_api_crud_test_aabbcc")
        self.assertEqual([s["step_type"] for s in p["config_json"]["steps"]],
                         ["routing", "parsing", "normalization", "enrichment", "output"])
        self.assertEqual(p["config_json"]["steps"][0]["parameters"]["port"], 7891)
        self.assertIn("def _enrichment(record)", p["config_json"]["steps"][3]["parameters"]["_enrichment_fn"])

    def test_successful_crud_and_cleanup(self):
        session = FakeSession(existing=["existing_parser"])
        result = crud.run_crud(self.profile, session=session, test_name="ps_api_crud_test_aabbcc", port=7891)
        self.assertEqual(result["create_http"], 200)
        self.assertTrue(result["create_confirmed"])
        self.assertEqual(result["update_http"], 200)
        self.assertTrue(result["update_confirmed"])
        self.assertEqual(result["delete_http"], 200)
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(result["baseline_count"], result["final_count"])
        self.assertEqual(sum(call[0]=="POST" for call in session.calls), 2)  # JWT and create
        self.assertEqual(sum(call[0]=="PUT" for call in session.calls), 1)
        self.assertEqual(sum(call[0]=="DELETE" for call in session.calls), 1)
        self.assertEqual(session.before, session.existing)

    def test_denied_create_never_update_delete(self):
        session = FakeSession(create_status=403, existing=["existing_parser"])
        result = crud.run_crud(self.profile, session=session, test_name="ps_api_crud_test_aabbcc", port=7891)
        self.assertEqual(result["create_http"], 403)
        self.assertFalse(result["create_confirmed"])
        self.assertFalse(any(call[0] in ("PUT","DELETE") for call in session.calls))
        self.assertTrue(result["cleanup_confirmed"])

    def test_name_collision_fails_before_post(self):
        session = FakeSession(existing=["ps_api_crud_test_aabbcc"])
        with self.assertRaises(crud.UnsafeCrudError):
            crud.run_crud(self.profile, session=session, test_name="ps_api_crud_test_aabbcc", port=7891)
        self.assertEqual([t for t,_ in session.calls], ["POST", "GET"])

    def test_delete_is_attempted_when_update_rejected(self):
        session = FakeSession(modification_status=403)
        result = crud.run_crud(self.profile, session=session, test_name="ps_api_crud_test_aabbcc", port=7891)
        self.assertEqual(result["update_http"], 403)
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(sum(call[0]=="DELETE" for call in session.calls), 1)

    def test_failed_delete_reports_residue(self):
        session = FakeSession(deletion_status=403)
        result = crud.run_crud(self.profile, session=session, test_name="ps_api_crud_test_aabbcc", port=7891)
        self.assertEqual(result["delete_http"], 403)
        self.assertFalse(result["cleanup_confirmed"])
        self.assertEqual(result["residual_test_parsers"], 1)

    def test_reject_non_test_parser_names(self):
        for name in ("prod", "ps_api_crud_", "ps_api_crud_fake;other", "ps_api_crud_TOO_LATE"):
            with self.subTest(name=name), self.assertRaises(crud.UnsafeCrudError):
                crud.assert_test_name(name)

    def test_validate_target_poc_only(self):
        with self.assertRaises(crud.UnsafeCrudError):
            crud.validate_target({"host":"https://prod.example.com", "tenant":"tenant-A", "key":"key"})
        with self.assertRaises(crud.UnsafeCrudError):
            crud.validate_target({"host":"http://poc-apac.stellarcyber.cloud", "tenant":"tenant-A", "key":"key"})
        crud.validate_target(self.profile)

    def test_dry_run_never_opens_credential_file(self):
        with unittest.mock.patch.object(crud, "load_private_profile", side_effect=AssertionError("must not read")):
            self.assertEqual(crud.main([]), 0)

    def test_existing_parser_port_rejects_without_mutation(self):
        session = FakeSession(existing_ports=[7891])
        with self.assertRaises(crud.UnsafeCrudError):
            crud.run_crud(self.profile, session=session, test_name="ps_api_crud_test_aabbcc", port=7891)
        self.assertEqual(sum(call[0] == "POST" for call in session.calls), 1)  # JWT only
        self.assertFalse(any(call[0] in ("PUT", "DELETE") for call in session.calls))

    def test_http_success_without_persisted_version_is_not_reported_verified(self):
        session = FakeSession(persist_update=False)
        r = crud.run_crud(self.profile, session=session, test_name="ps_api_crud_test_aabbcc", port=7891)
        self.assertEqual(r["update_http"], 200)
        self.assertFalse(r["update_confirmed"])
        self.assertTrue(r["cleanup_confirmed"])

    def test_cleanup_runs_after_uncertain_post_create_read(self):
        class FlakySession(FakeSession):
            def __init__(self):
                super().__init__()
                self.parser_reads = 0

            def get(self, url, **kwargs):
                if url.endswith("/custom_log_parsers"):
                    self.parser_reads += 1
                    if self.parser_reads == 4:
                        raise crud.requests.ConnectionError("transient read failure")
                return super().get(url, **kwargs)

        session = FlakySession()
        r = crud.run_crud(self.profile, session=session, test_name="ps_api_crud_test_aabbcc", port=7891)
        self.assertEqual(r["create_http"], 200)
        self.assertEqual(r["delete_http"], 200)
        self.assertTrue(r["cleanup_confirmed"])
        self.assertIn("cleanup_precheck", r["transport_error"])

    def test_error_diagnostic_redacts_tenant_jwt_and_parser_name(self):
        text = "tenant-x jwt-secret-value ps_api_crud_test_aabbcc invalid parser/conf file"
        r = crud.safe_error_diagnostic(
            FakeResponse(422, {"message": "Validation Failed", "details": {"file": [text]}}),
            name="ps_api_crud_test_aabbcc", tenant="tenant-x", jwt="jwt-secret-value",
        )
        rendered = repr(r)
        for secret in ("tenant-x", "jwt-secret-value", "ps_api_crud_test_aabbcc"):
            self.assertNotIn(secret, rendered)
        self.assertIn("invalid parser/conf file", rendered)


if __name__ == "__main__":
    unittest.main()
