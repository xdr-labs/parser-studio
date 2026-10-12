"""Offline contract tests for the POC-only legacy parser upload adapter.

The tests use mocked HTTP. No live POC calls or credential-file reads occur.
"""

import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

from stellar_legacy_adapter import (
    LegacyPocClient,
    LegacyUpload,
    LegacyContractError,
    LegacyApiError,
    LEGACY_CAPABILITIES,
)

NAME = "customized_ps_api_crud_test_aabbcc"
HOST = "https://poc-apac.stellarcyber.cloud"
TENANT = "test-tenant-id"


def source_file(name, text):
    raw = text.encode("utf-8")
    return {
        "name": name,
        "content": text,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def generated_pair(name=NAME, *, port=7891):
    conf = (
        "<source>\n  @type udp\n"
        f"  port {port}\n"
        f"  tag {name}\n"
        "  <parse>\n"
        f"    @type {name}\n"
        "  </parse>\n</source>\n"
        f"<match {name}.**>\n"
        "  @type rewrite_tag_filter\n</match>\n"
    )
    files = [
        source_file(name + ".conf", conf),
        source_file(name, "# STELLAR_INIT_BEGIN\n" "def parse(text)\n  yield nil, nil\nend\n"),
    ]
    return {
        "contract": "host-customized-pair.v0.1",
        "files": files,
        "manifest": {
            "status": "DRAFT", "contract": "host-customized-pair.v0.1",
            "schemaRevision": "0.1", "targetImportVerified": False,
            "engineVerified": False,
            "fileHashes": {item["name"]: item["sha256"] for item in files},
        },
    }


class FakeResponse:
    def __init__(self, status, data):
        self.status_code = status
        self.data = data
    def json(self):
        return self.data


class FakeHttpSession:
    def __init__(self, *, create=200, update=200, delete=200, port_taken=False):
        self.status = {"POST": create, "PUT": update, "DELETE": delete}
        self.calls = []
        self.version = None
        self.created = False
        self.port_taken = port_taken
        self.initial_name = "other_custom_parser"
    def post(self, url, **kwargs):
        if url.endswith("/access_token"):
            self.calls.append(("AUTH", url))
            assert kwargs["headers"]["Authorization"] == "Bearer user-test-key"
            return FakeResponse(200, {"access_token": "jwt-test-value"})
        self.calls.append(("CREATE", url))
        assert kwargs["headers"]["Authorization"] == "Bearer jwt-test-value"
        assert kwargs["data"] == {
            "cust_id": TENANT, "parser_name": NAME, "version": "1.0.0",
        }
        files = kwargs["files"]
        assert [x[0] for x in files] == ["file", "file"]
        assert [x[1][0] for x in files] == [NAME, NAME + ".conf"]
        assert files[0][1][1].startswith(b"# STELLAR_INIT_BEGIN")
        assert b"port 7891" in files[1][1][1]
        if self.status["POST"] == 200:
            self.created = True
            self.version = "1.0.0"
        return FakeResponse(self.status["POST"], {"message": "fake-create"})
    def get(self, url, **kwargs):
        kind = "CATALOG" if url.endswith("/parsers") else "LIST"
        self.calls.append((kind, url))
        assert kwargs["params"]["cust_id"] == TENANT
        assert kwargs["headers"]["Authorization"] == "Bearer jwt-test-value"
        if kind == "CATALOG":
            return FakeResponse(200, {"data": [
                {"port": 7891 if self.port_taken else 5523},
            ]})
        data = [{"parser_name": self.initial_name, "cust_id": TENANT}]
        if self.created:
            data.append({"parser_name": NAME, "cust_id": TENANT, "version": self.version})
        return FakeResponse(200, {"data": data})
    def put(self, url, **kwargs):
        self.calls.append(("UPDATE", url))
        assert url.endswith("/" + NAME)
        assert kwargs["data"]["version"] == "1.0.1"
        assert kwargs["data"]["cust_id"] == TENANT
        assert len(kwargs["files"]) == 2
        if self.status["PUT"] == 200:
            self.version = "1.0.1"
        return FakeResponse(self.status["PUT"], {})
    def delete(self, url, **kwargs):
        self.calls.append(("DELETE", url))
        assert url.endswith("/" + NAME)
        assert kwargs["params"]["cust_id"] == TENANT
        if self.status["DELETE"] == 200:
            self.created = False
        return FakeResponse(self.status["DELETE"], {})
    def close(self):
        pass


def make_client(session=None):
    return LegacyPocClient(
        {"host": HOST, "tenant": TENANT, "key": "user-test-key"},
        session=session or FakeHttpSession(),
    )


class LegacyAdapterTests(unittest.TestCase):
    def test_pair_contract_prepare_proves_hashes_names_and_bytes(self):
        plan = LegacyUpload.from_generated(generated_pair(), tenant=TENANT, version="1.0.0")
        self.assertEqual(plan.name, NAME)
        self.assertEqual(plan.port, 7891)
        self.assertEqual([x[1][0] for x in plan.multipart_files()], [NAME, NAME + ".conf"])
        self.assertEqual(plan.form_data(), {"cust_id": TENANT, "parser_name": NAME, "version": "1.0.0"})
        self.assertIn("DRAFT", plan.proof["readiness"])
        self.assertNotIn("STELLAR_INIT_BEGIN", repr(plan))

    def test_not_ready_vs_vendor_verified(self):
        plan = LegacyUpload.from_generated(generated_pair(), tenant=TENANT, version="1.0.0")
        self.assertFalse(plan.proof["target_import_verified"])
        self.assertFalse(LEGACY_CAPABILITIES["modular_rest_upload_verified"])
        self.assertFalse(LEGACY_CAPABILITIES["activation_api_verified"])
        self.assertTrue(LEGACY_CAPABILITIES["legacy_pair_crud_verified"])

    def test_manifest_hashes_and_contract_consistency_required(self):
        for mutate in (
            lambda data: data["manifest"]["fileHashes"].update({NAME: "a" * 64}),
            lambda data: data["manifest"].pop("fileHashes"),
            lambda data: data["manifest"].update({"contract": "other-contract"}),
        ):
            data = generated_pair()
            mutate(data)
            with self.assertRaises(LegacyContractError):
                LegacyUpload.from_generated(data, tenant=TENANT, version="1.0.0")

    def test_unvalidated_direct_upload_construction_rejected(self):
        with self.assertRaises(LegacyContractError):
            LegacyUpload(
                name=NAME, tenant=TENANT, version="1.0.0", port=7891,
                parser_bytes=b"", conf_bytes=b"garbage",
                parser_hash="a" * 64, conf_hash="b" * 64,
            )

    def test_backend_slug_restrictions_are_preserved(self):
        for name in ("customized_Aname", "customized_x", "customized_" + "a" * 50):
            data = generated_pair(name)
            with self.subTest(name=name), self.assertRaises(LegacyContractError):
                LegacyUpload.from_generated(data, tenant=TENANT, version="1.0.0")

    def test_wrong_sha_or_byte_count_rejected(self):
        broken = generated_pair()
        broken["files"][0]["sha256"] = "a" * 64
        with self.assertRaises(LegacyContractError):
            LegacyUpload.from_generated(broken, tenant=TENANT, version="1.0.0")
        broken = generated_pair()
        broken["files"][1]["bytes"] += 1
        with self.assertRaises(LegacyContractError):
            LegacyUpload.from_generated(broken, tenant=TENANT, version="1.0.0")

    def test_missing_extra_and_wrong_pair_names_rejected(self):
        for bad in (
            lambda p: p["files"].pop(1),
            lambda p: p["files"].append(source_file("other", "test")),
            lambda p: p["files"][0].update(name=NAME + ".json"),
            lambda p: p["files"][0].update(name="../../inject"),
        ):
            data = generated_pair()
            bad(data)
            with self.subTest(files=[x["name"] for x in data["files"]]), self.assertRaises(LegacyContractError):
                LegacyUpload.from_generated(data, tenant=TENANT, version="1.0.0")

    def test_conflicting_ports_and_missing_source_rejected(self):
        for conf in (
            "<source>\n  @type udp\n  port 7891\n  port 7892\n</source>\n",
            "# no sources\n",
            "<source>\n  @type udp\n  port abc\n</source>\n",
        ):
            data = generated_pair()
            data["files"][0] = source_file(NAME + ".conf", conf)
            with self.subTest(conf=conf), self.assertRaises(LegacyContractError):
                LegacyUpload.from_generated(data, tenant=TENANT, version="1.0.0")

    def test_conf_tenant_conflict_fails_closed(self):
        data = generated_pair()
        conf = data["files"][0]["content"] + "  cust_id different-tenant\n"
        data["files"][0] = source_file(NAME + ".conf", conf)
        with self.assertRaises(LegacyContractError):
            LegacyUpload.from_generated(data, tenant=TENANT, version="1.0.0")

    def test_non_poc_host_rejected(self):
        with self.assertRaises(LegacyContractError):
            LegacyPocClient({"host": "https://example.org", "tenant": TENANT, "key": "key"})

    def test_mutations_require_explicit_confirmation(self):
        session = FakeHttpSession()
        client = make_client(session)
        plan = LegacyUpload.from_generated(generated_pair(), tenant=TENANT, version="1.0.0")
        with self.assertRaises(LegacyContractError):
            client.create(plan)
        self.assertEqual(session.calls, [])

    def test_safe_create_update_delete_http_and_readback(self):
        session = FakeHttpSession()
        client = make_client(session)
        original = LegacyUpload.from_generated(generated_pair(), tenant=TENANT, version="1.0.0")
        modified = LegacyUpload.from_generated(generated_pair(), tenant=TENANT, version="1.0.1")
        created = client.create(original, confirmed=True)
        self.assertTrue(created["verified"])
        self.assertEqual(created["http"], 200)
        changed = client.update(modified, expected_version="1.0.0", confirmed=True)
        self.assertTrue(changed["verified"])
        deleted = client.delete(NAME, expected_version="1.0.1", confirmed=True)
        self.assertTrue(deleted["verified"])
        self.assertEqual(sum(x[0] == "CREATE" for x in session.calls), 1)
        self.assertEqual(sum(x[0] == "UPDATE" for x in session.calls), 1)
        self.assertEqual(sum(x[0] == "DELETE" for x in session.calls), 1)
        self.assertEqual(sum(x[0] == "AUTH" for x in session.calls), 1)
        self.assertNotIn("user-test-key", repr(created) + repr(changed) + repr(deleted))
        self.assertNotIn("jwt-test-value", repr(created) + repr(changed) + repr(deleted))

    def test_port_collision_fails_before_create(self):
        s = FakeHttpSession(port_taken=True)
        client = make_client(s)
        plan = LegacyUpload.from_generated(generated_pair(), tenant=TENANT, version="1.0.0")
        with self.assertRaises(LegacyContractError):
            client.create(plan, confirmed=True)
        self.assertFalse(any(x[0] == "CREATE" for x in s.calls))

    def test_version_conflict_fails_before_update_delete(self):
        s = FakeHttpSession()
        client = make_client(s)
        plan = LegacyUpload.from_generated(generated_pair(), tenant=TENANT, version="1.0.0")
        client.create(plan, confirmed=True)
        with self.assertRaises(LegacyContractError):
            client.update(plan, expected_version="7.7.7", confirmed=True)
        with self.assertRaises(LegacyContractError):
            client.delete(NAME, expected_version="7.7.7", confirmed=True)
        self.assertNotIn("UPDATE", [x[0] for x in s.calls])
        self.assertNotIn("DELETE", [x[0] for x in s.calls])

    def test_cannot_modify_existing_non_test_parser(self):
        client = make_client(FakeHttpSession())
        with self.assertRaises(LegacyContractError):
            client.delete("existing_parser", expected_version="1.0.0", confirmed=True)

    def test_rejected_upload_is_not_success(self):
        s = FakeHttpSession(create=422)
        client = make_client(s)
        plan = LegacyUpload.from_generated(generated_pair(), tenant=TENANT, version="1.0.0")
        with self.assertRaises(LegacyApiError) as caught:
            client.create(plan, confirmed=True)
        self.assertEqual(caught.exception.status, 422)
        self.assertNotIn("fake-create", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
