"""Offline contract tests for the POC-only legacy parser upload adapter.

The tests use mocked HTTP. No live POC calls or credential-file reads occur.
"""

import base64
import hashlib
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

import stellar_legacy_adapter as adapter_module
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

# Minimal test-only representation of the pinned Ruby compiler layout.
# Its hash is injected into the module allowlist ONLY for mocked tests; no
# new trusted compiler fingerprint is added to shipped production policy.
TEST_RUBY_TEMPLATE = (
    "# STELLAR_INIT_BEGIN\n"
    "require 'json'\nrequire 'base64'\n"
    "def initialize()\n"
    "  @parser_rule_set = JSON.parse(Base64.strict_decode64('__PARSER_PROJECT_B64__'))\n"
    "end\n# STELLAR_INIT_END\n"
    "# STELLAR_PARSE_BEGIN\n"
    "def parse(text)\n  yield nil, nil\nend\n"
    "# STELLAR_PARSE_END\n"
)


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
        "<source>\n  @type udp\n  bind 127.0.0.1\n"
        f"  port {port}\n"
        f"  tag {name}\n"
        "  <parse>\n"
        f"    @type {name}\n"
        "  </parse>\n</source>\n"
        f"<match {name}.**>\n"
        "  @type null\n</match>\n"
    )
    project = {
        "projectId": "synthetic-fixture", "schemaRevision": "0.1",
        "slug": name.removeprefix("customized_"), "vendor": "Synthetic",
        "receiver": {"port": port, "bindAddress": "127.0.0.1", "protocols": ["udp"]},
    }
    embedded = base64.b64encode(
        json.dumps(project, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    ruby = TEST_RUBY_TEMPLATE.replace("__PARSER_PROJECT_B64__", embedded)
    files = [
        source_file(name + ".conf", conf),
        source_file(name, ruby),
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
    def setUp(self):
        # A mock compiler template fingerprint is trusted for test execution,
        # but shipped policy only contains real pinned backend Git templates.
        mock_digest = hashlib.sha256(TEST_RUBY_TEMPLATE.encode()).hexdigest()
        patcher = patch.object(
            adapter_module, "REVIEWED_TEMPLATE_SHA256",
            adapter_module.REVIEWED_TEMPLATE_SHA256 | {mock_digest},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

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

    def test_test_only_write_requires_localhost_and_no_live_forwarding(self):
        base = generated_pair()
        source = base['files'][0]['content']
        for unsafe in (
            source.replace('bind 127.0.0.1', 'bind 0.0.0.0'),
            source.replace('bind 127.0.0.1', ''),
            source.replace('@type null', '@type rewrite_tag_filter'),
            source.replace('  @type udp', '  @type exec'),
            source.replace('  @type udp', '  @include /etc/td-agent/transport_settings.conf\n  @type udp'),
            source.replace(f'<match {NAME}.**>', '<match **>'),
            source.replace(f'tag {NAME}', 'tag unrelated'),
        ):
            data = generated_pair()
            data['files'][0] = source_file(NAME + '.conf', unsafe)
            data['manifest']['fileHashes'][NAME + '.conf'] = data['files'][0]['sha256']
            plan = LegacyUpload.from_generated(data, tenant=TENANT, version='1.0.0')
            http = FakeHttpSession()
            client = make_client(http)
            with self.subTest(config=unsafe[:100]), self.assertRaises(LegacyContractError):
                client.create(plan, confirmed=True)
            self.assertEqual(http.calls, [], 'blocked writes must not exchange JWT or call server')

    def test_test_only_write_rejects_non_reserved_ports(self):
        data = generated_pair(port=8123)
        plan = LegacyUpload.from_generated(data, tenant=TENANT, version='1.0.0')
        http = FakeHttpSession()
        with self.assertRaises(LegacyContractError):
            make_client(http).create(plan, confirmed=True)
        self.assertEqual(http.calls, [])

    def test_test_only_update_uses_same_isolation_gate(self):
        data = generated_pair()
        text = data['files'][0]['content'].replace('bind 127.0.0.1', 'bind 0.0.0.0')
        data['files'][0] = source_file(NAME + '.conf', text)
        data['manifest']['fileHashes'][NAME + '.conf'] = data['files'][0]['sha256']
        plan = LegacyUpload.from_generated(data, tenant=TENANT, version='1.0.1')
        http = FakeHttpSession()
        with self.assertRaises(LegacyContractError):
            make_client(http).update(plan, expected_version='1.0.0', confirmed=True)
        self.assertEqual(http.calls, [])

    def test_unapproved_fluentd_directives_are_rejected_before_http(self):
        safe = generated_pair()
        original = safe["files"][0]["content"]
        modifications = {
            "filter_block": original + "\n<filter **>\n  @type record_transformer\n</filter>\n",
            "source_label": original.replace("  bind 127.0.0.1", "  bind 127.0.0.1\n  @label @OUTPUT"),
            "parse_exec": original.replace(
                "  </parse>", "    @type exec\n  </parse>"
            ),
            "match_extra": original.replace("  @type null", "  @type null\n  @log_level debug"),
            "root_attribute": original + "\n  @log_level debug\n",
            "unknown_stanza": original + "\n<worker 0>\n</worker>\n",
            "extra_parse": original.replace(
                "  </parse>", "    <format>\n      @type json\n    </format>\n  </parse>"
            ),
        }
        for kind, contents in modifications.items():
            project = generated_pair()
            project["files"][0] = source_file(NAME + ".conf", contents)
            project["manifest"]["fileHashes"][NAME + ".conf"] = project["files"][0]["sha256"]
            plan = LegacyUpload.from_generated(project, tenant=TENANT, version="1.0.0")
            fake = FakeHttpSession()
            with self.subTest(kind=kind), self.assertRaises(LegacyContractError):
                make_client(fake).create(plan, confirmed=True)
            self.assertEqual(fake.calls, [], "unsafe CONF must not obtain JWT")

    def test_unsigned_ruby_never_uploads_even_with_self_consistent_hashes(self):
        for untrusted in (
            "system('unsafe')\n",
            "require 'json'\ndef parse(text)\n  yield nil,nil\nend\n",
            TEST_RUBY_TEMPLATE.replace("# STELLAR_PARSE_END", "  system('unsafe')\n# STELLAR_PARSE_END"),
        ):
            project = generated_pair()
            project["files"][1] = source_file(NAME, untrusted)
            project["manifest"]["fileHashes"][NAME] = project["files"][1]["sha256"]
            plan = LegacyUpload.from_generated(project, tenant=TENANT, version="1.0.0")
            fake = FakeHttpSession()
            with self.subTest(untrusted=untrusted[:25]), self.assertRaises(LegacyContractError):
                make_client(fake).create(plan, confirmed=True)
            self.assertEqual(fake.calls, [], "unsafe Ruby must not obtain JWT")

    def test_template_attestation_checks_embedded_ir_name_port_and_synthetic_source(self):
        for invalid in ("slug", "port", "bind", "project_id", "vendor", "protocols"):
            data = generated_pair()
            p = {
                "projectId": "synthetic-fixture", "schemaRevision": "0.1",
                "slug": NAME.removeprefix("customized_"), "vendor": "Synthetic",
                "receiver": {"port": 7891, "bindAddress": "127.0.0.1", "protocols": ["udp"]},
            }
            if invalid == "slug":
                p["slug"] = "wrong_slug"
            elif invalid == "port":
                p["receiver"]["port"] = 7892
            elif invalid == "bind":
                p["receiver"]["bindAddress"] = "0.0.0.0"
            elif invalid == "project_id":
                p["projectId"] = "unreviewed-user-upload"
            elif invalid == "vendor":
                p["vendor"] = "UnknownCompany"
            elif invalid == "protocols":
                p["receiver"]["protocols"] = ["tcp"]
            encoded = base64.b64encode(json.dumps(p).encode()).decode()
            ruby = TEST_RUBY_TEMPLATE.replace("__PARSER_PROJECT_B64__", encoded)
            data["files"][1] = source_file(NAME, ruby)
            data["manifest"]["fileHashes"][NAME] = data["files"][1]["sha256"]
            plan = LegacyUpload.from_generated(data, tenant=TENANT, version="1.0.0")
            fake = FakeHttpSession()
            with self.subTest(invalid=invalid), self.assertRaises(LegacyContractError):
                make_client(fake).create(plan, confirmed=True)
            self.assertEqual(fake.calls, [])

    def test_pinned_backend_template_fingerprints_are_explicit(self):
        # These are template fingerprints from committed backend sources, not
        # arbitrary SHA-256 values included by the uploader in a manifest.
        self.assertEqual(
            adapter_module.REVIEWED_TEMPLATE_SHA256 - {
                hashlib.sha256(TEST_RUBY_TEMPLATE.encode()).hexdigest()
            },
            {
                "e56812e5efd75ddc255e0813ecbd02f675bfb7b85928b35ff0db6b472791044e",
                "e941f631da790103cc4c53a89e2eebca2b5df470300935690ebd3450d2e4e911",
            },
        )

    def test_duplicate_json_keys_in_embedded_project_are_rejected(self):
        project = generated_pair()
        bad = '{"projectId":"synthetic-fixture","projectId":"synthetic-fixture","slug":"ps_api_crud_test_aabbcc","schemaRevision":"0.1","vendor":"Synthetic","receiver":{"port":7891,"bindAddress":"127.0.0.1","protocols":["udp"]}}'
        ruby = TEST_RUBY_TEMPLATE.replace(
            "__PARSER_PROJECT_B64__", base64.b64encode(bad.encode()).decode()
        )
        project["files"][1] = source_file(NAME, ruby)
        project["manifest"]["fileHashes"][NAME] = project["files"][1]["sha256"]
        plan = LegacyUpload.from_generated(project, tenant=TENANT, version="1.0.0")
        http = FakeHttpSession()
        with self.assertRaises(LegacyContractError):
            make_client(http).create(plan, confirmed=True)
        self.assertEqual(http.calls, [])

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

    def test_expired_jwt_read_reauthenticates_once(self):
        class ExpiredGet:
            def __init__(self):
                self.jwt_issue_count = 0
                self.get_tokens = []
            def post(self, url, **kwargs):
                assert url.endswith('/access_token')
                self.jwt_issue_count += 1
                return FakeResponse(200, {'access_token': 'jwt-' + str(self.jwt_issue_count)})
            def get(self, url, **kwargs):
                token = kwargs['headers']['Authorization']
                self.get_tokens.append(token)
                if token == 'Bearer jwt-1':
                    return FakeResponse(401, {'sensitive': 'untrusted'})
                return FakeResponse(200, {'data': []})
            def close(self):
                pass
        session = ExpiredGet()
        client = make_client(session)
        self.assertEqual(client._records('/custom_log_parsers'), [])
        self.assertEqual(session.jwt_issue_count, 2)
        self.assertEqual(session.get_tokens, ['Bearer jwt-1', 'Bearer jwt-2'])

    def test_cached_jwt_expires_after_bounded_time(self):
        class JwtWindowSession:
            def __init__(self):
                self.auth_count = 0
                self.seen = []
            def post(self, url, **kwargs):
                self.auth_count += 1
                return FakeResponse(200, {'access_token': 'jwt-' + str(self.auth_count)})
            def get(self, url, **kwargs):
                self.seen.append(kwargs['headers']['Authorization'])
                return FakeResponse(200, {'data': []})
            def close(self):
                pass
        session = JwtWindowSession()
        client = make_client(session)
        with patch.object(adapter_module.time, 'monotonic', side_effect=[1000.0, 1001.0, 1500.0, 1501.0]):
            self.assertEqual(client._records('/custom_log_parsers'), [])
            self.assertEqual(client._records('/custom_log_parsers'), [])
        self.assertEqual(session.auth_count, 2)
        self.assertEqual(session.seen, ['Bearer jwt-1', 'Bearer jwt-2'])

    def test_non_idempotent_create_never_retries_after_401(self):
        session = FakeHttpSession(create=401)
        client = make_client(session)
        plan = LegacyUpload.from_generated(generated_pair(), tenant=TENANT, version='1.0.0')
        with self.assertRaises(LegacyApiError) as caught:
            client.create(plan, confirmed=True)
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(sum(verb == 'CREATE' for verb, _ in session.calls), 1)

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
