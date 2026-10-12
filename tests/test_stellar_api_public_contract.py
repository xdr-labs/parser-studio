"""Pure contract tests: public Swagger evidence MUST NOT authorize modular writes."""

import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import stellar_api_public_contract as contract


def method(*, multipart=None):
    item = {"security": [{"jwt": []}], "responses": {"200": {"description": "ok"}}}
    if multipart is not None:
        required = sorted(multipart)
        item["requestBody"] = {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            field: (
                                {"type": "array", "items": {"type": "string", "format": "binary"}}
                                if field == "file" else {"type": "string"}
                            ) for field in required
                        },
                        "required": required,
                    }
                }
            },
        }
    return item


def sample_spec():
    return {
        "openapi": "3.1.0",
        "paths": {
            "/custom_log_parsers": {
                "get": method(),
                "post": method(multipart=("cust_id", "parser_name", "version", "file")),
            },
            "/custom_log_parsers/{name}": {
                "put": method(multipart=("cust_id", "version", "file")),
                "delete": method(),
            },
            "/custom_log_parsers/parsers": {"get": method()},
        },
    }


class PublicContractTests(unittest.TestCase):
    def test_legacy_rest_methods_have_schema_evidence(self):
        profile = contract.classify_spec(sample_spec(), "7.0.xs")
        self.assertEqual(profile["public_legacy_methods"], {
            "GET /custom_log_parsers": "DOCUMENTED",
            "POST /custom_log_parsers": "DOCUMENTED",
            "PUT /custom_log_parsers/{name}": "DOCUMENTED",
            "DELETE /custom_log_parsers/{name}": "DOCUMENTED",
            "GET /custom_log_parsers/parsers": "DOCUMENTED",
        })
        self.assertTrue(profile["legacy_pair_multipart_schema_documented"])
        self.assertEqual(profile["unclassified_parser_routes"], [])
        self.assertEqual(profile["release_note_bulk_toggle"], "DESCRIBED_NO_PUBLIC_SCHEMA")

    def test_legacy_post_or_put_missing_binary_file_fails_closed(self):
        for op in ("post", "put"):
            spec = sample_spec()
            req = spec["paths"]["/custom_log_parsers" if op == "post" else "/custom_log_parsers/{name}"][op]["requestBody"]
            req["content"]["multipart/form-data"]["schema"]["properties"]["file"] = {"type": "string"}
            profile = contract.classify_spec(spec, "7.0.xs")
            self.assertFalse(profile["legacy_pair_multipart_schema_documented"])
            self.assertEqual(profile["public_legacy_methods"][op.upper() + (
                " /custom_log_parsers" if op == "post" else " /custom_log_parsers/{name}")],
                "SCHEMA_MISMATCH")

    def test_missing_jwt_auth_fails_closed(self):
        spec = sample_spec()
        spec["paths"]["/custom_log_parsers"]["post"]["security"] = [{"basic": []}]
        profile = contract.classify_spec(spec, "7.0.xs")
        self.assertEqual(profile["public_legacy_methods"]["POST /custom_log_parsers"], "SCHEMA_MISMATCH")
        self.assertFalse(profile["legacy_pair_multipart_schema_documented"])

    def test_modular_and_toggle_never_advertised_as_verified(self):
        spec = sample_spec()
        spec["paths"]["/private/modular-parsers/bulk"] = {"post": method()}
        profile = contract.classify_spec(spec, "7.0.xs")
        self.assertEqual(profile["modular_upload"], "NOT_VERIFIED")
        self.assertEqual(profile["activation_api"], "NOT_VERIFIED")
        self.assertEqual(profile["unclassified_parser_routes"], ["POST /private/modular-parsers/bulk"])
        with self.assertRaises(contract.UnsupportedCapability):
            contract.require_supported_operation(profile, "modular_upload")
        for action in ("enable", "disable", "bulk_disable"):
            with self.subTest(action=action), self.assertRaises(contract.UnsupportedCapability):
                contract.require_supported_operation(profile, action)

    def test_legacy_capability_requires_verified_poc_not_swagger_only(self):
        evidence = contract.classify_spec(sample_spec(), "7.0.xs")
        with self.assertRaises(contract.UnsupportedCapability):
            contract.require_supported_operation(evidence, "legacy_create")
        result = contract.require_supported_operation(
            evidence, "legacy_create",
            verified_poc_legacy=True,
            approved_test_environment=True,
        )
        self.assertEqual(result, "LEGACY_TEST_ONLY")
        with self.assertRaises(contract.UnsupportedCapability):
            contract.require_supported_operation(
                evidence, "legacy_create",
                verified_poc_legacy=True,
                approved_test_environment=False,
            )

    def test_bad_or_unknown_swagger_rejected(self):
        for bad in (
            {},
            {"openapi": "2.0", "paths": {}},
            {"openapi": "3.1.0", "paths": []},
            {"openapi": "3.1.0", "paths": {"/custom_log_parsers": None}},
        ):
            with self.subTest(bad=bad), self.assertRaises(contract.InvalidOfficialSpec):
                contract.classify_spec(bad, "7.0.xs")
        with self.assertRaises(contract.InvalidOfficialSpec):
            contract.classify_spec(sample_spec(), "7.0.0-vendor-private")

    def test_extracts_json_from_utf8_bom_js_wrapper_and_rejects_other_script(self):
        raw = ("\ufeffvar spec = " + json.dumps(sample_spec()) + ";").encode("utf-8")
        parsed = contract.decode_spec_js(raw)
        self.assertEqual(parsed["openapi"], "3.1.0")
        for s in (b"window.auth = {secret: 1};", b"var spec = [];", b"var spec = {}; alert(1)", b""):
            with self.subTest(raw=s[:20]), self.assertRaises(contract.InvalidOfficialSpec):
                contract.decode_spec_js(s)

    def test_official_source_urls_are_exact_and_https(self):
        expected = {
            "6.5.xs": "https://docs.stellarcyber.ai/6.5.xs/Resources/SwaggerUI/dist/spec-saas.js",
            "7.0.xs": "https://docs.stellarcyber.ai/7.0.xs/Resources/SwaggerUI/dist/spec-saas.js",
        }
        self.assertEqual(contract.OFFICIAL_SPEC_URLS, expected)

    def test_fetched_public_contract_uses_allowlisted_url(self):
        raw = ("var spec = " + json.dumps(sample_spec())).encode()
        class FakeResponse(io.BytesIO):
            status = 200
        seen = []
        class FakeOpener:
            def open(self, req, timeout):
                seen.append((req.full_url, timeout))
                return FakeResponse(raw)
        profile = contract.fetch_public_contract("7.0.xs", opener=FakeOpener())
        self.assertTrue(profile["legacy_pair_multipart_schema_documented"])
        self.assertEqual(seen[0][0], contract.OFFICIAL_SPEC_URLS["7.0.xs"])
        with self.assertRaises(contract.InvalidOfficialSpec):
            contract.fetch_public_contract("../../other", opener=FakeOpener())

    def test_cli_default_is_offline_and_never_claims_deploy_ready(self):
        with patch.object(contract, "fetch_public_contract", side_effect=AssertionError("network")):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(contract.main([]), 0)
        self.assertIn("NO_NETWORK", out.getvalue())
        self.assertIn("NOT_VERIFIED", out.getvalue())


if __name__ == "__main__":
    unittest.main()
