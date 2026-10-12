#!/usr/bin/env python3
"""Fail-closed PUBLIC Swagger capability classifier for Stellar Cyber parsers.

Do not confuse documented Legacy CRUD with unverified Modular upload or
parser activation. No customer-host traffic, parser mutation or credential
reads. Only --check-public-swagger accesses fixed vendor documentation URLs.
"""

import argparse
import hashlib
import json
import re
from urllib import request, error

OFFICIAL_SPEC_URLS = {
    "6.5.xs": "https://docs.stellarcyber.ai/6.5.xs/Resources/SwaggerUI/dist/spec-saas.js",
    "7.0.xs": "https://docs.stellarcyber.ai/7.0.xs/Resources/SwaggerUI/dist/spec-saas.js",
}
MAX_SWAGGER_BYTES = 2_000_000
HTTP_TIMEOUT_SECONDS = 18

LEGACY_ROUTE_METHODS = {
    "GET /custom_log_parsers": None,
    "POST /custom_log_parsers": {"cust_id", "parser_name", "version", "file"},
    "PUT /custom_log_parsers/{name}": {"cust_id", "version", "file"},
    "DELETE /custom_log_parsers/{name}": None,
    "GET /custom_log_parsers/parsers": None,
}
SUPPORTED_LEGACY_OPERATIONS = {
    "legacy_list": "GET /custom_log_parsers",
    "legacy_catalogue": "GET /custom_log_parsers/parsers",
    "legacy_create": "POST /custom_log_parsers",
    "legacy_update": "PUT /custom_log_parsers/{name}",
    "legacy_delete": "DELETE /custom_log_parsers/{name}",
}
WRITE_OPERATIONS = frozenset({"legacy_create", "legacy_update", "legacy_delete"})


class InvalidOfficialSpec(ValueError):
    pass


class UnsupportedCapability(PermissionError):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def decode_spec_js(payload: bytes) -> dict:
    """Decode only the JSON assigned in an ordinary JS var spec assignment."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_SWAGGER_BYTES:
        raise InvalidOfficialSpec("Missing or oversized public Swagger source")
    try:
        script = payload.decode("utf-8-sig")
    except UnicodeError:
        raise InvalidOfficialSpec("Public Swagger is not valid UTF-8") from None
    match = re.match(r"\s*var\s+spec\s*=\s*", script)
    if match is None:
        raise InvalidOfficialSpec("Unknown public Swagger JavaScript wrapper")
    try:
        spec, consumed = json.JSONDecoder().raw_decode(script[match.end():])
    except (ValueError, TypeError):
        raise InvalidOfficialSpec("Could not decode official Swagger JSON") from None
    trailing = script[match.end() + consumed:].strip()
    if trailing not in ("", ";") or not isinstance(spec, dict):
        raise InvalidOfficialSpec("Unexpected executable code in official Swagger")
    return spec


def _jwt_required(operation: dict) -> bool:
    security = operation.get("security")
    return isinstance(security, list) and any(
        isinstance(item, dict) and "jwt" in item for item in security
    )


def _multipart_file_schema(operation: dict, required: set) -> bool:
    try:
        body = operation["requestBody"]
        if body.get("required") is not True:
            return False
        schema = body["content"]["multipart/form-data"]["schema"]
        actual = set(schema["required"])
        props = schema["properties"]
        file_spec = props["file"]
        return (
            required <= actual
            and required <= set(props)
            and file_spec.get("type") == "array"
            and file_spec.get("items", {}).get("type") == "string"
            and file_spec.get("items", {}).get("format") == "binary"
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def classify_spec(spec: dict, version: str) -> dict:
    """Documented in published Swagger is NOT the same as verified on POC."""
    if version not in OFFICIAL_SPEC_URLS:
        raise InvalidOfficialSpec("Unrecognized official SaaS Swagger version")
    if (
        not isinstance(spec, dict)
        or not isinstance(spec.get("openapi"), str)
        or not spec["openapi"].startswith("3.")
        or not isinstance(spec.get("paths"), dict)
        or any(not isinstance(path, str) or not isinstance(ops, dict)
               for path, ops in spec["paths"].items())
    ):
        raise InvalidOfficialSpec("Unknown OpenAPI document shape")

    paths = spec["paths"]
    method_states = {}
    for method_path, required_fields in LEGACY_ROUTE_METHODS.items():
        method, path = method_path.split(" ", 1)
        candidate = paths.get(path, {}).get(method.lower())
        if candidate is None:
            method_states[method_path] = "NOT_DOCUMENTED"
        elif not isinstance(candidate, dict) or not _jwt_required(candidate):
            method_states[method_path] = "SCHEMA_MISMATCH"
        elif required_fields is not None and not _multipart_file_schema(candidate, required_fields):
            method_states[method_path] = "SCHEMA_MISMATCH"
        else:
            method_states[method_path] = "DOCUMENTED"

    unclassified = sorted(
        method.upper() + " " + path
        for path, operations in paths.items()
        if "parser" in path.lower()
        for method in operations
        if method in {"get", "post", "put", "patch", "delete"}
        and method.upper() + " " + path not in LEGACY_ROUTE_METHODS
    )
    return {
        "version": version,
        "source": OFFICIAL_SPEC_URLS[version],
        "source_type": "PUBLISHED_SWAGGER_NOT_TARGET_VERIFICATION",
        "documented_path_count": len(paths),
        "public_legacy_methods": method_states,
        "legacy_pair_multipart_schema_documented": all(
            method_states[path] == "DOCUMENTED"
            for path in ("POST /custom_log_parsers", "PUT /custom_log_parsers/{name}")
        ),
        "unclassified_parser_routes": unclassified,
        "modular_upload": "NOT_VERIFIED",
        "activation_api": "NOT_VERIFIED",
        "release_note_bulk_toggle": (
            "DESCRIBED_NO_PUBLIC_SCHEMA" if version == "7.0.xs" else "NOT_DOCUMENTED"
        ),
        "general_deployment_authorized": False,
    }


def require_supported_operation(
    profile: dict,
    operation: str,
    *,
    verified_poc_legacy: bool = False,
    approved_test_environment: bool = False,
) -> str:
    """Fail closed: a public endpoint alone never authorizes writes."""
    route = SUPPORTED_LEGACY_OPERATIONS.get(operation)
    if route is None:
        raise UnsupportedCapability("Operation not verified by published Parser API")
    if not isinstance(profile, dict) or profile.get("public_legacy_methods", {}).get(route) != "DOCUMENTED":
        raise UnsupportedCapability("Official API contract is not documented")
    if not verified_poc_legacy or not approved_test_environment:
        raise UnsupportedCapability("POC proof and approved test environment are required")
    if operation in WRITE_OPERATIONS:
        if not profile.get("legacy_pair_multipart_schema_documented", False):
            raise UnsupportedCapability("Multipart legacy upload schema unavailable")
        return "LEGACY_TEST_ONLY"
    return "LEGACY_READ_ONLY"


def fetch_public_contract(version: str, *, opener=None) -> dict:
    """Fetch only the exact vendor documentation URL, with no redirects."""
    if version not in OFFICIAL_SPEC_URLS:
        raise InvalidOfficialSpec("Only official Swagger sources are supported")
    client = opener if opener is not None else request.build_opener(NoRedirect())
    req = request.Request(
        OFFICIAL_SPEC_URLS[version],
        headers={"Accept": "application/javascript,text/javascript"},
    )
    try:
        with client.open(req, timeout=HTTP_TIMEOUT_SECONDS) as res:
            if res.status != 200:
                raise InvalidOfficialSpec("Vendor documentation was not HTTP 200")
            raw = res.read(MAX_SWAGGER_BYTES + 1)
    except (error.HTTPError, error.URLError, TimeoutError, OSError):
        raise InvalidOfficialSpec("Vendor documentation download failed") from None
    profile = classify_spec(decode_spec_js(raw), version)
    profile["source_sha256"] = hashlib.sha256(raw).hexdigest()
    return profile


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Classify published Stellar Cyber Parser REST API support"
    )
    parser.add_argument("--check-public-swagger", action="store_true")
    options = parser.parse_args(argv)
    if not options.check_public_swagger:
        print(json.dumps({
            "mode": "NO_NETWORK",
            "legacy_poc_crud": "VERIFIED_SEPARATELY",
            "modular_upload": "NOT_VERIFIED",
            "activation_api": "NOT_VERIFIED",
            "general_deployment_authorized": False,
        }, sort_keys=True))
        return 0
    try:
        profiles = [fetch_public_contract(version) for version in OFFICIAL_SPEC_URLS]
    except InvalidOfficialSpec as exc:
        print("PUBLIC_SWAGGER_CHECK_FAILED: " + type(exc).__name__)
        return 2
    print(json.dumps({"profiles": profiles}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
