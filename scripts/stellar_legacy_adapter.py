"""Evidence-backed legacy Custom Parser REST adapter (POC-only mutations).

Accepts generated Parser Studio file pairs and their checksums without running
Ruby or Fluentd. Retains the vendor distinction between legacy pair CRUD and
unverified modular/activation REST APIs.

No network occurs at import or when preparing an upload. Mutations require
explicit confirmation and a test-only name on the owner-approved POC host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Mapping, Sequence

import requests

POC_HOST = "https://poc-apac.stellarcyber.cloud"
API_PREFIX = "/connect/api/v1"
HTTP_TIMEOUT = (10, 25)
MAX_FILE_BYTES = 512_000

# Exact current backend schema: slug ^[a-z][a-z0-9_]{1,47}$.
NAME_PATTERN = re.compile(r"customized_[a-z][a-z0-9_]{1,47}\Z")
TEST_NAME_PATTERN = re.compile(r"(?:customized_)?ps_api_crud_test_[0-9a-f]{6,16}\Z")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9._/\-]{1,64}\Z")
PORT_PATTERN = re.compile(r"^\s*port\s+(\d+)\s*$", re.MULTILINE)
TENANT_PATTERN = re.compile(r"^\s*cust_id\s+['\"]?([a-zA-Z0-9_-]+)", re.MULTILINE)

LEGACY_CAPABILITIES = {
    "legacy_pair_crud_verified": True,
    "modular_rest_upload_verified": False,
    "activation_api_verified": False,
    "target_runtime_parsing_verified": False,
    "legacy_parser_may_be_active_on_upload": True,
    "verified_environment": "owner-approved POC only",
}


class LegacyContractError(ValueError):
    """Unsafe or unsupported generated artifact / environment."""


class LegacyApiError(RuntimeError):
    """Sanitized vendor HTTP error; raw headers/body are never propagated."""

    def __init__(self, method: str, status: int):
        self.method = method
        self.status = status
        super().__init__(f"{method} rejected with HTTP {status}")


def _verify_file(record: Mapping[str, Any]) -> tuple[str, bytes, str]:
    if not isinstance(record, dict):
        raise LegacyContractError("Generated file must be a structured record")
    filename = record.get("name")
    body = record.get("content")
    expected_size = record.get("bytes")
    expected_hash = record.get("sha256")
    if not isinstance(filename, str) or not filename or "/" in filename or "\\" in filename:
        raise LegacyContractError("Unsafe or missing generated filename")
    if isinstance(body, str):
        content = body.encode("utf-8")
    elif isinstance(body, bytes):
        content = body
    else:
        raise LegacyContractError("Generated file must contain text or bytes")
    if not content or len(content) > MAX_FILE_BYTES:
        raise LegacyContractError("Empty or oversized generated file")
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size != len(content):
        raise LegacyContractError("Generated file byte length mismatch")
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        raise LegacyContractError("Missing or malformed generated SHA-256 hash")
    checksum = hashlib.sha256(content).hexdigest()
    if checksum != expected_hash.lower():
        raise LegacyContractError("Generated file SHA-256 mismatch")
    return filename, content, checksum


def _validate_conf(conf_bytes: bytes, tenant: str) -> int:
    try:
        conf = conf_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegacyContractError("Configuration file is not UTF-8") from None
    if "<source>" not in conf or "</source>" not in conf or "@type" not in conf:
        raise LegacyContractError("Missing recognizable receiver configuration")
    ports = [int(match.group(1)) for match in PORT_PATTERN.finditer(conf)]
    if not ports or any(not 1 <= port <= 65535 for port in ports) or len(set(ports)) != 1:
        raise LegacyContractError("Missing, invalid, or inconsistent receiver port")
    declared = TENANT_PATTERN.findall(conf)
    if declared and any(t != tenant for t in declared):
        raise LegacyContractError("Configuration tenant does not match selected tenant")
    return ports[0]


@dataclass(frozen=True, repr=False)
class LegacyUpload:
    """Validated in-memory artifact plan (never prints source bodies)."""

    name: str
    tenant: str
    version: str
    port: int
    parser_bytes: bytes = field(repr=False)
    conf_bytes: bytes = field(repr=False)
    parser_hash: str
    conf_hash: str
    status: str = "DRAFT"

    def __post_init__(self):
        # Even direct dataclass construction must satisfy integrity checks;
        # callers cannot bypass from_generated() with forged bytes or hashes.
        if not isinstance(self.name, str) or not NAME_PATTERN.fullmatch(self.name):
            raise LegacyContractError("Invalid generated parser name")
        if not isinstance(self.tenant, str) or not self.tenant.strip() or any(c.isspace() for c in self.tenant):
            raise LegacyContractError("Invalid generated tenant")
        if not isinstance(self.version, str) or not VERSION_PATTERN.fullmatch(self.version):
            raise LegacyContractError("Invalid generated version")
        if self.status not in ("DRAFT", "ENGINE_TESTED", "NATIVE_TESTED"):
            raise LegacyContractError("Unexpected artifact status")
        for body, expected in ((self.parser_bytes, self.parser_hash), (self.conf_bytes, self.conf_hash)):
            if not isinstance(body, bytes) or not body or len(body) > MAX_FILE_BYTES:
                raise LegacyContractError("Invalid generated payload bytes")
            if not isinstance(expected, str) or hashlib.sha256(body).hexdigest() != expected:
                raise LegacyContractError("Invalid generated payload SHA-256")
        if self.port != _validate_conf(self.conf_bytes, self.tenant):
            raise LegacyContractError("Configuration port differs from upload plan")

    @classmethod
    def from_generated(
        cls,
        generated: Mapping[str, Any],
        *,
        tenant: str,
        version: str,
    ) -> LegacyUpload:
        if not isinstance(generated, dict) or generated.get("contract") != "host-customized-pair.v0.1":
            raise LegacyContractError("Unrecognized Parser Studio pair contract")
        if not isinstance(tenant, str) or not tenant.strip() or any(ch.isspace() for ch in tenant):
            raise LegacyContractError("Invalid tenant ID")
        if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
            raise LegacyContractError("Unsupported version string")
        manifest = generated.get("manifest")
        if not isinstance(manifest, dict):
            raise LegacyContractError("Missing generated manifest")
        status = manifest.get("status")
        if status not in ("DRAFT", "ENGINE_TESTED", "NATIVE_TESTED"):
            raise LegacyContractError("Unrecognized generated artifact readiness")
        files = generated.get("files")
        if not isinstance(files, list) or len(files) != 2:
            raise LegacyContractError("Expected exactly two generated legacy files")
        records = [_verify_file(item) for item in files]
        mapping = {name: (body, digest) for name, body, digest in records}
        if len(mapping) != 2:
            raise LegacyContractError("Duplicate generated filename")
        # Require manifest hashes to agree with each compiled artifact.
        if (manifest.get("contract") != generated["contract"]
                or manifest.get("schemaRevision") != "0.1"
                or manifest.get("fileHashes") != {key: val[1] for key, val in mapping.items()}):
            raise LegacyContractError("Manifest contract or SHA-256 mismatch")
        parser_candidates = [name for name in mapping if not name.endswith(".conf")]
        if len(parser_candidates) != 1:
            raise LegacyContractError("Expected one extensionless parser body")
        name = parser_candidates[0]
        if not NAME_PATTERN.fullmatch(name) or set(mapping) != {name, name + ".conf"}:
            raise LegacyContractError("Expected matched customized_<slug> and .conf filenames")
        parser_body, parser_digest = mapping[name]
        conf_body, conf_digest = mapping[name + ".conf"]
        # Only the transport contract is checked. The native runner and the
        # vendor proprietary runtime remain independent compatibility gates.
        port = _validate_conf(conf_body, tenant)
        return cls(
            name=name,
            tenant=tenant,
            version=version,
            port=port,
            parser_bytes=parser_body,
            conf_bytes=conf_body,
            parser_hash=parser_digest,
            conf_hash=conf_digest,
            status=status,
        )

    @property
    def proof(self) -> dict:
        return {
            "readiness": self.status + " (transport only)",
            "parser_sha256": self.parser_hash,
            "conf_sha256": self.conf_hash,
            "target_import_verified": False,
            "runtime_parsing_verified": False,
        }

    def form_data(self) -> dict[str, str]:
        return {"cust_id": self.tenant, "parser_name": self.name, "version": self.version}

    def multipart_files(self):
        return [
            ("file", (self.name, self.parser_bytes, "application/octet-stream")),
            ("file", (self.name + ".conf", self.conf_bytes, "text/plain")),
        ]


class LegacyPocClient:
    """Explicit, test-only bridge for a verified POC legacy pair REST contract."""

    def __init__(self, profile: Mapping[str, str], *, session=None):
        if (
            not isinstance(profile, dict)
            or profile.get("host") != POC_HOST
            or not isinstance(profile.get("tenant"), str)
            or not profile["tenant"]
            or not isinstance(profile.get("key"), str)
            or not profile["key"]
        ):
            raise LegacyContractError("Only the owner-approved POC profile can be used")
        self.host = POC_HOST
        self.tenant = profile["tenant"]
        self._key = profile["key"]
        self._jwt = None
        self._client = session if session is not None else requests.Session()
        self._owns_session = session is None

    def close(self):
        if self._owns_session:
            self._client.close()

    def _token(self) -> str:
        if self._jwt is None:
            try:
                r = self._client.post(
                    self.host + API_PREFIX + "/access_token",
                    headers={"Authorization": "Bearer " + self._key, "Accept": "application/json"},
                    timeout=HTTP_TIMEOUT, allow_redirects=False,
                )
            except requests.RequestException as exc:
                raise LegacyContractError("Authentication network failure: " + type(exc).__name__) from None
            if r.status_code != 200:
                raise LegacyApiError("AUTH", r.status_code)
            try:
                jwt = r.json().get("access_token")
            except (ValueError, TypeError, AttributeError):
                jwt = None
            if not isinstance(jwt, str) or not jwt:
                raise LegacyContractError("Invalid access-token response")
            self._jwt = jwt
        return self._jwt

    def _headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self._token(), "Accept": "application/json"}

    def _records(self, path: str) -> list[dict]:
        try:
            r = self._client.get(
                self.host + API_PREFIX + path,
                params={"cust_id": self.tenant},
                headers=self._headers(),
                allow_redirects=False,
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise LegacyContractError("Parser listing network failure: " + type(exc).__name__) from None
        if r.status_code != 200:
            raise LegacyApiError("GET", r.status_code)
        try:
            obj = r.json()
            data = obj.get("data") if isinstance(obj, dict) else None
        except (ValueError, TypeError, AttributeError):
            data = None
        if not isinstance(data, list) or len(data) > 10_000 or any(not isinstance(x, dict) for x in data):
            raise LegacyContractError("Unexpected vendor parser-list response")
        return data

    def _find(self, name: str):
        return next(
            (record for record in self._records("/custom_log_parsers")
             if record.get("parser_name") == name and record.get("cust_id", self.tenant) == self.tenant),
            None,
        )

    @staticmethod
    def _write_guard(name: str, confirmed: bool):
        if confirmed is not True:
            raise LegacyContractError("Write requires explicit confirmation")
        if not TEST_NAME_PATTERN.fullmatch(name):
            raise LegacyContractError("Only disposable POC test parser identities may be mutated")

    def _check_plan(self, plan: LegacyUpload, confirmed: bool):
        if not isinstance(plan, LegacyUpload) or plan.tenant != self.tenant:
            raise LegacyContractError("Selected tenant differs from upload plan")
        self._write_guard(plan.name, confirmed)

    def _write(self, method: str, name: str, **kwargs) -> int:
        fn = {"POST": self._client.post, "PUT": self._client.put, "DELETE": self._client.delete}[method]
        try:
            r = fn(
                self.host + API_PREFIX + "/custom_log_parsers" + ("/" + name if method != "POST" else ""),
                headers=self._headers(),
                allow_redirects=False,
                timeout=HTTP_TIMEOUT,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise LegacyContractError("Vendor mutation network failure: " + type(exc).__name__) from None
        if r.status_code != 200:
            raise LegacyApiError(method, r.status_code)
        return r.status_code

    def create(self, plan: LegacyUpload, *, confirmed: bool = False) -> dict:
        self._check_plan(plan, confirmed)
        if self._find(plan.name) is not None:
            raise LegacyContractError("Parser name already exists")
        catalogue = self._records("/custom_log_parsers/parsers")
        if any(isinstance(x.get("port"), (int, float)) and not isinstance(x.get("port"), bool)
               and x["port"] == plan.port for x in catalogue):
            raise LegacyContractError("Parser listener port collision")
        status = self._write(
            "POST", plan.name,
            data=plan.form_data(), files=plan.multipart_files(),
        )
        record = self._find(plan.name)
        return {
            "method": "POST", "http": status,
            "verified": record is not None and str(record.get("version")) == plan.version,
            "name": plan.name, "version": plan.version,
        }

    def update(
        self, plan: LegacyUpload, *, expected_version: str, confirmed: bool = False
    ) -> dict:
        self._check_plan(plan, confirmed)
        if not isinstance(expected_version, str) or not VERSION_PATTERN.fullmatch(expected_version):
            raise LegacyContractError("Invalid expected version")
        found = self._find(plan.name)
        if found is None or str(found.get("version")) != expected_version:
            raise LegacyContractError("Existing parser/version does not match expected value")
        data = plan.form_data()
        data.pop("parser_name")
        status = self._write("PUT", plan.name, data=data, files=plan.multipart_files())
        new = self._find(plan.name)
        return {
            "method": "PUT", "http": status,
            "verified": new is not None and str(new.get("version")) == plan.version,
            "name": plan.name, "version": plan.version,
        }

    def delete(self, name: str, *, expected_version: str, confirmed: bool = False) -> dict:
        self._write_guard(name, confirmed)
        if not isinstance(expected_version, str) or not VERSION_PATTERN.fullmatch(expected_version):
            raise LegacyContractError("Invalid expected version")
        found = self._find(name)
        if found is None or str(found.get("version")) != expected_version:
            raise LegacyContractError("Existing parser/version does not match expected value")
        status = self._write("DELETE", name, params={"cust_id": self.tenant})
        still_here = self._find(name)
        return {
            "method": "DELETE", "http": status,
            "verified": still_here is None,
            "name": name,
        }
