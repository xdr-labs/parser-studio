# Public API evidence gate — Legacy vs Modular Parsers

**Checked:** 2026-10-12 KST, vendor SaaS Swagger 6.5.xs and 7.0.xs.
**Scope:** independent Parser Studio API validation lane on dev-atlas, not a Web UI or native compiler implementation.

## Published contract vs POC verification

| Capability | Public SaaS Swagger | POC evidence | Parser Studio support status |
| --- | --- | --- | --- |
| User Scope JWT | JWT bearer API | JWT exchange HTTP 200 | VERIFIED_POC |
| GET custom parsers | Documented | HTTP 200 | VERIFIED_POC |
| GET parser catalogue | Documented | HTTP 200 | VERIFIED_POC |
| POST paired Legacy parser | Documented multipart file array | HTTP 200 + read-back | VERIFIED_POC_TEST_ONLY |
| PUT paired Legacy parser | Documented multipart file array | HTTP 200 + version read-back | VERIFIED_POC_TEST_ONLY |
| DELETE paired Legacy parser | Documented | HTTP 200 + absence read-back | VERIFIED_POC_TEST_ONLY |
| Modular Parser REST upload | No separate public endpoint in inspected schema | No compatible upload proved | NOT_VERIFIED |
| Modular Parser enable/disable | No named public endpoint or request schema | Not tested | NOT_VERIFIED |
| Bulk parser state changes | 7.0.0s release note describes API support | Exact public API schema missing | RELEASE_NOTE_ONLY |
| Proprietary loader and real-event parsing | Outside these Swagger methods | No log-ingestion evidence | NOT_VERIFIED |

**Important distinction:** An endpoint absent from the two *public* Swagger
documents does **not** prove that the product cannot provide the feature
through an authenticated/internal/private API. It means we cannot safely
implement a documented, general-purpose API adapter from these sources.
The 7.0.0s notes explicitly describe bulk parser-state APIs, but publish
no request URL/body in the checked public Swagger.

## Reproducible official Swagger source evidence

The read-only code is `scripts/stellar_api_public_contract.py`.
It fetches only two hardcoded official documentation resources when explicitly
requested, rejects HTTP redirects, and prints only schema-based capabilities.
It never reads private API keys or contacts a POC/customer DP.

| Official version | Public paths | Known Custom Parser routes | SHA-256 of original JS |
| --- | ---: | --- | --- |
| 6.5.xs | 181 | 3 paths, 5 HTTP methods | `5f3a6b0f199911905150f5f0179f07ae684905557fca1f5bed66ff08eb30d22f` |
| 7.0.xs | 241 | 3 paths, 5 HTTP methods | `835449a3251b8eec049d56de8fd6cfb02ce5535fbc2c1373b9ba196cb9599ca2` |

For each version, the public specs document:

- `GET /custom_log_parsers`
- `POST /custom_log_parsers`
- `PUT /custom_log_parsers/{name}`
- `DELETE /custom_log_parsers/{name}`
- `GET /custom_log_parsers/parsers`

The POST and PUT require `multipart/form-data`, a binary `file` array,
`cust_id`, `version`, plus POST `parser_name`. All five operations
declare JWT authorization. No other path containing `parser` was present
in either inspected public Swagger snapshot.

Commands:

```bash
cd /home/aella/parser-studio-api-clean-verify
python3 scripts/stellar_api_public_contract.py                      # offline; no network
python3 scripts/stellar_api_public_contract.py --check-public-swagger  # official docs GET only
python3 -m unittest discover -s tests -p 'test_*.py' -q
```

The schema classifier does **not** unlock modular/activation features even
when a new unclassified path appears; new paths require their own evidenced
request/response/permission contract and approved nonproduction E2E. The
`require_supported_operation` policy helper separately requires both
documented legacy schema and verified owner-approved POC provenance.
Neither helper is itself a general deployment authorization.

## Defensive test-only adapter write gate

Existing `scripts/stellar_legacy_adapter.py` further rejects POC
CREATE/UPDATE before any HTTP request unless the artifact is a
`customized_ps_api_crud_test_<hex>` disposable test pair, the explicit
`confirmed=True` flag is supplied, and all the following are satisfied:

- The test uses a reserved port in **7800–7999** and no currently occupied
  parser catalogue port.
- Every UDP/TCP receiver in the `.conf` file binds specifically to
  `127.0.0.1`, with its exact test-parser name as the tag and parser type.
- The only accepted output is the exact test tag routed to `@type null`
  (discard). Broad match patterns, external `@include` and public binds
  are refused.
- Exact file bytes/lengths/individual SHA-256 and independent compiler
  manifest SHA-256 are checked. Arbitrary/edited files are not silently
  considered vendor-compatible.
- Every write uses an exact test-only name, an owner-approved POC hostname,
  and selected tenant, with version collision checks.

**A production-shaped backend `.conf` using `bind 0.0.0.0`,
`@include /etc/td-agent/transport_settings.conf`, or
`rewrite_tag_filter` must not be accepted by this test-only writer.**
The backend may validly produce such a file for downloaded offline review,
but uploading it requires an independently reviewed deployment policy.
The adapter does not silently modify the compiled artifact to fit its
test-only rules, since that would break compiler SHA/provenance.

The integration must continue to distinguish:

1. **Authoring/generation** — UI and backend compile two draft files,
   no target modification.
2. **API registration** — actual POC legacy pair CRUD was verified;
   currently the Python reference write client accepts only disposable,
   localhost-bound test fixtures and explicit confirmation.
3. **Activation and real parsing** — still unverified. Legacy upload can
   have immediate operational effects; no silent auto-upload should be
   initiated by the general Web UI.

## Modular Parser UI fallback is distinct from the Legacy REST contract

The official Parser Studio UI instructions do document uploading a **Modular
Parser JSON** exported from another tenant/instance. Uploading it through
**System > DATA SOURCE MANAGEMENT > Parser Studio > Parsers > Create Parser >
Upload Custom Parser** is a **UI action**, not a verified public REST API.
The downloaded JSON must have valid five-stage structure and an appropriate
selected tenant. The UI verifies configured port use, creates new parser and
configuration IDs, and refreshes the version; such files are independent of
the original parser after upload.

The vendor's UI instructions require **root-level user access with read/write
privileges** for parser creation. Our POC User Scope key successfully managed
*Legacy* Custom Parser pairs via REST, but that does **not** establish root
privileges or Modular JSON upload permission. Also, our current backend's
extensionless Ruby + CONF output is **not** a vendor Modular JSON export, so
it must not be represented as one to bypass the API evidence gate.

Manual vendor UI upload is a fallback for an independently validated vendor
Modular JSON, not a substitute for implementing an undocumented API.

## Remaining validation request

To implement Modular Parser activation/bulk management, obtain an
official supported endpoint, authenticated request/response schema, RBAC
requirements, and a reproducible test-tenant procedure from Stellar Cyber.
Then perform a separately authorized, disposable nonproduction trial with
before/after state checks. Do not infer or brute-force undocumented endpoints
on the POC. Existing Legacy CRUD evidence should not be repeated.

## Sources

- SaaS 6.5 Swagger: https://docs.stellarcyber.ai/6.5.xs/Resources/SwaggerUI/dist/index-saas.html
- SaaS 7.0 Swagger: https://docs.stellarcyber.ai/7.0.xs/Resources/SwaggerUI/dist/index-saas.html
- 7.0.0s release notes (AELDEV-71125):
  https://docs.stellarcyber.ai/7.0.xs/Release-Notes/Stellar-Cyber-7.0.0-Release-Notes.htm
- 7.0 Parser Studio:
  https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Parser-Studio-Parsers.htm
- Earlier POC CRUD proof: `docs/10_STELLAR_POC_API_CRUD_EVIDENCE.md`
- Legacy adapter contract: `docs/11_POC_LEGACY_DEPLOY_ADAPTER.md`
