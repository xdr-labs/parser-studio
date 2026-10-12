# POC legacy Custom Parser deployment adapter

**Project:** Parser Studio — xdr-labs/parser-studio
**Host tested:** owner-approved `poc-apac` POC only
**Evidence baseline:** [POC CRUD experiment](10_STELLAR_POC_API_CRUD_EVIDENCE.md) and
[Stellar Cyber 7.0 SaaS Custom Parser API](https://docs.stellarcyber.ai/7.0.xs/Resources/SwaggerUI/dist/index-saas.html)

## Outcome

The new `scripts/stellar_legacy_adapter.py` is a **reusable, guarded reference
adapter** for the legacy paired-file REST contract already verified with the
owner's User Scope API key. It has no startup side effects.

| Capability | Evidence / classification |
| --- | --- |
| User Scope JWT exchange | POC HTTP 200 confirmed |
| List parsers + port catalogue | POC HTTP 200 confirmed |
| Create paired legacy parser | POC HTTP 200 + exact-name GET confirmed |
| Update paired legacy parser | POC HTTP 200 + version GET confirmed |
| Delete paired legacy parser | POC HTTP 200 + name-absent GET confirmed |
| Reusable adapter GET calls | POC tested on this branch (4 custom, 441 catalogue), **zero mutations** |
| Real parser ingestion / sensor activation / detection | **NOT VERIFIED** |
| Modular JSON-only REST upload | **NOT VERIFIED**; legacy POST rejected single JSON with 422 |
| Modular enable/disable REST API | **NOT VERIFIED**; no endpoint established in public Swagger |
| General-purpose/customer or production deployment | **NOT AUTHORIZED**; adapter restricts to test-only identities |

### What was implemented

`LegacyUpload.from_generated(pair_export, tenant, version)` consumes the
backend's `host-customized-pair.v0.1` export **as-is**, with no Ruby execution,
configuration mutation, or inclusion of raw sample logs. It enforces:

- Exactly two files: `customized_<slug>` extensionless Ruby and
  `customized_<slug>.conf`, in any input order, with exact matching names.
- Backend slug pattern `^[a-z][a-z0-9_]{1,47}$`, matching the backend
  `ParserProject` schema and import contract.
- UTF-8 Fluentd configuration containing a source and a single consistent
  receiver port (dual TCP/UDP declarations on the same port are allowed).
- Receiver `cust_id`, when present, must equal the selected tenant.
- Per-file `bytes` and SHA-256 checked against content; independent
  `manifest.fileHashes` SHA-256 and schema/contract match required.
- Strict per-file size limit, bounded version syntax, immutable in-memory
  upload plan, and no parser/source data in the plan's string representation.
- No upgrade of `targetImportVerified` or `runtime_parsing_verified` based
  only on transport/API acceptance.

`LegacyPocClient` performs exact POC-only User Scope authentication and two
read-only list requests. **Every write requires `confirmed=True`** and a
disposable name matching `ps_api_crud_test_<hex>` or
`customized_ps_api_crud_test_<hex>`. Reads/updates/deletes are tenant-scoped,
and the code rejects collisions, missing expected records, and version mismatches
before mutation. JWTs are refreshed after a bounded eight-minute cache window;
read-only GET requests may retry once after HTTP 401 with a refreshed JWT.
**POST/PUT/DELETE are never automatically retried after HTTP 401** to avoid
unintended repeated mutations. HTTP errors are categorized by method/status only,
with no raw vendor error body, key, JWT, or parser source in exceptions.

The adapter uses the documented multipart request fields:
`cust_id`, `parser_name` (POST only), `version`, and **two repeated
`file` parts** whose uploaded filenames equal the parser name and
`<parser_name>.conf`. Delete uses the exact-name URL and `cust_id` query.
The client does **not** expose any activation, import/download-modular, tenant
administration, or arbitrary parser mutation functions.

### Offline usage (no credentials, no network)

Provide a compiler return object `pair_export` and a tenant value to
validate a generated pair before any API call:

```python
from stellar_legacy_adapter import LegacyUpload

plan = LegacyUpload.from_generated(
    pair_export, tenant=selected_tenant_id, version="1.0.0"
)
print(plan.name, plan.port, plan.proof)
```

Only the generated artifact body and hashes are needed for the above call.
The key must remain on the backend, never in the browser/HTTP client.

For authenticated read-only POC operations, `LegacyPocClient` accepts the
profile returned by `probe_stellar_test_api.load_private_profile()`.
Do not enable write methods in a production service or public Web UI until
role-based confirmation, tenant isolation, deployment audit and rollback
policies have been reviewed and independently approved.

## Verification

- Clean independent worktree identified a PR #8 RED regression:
  `ModuleNotFoundError: verified_pair_fixture` caused by a module imported
  from a file not tracked by Git, plus auto-generated test name inconsistent
  with its own test-only guard. Removed the stale import, corrected the test
  name, and added an explicit default-path regression test.
- RED→GREEN adapter contract suite: byte/hash/name validation, manifest
  mismatch, direct-construction bypass, invalid ports/tenant, POC host guards,
  confirmation, collisions, mismatched versions, failure status and
  mocked create→GET→update→GET→delete→GET.
- **Backend-generated, synthetic actual file pair** (SHA-pinned fixture from
  dev-drlink) independently passed the read-only contract translator:
  `customized_sample_syslog`, 7123, two multipart parts, target import
  classification remains false.
- **New client actual read-only POC:** JWT exchange + both parser GET routes
  succeeded; 4 existing custom parser records and 441 catalogue entries;
  no create/update/delete calls were made during adapter validation.

## Next consumer integration

The actual Parser Studio backend is TypeScript and developed in a separate
session (Draft PR #4); the Web UI integration belongs to another session
(Draft PR #7). **Neither worktree was changed by this API-only branch.**
When the consumer integrates, preserve this strict boundary:

1. Backend generates validated files, byte counts, hashes and manifest;
   the adapter refuses unknown/altered files before any network call.
2. Dedicated authenticated server-side deployment service selects exactly one
   tenant, retrieves its credential securely, checks target capabilities and
   shows an explicit confirmation (legacy upload may immediately become active).
3. Backend performs known API writes only after separate deployment approval,
   verifies the same unique parser identity/version by GET, and records a
   non-sensitive audit result; on failure, only its own new test identity may
   be automatically cleaned up.
4. Do **not** claim proprietary parser runtime success from upload acceptance;
   full browser/native/real-log owner E2E remain separate gates. Modular
   enable/disable support is a separate adapter pending verified API evidence.

### Security note

Stellar Cyber's 7.0 SaaS documentation states that **legacy parsers are active
after upload and cannot be disabled** using the modular enable/disable controls.
They can have operational effects even when merely being registered. Do not
silently upload legacy parsers from the authoring UI.

Official docs:
- https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Custom-Log-Parser.htm
- https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Parser-Studio-Parsers.htm
