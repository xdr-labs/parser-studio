# Stellar Cyber POC — User Scope Custom Parser API CRUD verification

**Observed:** 2026-10-12 (KST). **Environment:** owner-approved Stellar Cyber POC
`https://poc-apac.stellarcyber.cloud`, tenant-selected locally from the private
test profile on `dev-atlas`. Credential and tenant identifier are never copied
into GitHub or published.

## Outcome: PASS for legacy host-reference parser pairs

| Action | Endpoint (prefix `/connect/api/v1`) | Actual result |
| --- | --- | --- |
| User Scope API Key → JWT | POST `/access_token` | HTTP 200 |
| Baseline listing | GET `/custom_log_parsers?cust_id=...` | HTTP 200, 4 entries |
| Parser catalogue | GET `/custom_log_parsers/parsers?cust_id=...` | HTTP 200; selected test port available |
| Disposable create | POST `/custom_log_parsers` | HTTP 200 |
| Confirm identity | GET `/custom_log_parsers?cust_id=...` | Exact test name found |
| Disposable update | PUT `/custom_log_parsers/{name}` | HTTP 200 |
| Verify update | GET `/custom_log_parsers?cust_id=...` | Version `1.0.1` observed |
| Disposable delete | DELETE `/custom_log_parsers/{name}?cust_id=...` | HTTP 200 |
| Verify cleanup | GET `/custom_log_parsers?cust_id=...` | Test name absent; 0 test residues; 4 entries total |

The disposable parser name was `customized_ps_api_crud_test_036fd939f3`;
its test-only receiver port was `7891`. The platform had four custom parsers
before and after this one-shot test. No pre-existing parser was updated or
deleted, and no data sources or sensors were modified by the script.

## Root cause of prior HTTP 422

An earlier request submitted only a modular JSON file. The POC's
`custom_log_parsers` endpoint rejected it with HTTP 422 and validation
text `missing parser/conf files, or wrong parser/conf file name`.

The existing four custom-parser metadata records show a different, legacy
upload convention (metadata only; no customer file content was fetched):

- `parser_name` begins with `customized_`.
- `parser_file` is exactly `parser_name` **without an extension**.
- `conf_file` is exactly `parser_name + '.conf'`.
- Both files are uploaded as repeated multipart `file` fields.
- Additional multipart fields: `cust_id`, `version`, and `parser_name`
  for POST; PUT uses `cust_id`, `version`, and both files.

This platform-specific, **tested legacy** contract is not equivalent to
the documented modular-parser UI import flow. A Modular JSON-only REST upload
is **NOT VERIFIED**. A modular enable/disable REST endpoint is also
**NOT VERIFIED**. Do not silently map the two formats to one API adapter.

## Test material and safety

The test pair was based on Parser Studio backend's independently generated,
synthetic native-suite artifact from `dev-drlink`, branch
`feat/r15-parser-pair-backend` (observed HEAD `687be44`).
The original fixture files on dev-atlas were SHA-matched to that source:

- Extensionless `customized_sample_syslog` SHA-256:
  `d5e025b2f1792567113246888f0b87e512dab43934279dfd22b19259c374a873`
- `customized_sample_syslog.conf` SHA-256:
  `0ebcd7c8a50ac016b994cf7a3efb9c920b50d9ae4d400fb6a7f753ce9e0e4ee7`

The fixture loader enforces private file mode `0600` and cache directory
mode `0700`, exact SHA-256 checks, no symlinks, approved filename and port,
and a random test-only parser name. It updates matching CONF names/ports and
the fixture's embedded synthetic receiver port before upload.

The backend artifact is **synthetic**, not a statement that generated parser
semantics are ready for customers. The host-customized pair contract was
native-engine tested by the backend workstream; this POC check verifies
registration CRUD only, not actual log ingestion or parser correctness.

The CRUD script is dry-run by default. It requires explicit `--execute`,
enforces the single approved POC host, uses TLS verification and no redirects,
checks for name/port conflicts, and attempts to delete only its newly created
unique test identity even if the update fails. A transient 429/5xx delete
response triggers one bounded retry if the same test name remains.

### Running the private local probe (owner-approved POC only)

From the **separate** dev-atlas worktree, after placing the attested synthetic
pair at `~/.cache/parser-studio-poc-crud-fixtures/`:

```bash
python3 scripts/verify_poc_parser_crud.py               # no network traffic
python3 scripts/verify_poc_parser_crud.py --execute     # modifies ONLY a disposable POC parser
```

The real POC test has already passed. **There is no need to re-execute this
write test** as a routine build or CI step. Do not include it in automatic
test suites; unit tests use mocks instead.

## Parser Studio integration acceptance

- **Supported by real POC evidence:** User Scope JWT exchange and tenant-
  scoped create, list, update, delete for the legacy extensionless+CONF pair.
- **Future adapter:** Use explicit, separately confirmed "Deploy to POC"
  action (not implicit auto-deploy), POST/PUT two named files, poll listing
  for proof, record per-revision status, and implement exact-name rollback.
- **Not verified:** Modular parser UI import API and enable/disable API; this
  test did not confirm runtime ingestion, sensor activation behavior, or
  full parser function accuracy.
- **Risk note:** Legacy custom parser upload may immediately enable a parser,
  per vendor documentation. Never use uncontrolled production listeners for
  test imports. Production deployment and release require separate approval.

References:
- https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Custom-Log-Parser.htm
- https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Parser-Studio-Parsers.htm
- https://github.com/xdr-labs/stellar-data-exporter/blob/main/app/stellar.py
