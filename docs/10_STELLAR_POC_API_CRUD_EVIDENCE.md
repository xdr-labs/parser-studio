# Stellar Cyber POC — Custom Parser REST API CRUD Evidence

**Verified on:** 2026-10-12 (KST)
**Target:** authorized POC SaaS DP (not a production release)
**Credential:** user-scoped API Key stored only in `~/.config/parser-studio/stellar-test-api.json` on dev-atlas
**Authorization:** explicit owner approval for disposable test parser create, update, and delete
**Status:** **CRUD PASS with read-back and cleanup** — sensor/runtime parsing and modular activation NOT VERIFIED.

## Tested operations

| Operation | Exact API path | Real result |
| --- | --- | --- |
| Exchange User Scope Key | `POST /connect/api/v1/access_token` | HTTP 200, JWT received |
| Initial inventory | `GET /connect/api/v1/custom_log_parsers?cust_id=...` | HTTP 200, 4 existing custom parsers |
| Parser port catalogue | `GET /connect/api/v1/custom_log_parsers/parsers?cust_id=...` | HTTP 200, test port 7891 not in use |
| CREATE disposable parser | `POST /connect/api/v1/custom_log_parsers` | HTTP 200 |
| READ back after CREATE | `GET /connect/api/v1/custom_log_parsers?cust_id=...` | Unique disposable name present |
| UPDATE to version 1.0.1 | `PUT /connect/api/v1/custom_log_parsers/{name}` | HTTP 200 |
| READ back after UPDATE | `GET /connect/api/v1/custom_log_parsers?cust_id=...` | The test parser's persisted `version` equals `1.0.1` |
| DELETE own test parser | `DELETE /connect/api/v1/custom_log_parsers/{name}?cust_id=...` | HTTP 200 |
| READ back after DELETE | `GET /connect/api/v1/custom_log_parsers?cust_id=...` | Test parser absent, 4 existing entries remain |

Verified test identity: `ps_api_crud_test_c46ddd7f98`. The name is ephemeral and contains no customer data. No other parser was changed.

## Concrete REST multipart contract (observed on POC)

The public 6.5s/7.0s Swagger defines the following required form data:

- `POST`: `cust_id`, `parser_name`, `version`, repeated `file` binary parts.
- `PUT`: `cust_id`, `version`, repeated `file` binary parts; name in URL.
- `DELETE`: name in URL and `cust_id` query parameter.
- `GET`: optional `cust_id` query parameter.
- Authenticate with `Authorization: Bearer <User Scope API Key>` to `POST /access_token`, then use `Authorization: Bearer <JWT>` for parser API calls.

**Critical live discovery:** The accepted file parts were exactly:

1. File part named `file`, uploaded filename equal to `parser_name` **without an extension**, whose body was the generated JSON parser fixture.
2. File part named `file`, uploaded filename equal to `parser_name + '.conf'`, whose body was a Fluentd configuration.

These filename requirements are an **observed POC REST contract**, not a claim that all Stellar Cyber versions use the same format. The UI documentation describes legacy uploads as `.json + .conf`, while the REST endpoint's accepted multipart filename pattern is different. Four preexisting POC custom-parser metadata entries confirmed the stored filename naming pattern without copying existing filenames or payloads.

A CONF containing only comments returned `400 Invalid port config`. The successful fixture used port `7891` (checked against the parser catalogue), `bind 127.0.0.1`, a Syslog source, and a null sink. No real log sources were reconfigured. The JSON body used the published five-step modular example layout, but **acceptance by the legacy REST CRUD endpoint does not prove that the resulting artifact works as a modular parser in the Stellar runtime**.

### Validation evidence and troubleshooting

The sequence of controlled attempts narrowed the contract:

| Input variant | Server response | Interpretation |
| --- | --- | --- |
| Single `name.json` uploaded | HTTP 422, `missing parser/conf files, or wrong parser/conf file name` | REST endpoint requires a paired file layout |
| `name.json` + `name.conf` | HTTP 422, same message | Uploaded parser filename does not match the expected REST naming pattern |
| `name` + `name.conf`, no port in CONF | HTTP 400, `Invalid port config` | File pair accepted; CONF requires a port declaration |
| `name` + `name.conf`, port 7891 with localhost binding | HTTP 200, full CRUD with version read-back | Validated REST test fixture accepted |

Each rejected attempt was followed by a parser list check: original count 4, no test parser residue. Successful CREATE/UPDATE/DELETE finished with the original count 4 and the unique test name absent.

## Reproduce safely on the approved test DP only

From `dev-atlas` in the isolated branch/worktree:

```bash
cd /home/aella/parser-studio-api-config
python3 scripts/probe_stellar_test_api.py           # safe auth and GET only
python3 scripts/test_stellar_parser_crud.py         # dry-run; no API calls
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

`python3 scripts/test_stellar_parser_crud.py --execute` is a **live mutation** operation and requires **explicit approval for the target test DP and tenant**. The one-time approval for this verified POC test is not a standing grant for other DPs, tenants, production releases, or permanent parser deployments.

Safety properties of the CRUD script: exact POC host allowlist, current-user 0600 credential load via existing helper, no JWT/key printing, random `ps_api_crud_test_...` identity, baseline name collision check, port-catalog collision check, response-status/error redaction, strict name-guarded PUT/DELETE, finally-block cleanup, final GET absence check.

## Not yet verified / distinct scope

- True Modular Parser upload/download/enable API: public Swagger's `/custom_log_parsers` CRUD works with the observed paired-file contract; it is not evidence that the 7.0 Parser Studio **modular UI workflow** has a matching public API.
- Activation/disable or sensor ingestion, real log parsing, port-binding after deployment, fluentd/runtime equivalence, and full user E2E.
- Tenant permissions outside the authorized POC. Root-level privileges remain a documented requirement for the **UI** workflow; current POC's User Scope Key demonstrably has REST CRUD access.
- Production API usage or release, which require separate approval.

Official references:

- https://docs.stellarcyber.ai/7.0.xs/Resources/SwaggerUI/dist/index-saas.html
- https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Custom-Log-Parser.htm
- https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Parser-Studio-Parsers.htm
- https://github.com/xdr-labs/stellar-data-exporter/blob/main/app/stellar.py

No customer parser content, existing parser names, private tenant IDs, or API secrets are included in this report.
