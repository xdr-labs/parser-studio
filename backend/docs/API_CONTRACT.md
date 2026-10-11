# Parser Studio Backend API Contract v0.1

**Integration owner:** Backend PR #4; Web UI PR #3 consumes this interface later. No UI code is modified in this branch.

## Deployment boundary

Stateless Node 22+ HTTP service, bound only to `127.0.0.1:4179` by `npm start` unless explicitly reconfigured. **Not authenticated, not suitable for public deployment.** No CORS header is returned. Browser integration must use a same-origin reverse proxy with authentication/security added before public exposure.

No raw log content or executable Ruby is accepted by these endpoints. A complete declarative `ParserProject` (JSON Schema v0.1) is the request body.

## API

| Method and path | Request | Success result | Failure |
| --- | --- | --- | --- |
| GET `/health` | none | `{status:"ok",service:"parser-pair-backend",version:"0.1"}` | 404 for other paths |
| GET `/api/v1/parser-pairs/schema` | none | Current v0.1 JSON Schema | — |
| POST `/api/v1/parser-pairs/validate` | JSON `ParserProject` | HTTP 200 `{ok:true,issues:[]}` | HTTP 422 `{ok:false,issues:[{code,path,message}]}` |
| POST `/api/v1/parser-pairs/generate` | JSON `ParserProject` | HTTP 200 `{contract,files,manifest}` | HTTP 422 `{error:"INVALID_PROJECT",issues}` |

Responses include `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, same-origin resource policy. JSON input is limited to 256 KiB; oversized body is HTTP 413; non-JSON POST HTTP 415; malformed JSON HTTP 400. No server-side file write, no production deployment action, no RPC to Stellar Cyber.

## Project v0.1 essentials

Example request: [synthetic-firewall.json](../examples/synthetic-firewall.json).
Main fields: `schemaRevision`, `projectId`, `revision`, `slug`, `vendor`, `product`, `sourceCategory`, `receiver`, `extraction`, `normalization`, `classification`, optional `enrichment`.

**Extraction formats supported for limited, tested subsets:**

| `extraction.format` | Optional settings | Important limitations |
| --- | --- | --- |
| `json` | `maxDepth`: 1–8, default 8 | JSON object root; nested objects; invalid/deep JSON rejected |
| `kv` | none | Strict whitespace-separated key=value with optional quotes/backslash escapes; unknown suffix rejects |
| `csv` | `csvColumns` **required**, `csvDelimiter` optional `,`, `;` or TAB | Strict column count, quotes supported; one logical CSV record |
| `syslog_rfc5424` | `syslogBodyFormat`: `raw`, `json` or `kv` | RFC5424 header with single structured-data segment, not RFC3164 or multiline |
| `cef` | none | Standalone CEF:version, escaped header delimiter, strict KV extension subset; no Syslog-prefixed CEF |
| `leef` | none | Standalone LEEF 1.0 TAB and 2.0 one-character delimiter subset; not arbitrary LEEF extensions |

**Normalization:** `topFields`, `nsFields`, `vendorFields` maps with `normalized_name`, `data_type` (`string|integer|ip|port|boolean|date`), date `time_format:"iso8601"` plus explicit source timezone; `timezone:"UTC"` is available. Invalid ports, IP and unzoned timestamps fail. Names cannot collide with system fields or other outputs.

**Enrichment (ordered, optional):** `set_const`, `copy`, `lowercase`, `uppercase` with `source` (when applicable) and `target`. Duplicate/colliding output targets and nontext case conversions are rejected.

**Classification:** ordered `rules` of `field + operator (equals|exists) + index (session|threat|syslog|winlogevent)`; one `defaultIndex` required. Classifiers may reference available normalized/enriched fields; unmatched types produce transparent diagnostic states.

## Generated pair contract

```json
{
  "contract": "host-customized-pair.v0.1",
  "files": [
    {"name": "customized_sample_firewall.conf", "content": "...", "sha256": "...", "bytes": 753},
    {"name": "customized_sample_firewall", "content": "...", "sha256": "...", "bytes": 13350}
  ],
  "manifest": {
    "status": "DRAFT",
    "engineVerified": false,
    "targetImportVerified": false,
    "projectRevision": 1,
    "schemaRevision": "0.1",
    "fileHashes": {},
    "warnings": ["..."]
  }
}
```

The lengths and hashes above are illustrative and must be read from the **actual response**, not copied from the example. Both filenames are derived from `slug`, **not** arbitrary user filesystem paths. No `.rb` extension is added to the reference Ruby fragment.

**Do not change `status` to ENGINE_TESTED** solely because a separate synthetic Fluentd test passed. A per-project, sandboxed, bound native run with fixture evidence is necessary; actual Stellar Cyber loader/import verification remains separately assigned to the owner.

## Client integration sequence

1. GET schema → render the six-stage form inputs in the Guided Builder (the UI session owns layout).
2. POST /validate after editing → show `issues[].path` and `issues[].message`; do not discard incompatible rule edits silently.
3. POST /generate only on validated project → download two files, optionally create a client-side ZIP.
4. Show status **DRAFT**, evidence restrictions and exact filenames; never imply Stellar Cyber installation occurred.

Ruby callback diagnostics (to expose in future Test Lab after isolated native runner integration): `parser_err_msg` is a stable type/error marker, `parser_err_stage` indicates extraction/normalization/enrichment/classification, and `parser_err_field` identifies schema-controlled original field where applicable. The current HTTP API has **no user log execution endpoint**; no arbitrary user log/Ruby runtime is exposed.
