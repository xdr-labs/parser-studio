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
| GET `/api/v1/parser-pairs/capabilities` | none | v0.1 supported formats, receivers, import restrictions, target status and size limits | HTTP 405 for non-GET |
| POST `/api/v1/parser-pairs/validate` | JSON `ParserProject` | HTTP 200 `{ok:true,issues:[]}` | HTTP 422 `{ok:false,issues:[{code,path,message}]}` |
| POST `/api/v1/parser-pairs/generate` | JSON `ParserProject` | HTTP 200 `{contract,files,manifest}` | HTTP 422 `{error:"INVALID_PROJECT",issues}` |
| POST `/api/v1/parser-pairs/inspect` | `{name,confContent,fragmentContent}` | Inspection with SHA-256, importStatus, safe diagnostic codes, portableProject only for byte-exact internal output | HTTP 422 `{error:"INVALID_PAIR"}` |
| POST `/api/v1/parser-pairs/package` | `{pair,version}` previously generated exact PairExport + version, no DP credentials | Raw application/zip with immutable Ruby, CONF and manifest.json, response revision + SHA-256 headers | HTTP 422 ARTIFACT_* on invalid pair, 400 invalid JSON, 413 oversized |

Responses include `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, same-origin resource policy. Validate/generate JSON input is limited to 256 KiB; import/inspect body is limited to 2 MiB and never executes Ruby. Oversized body is HTTP 413; non-JSON or non-UTF-8 declared JSON charset HTTP 415; malformed JSON or invalid UTF-8 bytes or unpaired JSON Unicode escapes HTTP 400 (no replacement decoding). No server-side file write, no production deployment action, no RPC to Stellar Cyber.

## Backend capability negotiation

GET /api/v1/parser-pairs/capabilities returns a stateless capability contract with no file bodies:

- contract = host-customized-pair.v0.1; projectSchemaRevision = 0.1; receiverProtocols (udp/tcp) and extractionFormats (json/kv/csv/syslog_rfc5424/cef/leef) reflect the validated schema.
- authoring.formatCoverage = reviewed-bounded-subset. Adjacent RFC5424 structured-data blocks have bounded 1024-byte structural support only (authoring.rfc5424AdjacentStructuredDataSubset and rfc5424StructuredDataMaxBytes); full SD semantics are NOT claimed. HTTP receiver, multi-distinct-port receiver, multiline events and arbitrary Ruby authoring are false. Opaque legacy files can be inspected but never treated as an editable clone.
- import.exactInternalPairsEditable is true ONLY for byte-identical output of our reviewed generator. import.unknownLegacyRubyEditable is false.
- verification.nativeSyntheticProfile = ruby3.2.3-fluentd1.17.1 identifies the pinned offline synthetic test runner only. liveListenerVerified, proprietaryLoaderVerified, targetImportVerified and engineVerified are all false. Never infer production or vendor import compatibility from this endpoint.
- limits.maxProjectBodyBytes = 262144; limits.maxInspectBodyBytes = 2097152. No customer logs, source files or secrets are present.

## Project v0.1 essentials

Example request: [synthetic-firewall.json](../examples/synthetic-firewall.json).
Main fields: `schemaRevision`, `projectId`, `revision`, `slug`, `vendor`, `product`, `sourceCategory`, `receiver`, `extraction`, `normalization`, `classification`, optional `enrichment`.

**Extraction formats supported for limited, tested subsets:**

| `extraction.format` | Optional settings | Important limitations |
| --- | --- | --- |
| `json` | `maxDepth`: 1–8, default 8 | JSON object root; nested objects; invalid/deep JSON rejected |
| `kv` | none | Strict single-line key=value with optional quotes/backslash escapes; literal CR/LF and trailing garbage reject |
| `csv` | `csvColumns` **required**, `csvDelimiter` optional `,`, `;` or TAB | Strict column count and quoting, one physical CSV line only; literal CR/LF rejects |
| `syslog_rfc5424` | `syslogBodyFormat`: raw, json, kv, cef or leef | RFC5424 v1 header with bounded printable-ASCII HOSTNAME/APP-NAME/PROCID/MSGID and explicit RFC3339 timestamp or NILVALUE, bounded adjacent SD elements (up to 1024 bytes), optional nested CEF/LEEF under body.*; no RFC3164, multiline or arbitrary vendor extension syntax |
| `cef` | none | Standalone single-line CEF version 0 only, escaped header delimiter and strict KV extension subset; RFC5424-enveloped CEF uses explicit syslog body mode, no arbitrary prefixes |
| `leef` | none | Standalone LEEF 1.0 TAB and bounded LEEF 2.0 one-byte or hexadecimal 0xHH delimiter subset; ambiguous separators, incomplete escaping, empty extension tokens and CR/LF reject |

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

## Read-only import/clone contract

`/inspect` accepts a paired host-reference `.conf` and extensionless Ruby source fragment in memory. It scans structural markers and receiver metadata only; **never evals Ruby, writes files, or echoes the original imported source**.

- `importStatus:"EDITABLE_EXACT"` and `portableProject` are returned **only** when the import is byte-for-byte identical to a valid pair emitted by our own reviewed compiler from the decoded IR. This is not equivalent to Stellar Cyber verified compatibility.
- Arbitrary legacy/proprietary Ruby remains `importStatus:"OPAQUE_READ_ONLY"`, `roundTripVerified:false`, `portableProject:null`. The UI can display protocols, port(s), marker existence and warnings but cannot silently rewrite it as a lossless no-code project.
- The response includes SHA-256 of both original files for provenance. Never publish, upload to public AI, or store customer/vendor file bodies in Git; authenticated private storage needs a future design.

### Import/inspect structured diagnostics

The inspect response includes diagnostics with stable code, severity=warning and a static message. Codes are CONF_NO_SOURCE, CONF_UNSUPPORTED_PROTOCOL, CONF_INVALID_PORT, CONF_SOURCE_MISMATCH, CONF_SOURCE_MISSING_REFERENCE, CONF_RECEIVER_NOT_EDITABLE, CONF_MULTI_PORT_LAYOUT, RUBY_MARKERS_INCOMPLETE, RUBY_PARSE_ENTRY_MISSING and PAIR_NOT_REPRODUCIBLE. Invalid pair errors return HTTP 422 with issues containing code, path and message; error codes are PAIR_NAME_INVALID, PAIR_CONTENT_INVALID and PAIR_SIZE_EXCEEDED. Neither editable nor opaque inspection verifies live Fluentd transport, proprietary loader or Stellar Cyber target import. No source bytes are returned for opaque inspected pairs.

## Client integration sequence

1. GET schema → render the six-stage form inputs in the Guided Builder (the UI session owns layout).
2. POST /validate after editing → show `issues[].path` and `issues[].message`; do not discard incompatible rule edits silently.
3. POST /generate only on validated project → download two files, optionally create a client-side ZIP.
4. Show status **DRAFT**, evidence restrictions and exact filenames; never imply Stellar Cyber installation occurred.

Ruby callback diagnostics (to expose in future Test Lab after isolated native runner integration): `parser_err_msg` is a stable type/error marker, `parser_err_stage` indicates extraction/normalization/enrichment/classification, and `parser_err_field` identifies schema-controlled original field where applicable. The current HTTP API has **no user log execution endpoint**; no arbitrary user log/Ruby runtime is exposed.

## P1 offline synthetic starter templates

The optional backend utility in src/parser-templates.ts provides six reviewed
portable-schema starters: JSON, KV, CSV, RFC5424 Syslog, CEF and LEEF.
They compile into deterministic DRAFT Ruby/CONF pairs after the user selects
a project ID, parser slug, revision, one shared listener/sensor port, and
UDP/TCP protocol(s). Syslog requires port >= 6800. No fixture or template
asserts that a real vendor log, native Fluentd engine or Stellar loader was
tested. The synthetic mapping is only an editable starting suggestion.

The catalog intentionally does not include proprietary customer samples,
credentials, target references, automatic deployment or receiver port
reservation. The exported utility is currently not connected to the default
HTTP service or UI; those wiring changes require separate safe review.

## P1 read-only import loss assessment

The backend import-loss-report utility delegates to the existing bounded
PairInspection validator. An exact, byte-identical generated pair is labeled
EXACT_EDITABLE. Any older, unknown or modified Ruby/CONF pair remains
OPAQUE_KEEP_ORIGINALS with knownConversionLoss=null (unknown), and must retain
the original source. No unsupported Ruby is evaluated or silently converted.

The report includes only source SHA-256 values, discovered structural ports,
supported protocol names and fixed diagnostic codes. It never includes source
Ruby, CONF text, customer event values or credentials. It does not perform a
target write, imply real loader verification, or add any network routes.
