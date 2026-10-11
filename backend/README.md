# Parser Studio backend — R1.5 isolated integration contract

**Ownership:** Backend only. Other session owns the Web UI in Draft PR #3. This branch deliberately changes only `backend/**` (the denied workflow lives only as a template under `backend/docs/`); it does not modify any UI, legacy docs, remote td-agent or production target.

## Supported, precisely

- Strict, version-neutral `ParserProject` 0.1 JSON Schema in [schema/parser-project.v0.1.schema.json](schema/parser-project.v0.1.schema.json).
- Safe JSON / basic whitespace-delimited key=value extraction, with top-level, nested and vendor mappings; typed `string`, `integer`, `ip`, `port`, `boolean`, `iso8601 date`.
- Ordered classification by `equals` or `exists`, default `syslog`, and a generated `stellar_log_index`.
- UDP/TCP source blocks, host-reference custom parser type/tag, transport settings include and rewrite-tag routing.
- Deterministic compiler produces two files, **`customized_<slug>.conf` and extensionless `customized_<slug>`**, with SHA-256 and an explicitly **DRAFT** manifest.
- Local stateless HTTP validate/generate and schema endpoints for the separate UI to consume. No file writes from API.
- Node unit/API tests **8/8 PASS**, three generated Ruby fragments passed syntax checks, and eight synthetic Ruby callback cases passed using a project-local Ruby 3.2.3 runtime on dev-drlink. These are **not native Fluentd or Stellar import tests**. The pending GitHub Actions workflow is a documentation template because the current OAuth token lacks workflow modification scope.

**Not supported yet:** real vendor upload adapters, true Fluentd/plugin registration or runtime validation, enrichment, regex/Grok, CEF/LEEF, arbitrary Ruby, product-specific branches, HTTP receiver, multi-line parsing, real private sample log fixtures, production deployment. The asset is a Ruby **fragment**, not a standalone Fluentd plugin. The manifest must never claim `ENGINE_TESTED` or `TARGET_IMPORT_VERIFIED` based solely on Ruby harness tests.

## Run

```sh
cd backend
npm ci
npm run check
npm test
npm run build
npm start                  # listen only on 127.0.0.1:4179
```

To run the **synthetic Ruby-only smoke test** when Ruby is installed (or after the workflow template has been explicitly enabled with suitable GitHub permissions):

```sh
node dist/scripts/create-synthetic.js
ruby -c .tmp/native-fixtures/customized_sample_firewall
ruby -c .tmp/native-fixtures/customized_sample_kv
ruby -c .tmp/native-fixtures/customized_sample_extended
ruby test_native/fragment_smoke.rb .tmp/native-fixtures
```

These are not Fluentd or actual Stellar target tests.

## Web UI contract

All API input/output is UTF-8 JSON; **no CORS response header** is provided. For development, run UI and backend through a same-origin proxy; do not expose this unauthenticated backend on a public interface.

| Endpoint | Request | Response |
| --- | --- | --- |
| `GET /health` | — | `{status:"ok",service:"parser-pair-backend",version:"0.1"}` |
| `GET /api/v1/parser-pairs/schema` | — | JSON Schema for all guided form controls |
| `POST /api/v1/parser-pairs/validate` | Complete `ParserProject` JSON | `{ok,issues:[{code,path,message}]}` and HTTP 422 on invalid |
| `POST /api/v1/parser-pairs/generate` | Complete `ParserProject` JSON | `{contract, files:[{name,content,sha256,bytes}],manifest}` or HTTP 422 |

**Usage contract:**

1. UI constructs the typed project draft using field selection/mapping/receiver controls; it does not send arbitrary executable Ruby.
2. Call `/validate` to show exact schema/collision issues before the Generate button can proceed.
3. Call `/generate` only on a valid draft. UI downloads both returned files and may offer a ZIP constructed *locally*, without incorrectly appending `.rb` to the extensionless file.
4. Show the backend `manifest.status` (**DRAFT**) and warnings; the UI must not label the output verified or installed.
5. **No raw log samples** are part of the R1.5 model/API. A later private fixture/preview API needs a separate security and persistence contract.

Example payload is in [examples/synthetic-firewall.json](examples/synthetic-firewall.json) and includes documentation-only synthetic RFC5737 IPs. All paths and filenames are derived strictly from validated model fields; the HTTP API never accepts arbitrary filesystem paths.

## Persistence and security boundary

The server is stateless, bounded to 256 KiB JSON input and bound to loopback by default; not remotely published and has no authentication or tenant isolation yet. It does not execute Ruby or manage files. Generated Ruby embeds model JSON as Base64 to prevent source-code injection; only a reviewed fixed template is emitted. The runtime runner must be separate, pinned, isolated and privilege-limited before it processes untrusted customer records or before this is made multi-user.

**Integration note:** The docs/no-code-custom-parser-design PR #2 sets the future six-step UX and full generator requirements. Do not merge this backend without reconciling its API contract with the UI PR #3, which may independently advance.
