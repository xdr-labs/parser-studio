# ParserRecipe v0.2 — Strict, v0.1-equivalent backend compiler

## Scope and contract

This is a **real matched Ruby + CONF generator for an explicitly limited staged recipe subset**. It **does not** implement a general multi-family routing engine, full RFC3164 interpretation, multiline reconstruction, arbitrary Ruby, Grok, regex, JSONata, dynamic Python, arbitrary templates, or an LLM. No customer source event, raw sample or secret is submitted to the recipe compiler. The caller supplies a source SHA-256 and count for correlation; those are **not independently verified against raw source events by the backend**.

The **existing** ParserProject v0.1 schema, validate/generate endpoints and produced file contract remain unchanged. New, separate HTTP endpoints:

| Method | Relative path | Behavior |
|---|---|---|
| GET | `/api/v1/parser-pairs/recipe/v0.2/schema` | Strict JSON Schema for the reviewed staged recipe |
| GET | `/api/v1/parser-pairs/recipe/v0.2/capabilities` | Versioned supported/unsupported matrix, no native or target success claim |
| POST | `/api/v1/parser-pairs/recipe/v0.2/validate` | Strict metadata, ordered stages, mapping and semantic-equivalence checks |
| POST | `/api/v1/parser-pairs/recipe/v0.2/generate` | Deterministic pair of `customized_<slug>.conf` and extensionless `customized_<slug>` with exact SHA-256 |

For both POST calls, JSON root must contain **exactly** `{"recipe": {...}, "legacyProject": {...}}`. The `legacyProject` is the original, independently validated ParserProject v0.1 snapshot. It is not synthesized from untrusted AI stage text. The v0.2 recipe must match its project ID, source format, body format, every field mapping and typed cast, ordered classification, bounded single-line event policy, and explicit unparsed fallback. Any unknown stage, unmatched format, differently typed field, classifier change, extra property, unsafe source path, ambiguous runtime transformation or invalid 0.1 project fails closed with stable error codes and **no parser output**. Native/DP import claims supplied by the caller are invalid.

**Supported staged compilation (for identical 0.1 projection only):** `split_event(single-line)`, `unwrap_syslog(version=1, strict_header)`, one of `parse_json`, `parse_kv`, `parse_csv`, `parse_cef`, `parse_leef`; bounded `map_field` and adjacent typed `cast_type`; deterministic `classify(equals)`; terminal `fallback_unparsed(retain_unparsed)`. RFC5424 embedded JSON/KV/CEF/LEEF uses the independently reviewed v0.1 bounded parser implementation. Mixed families, arbitrary new operators, full RFC3164 time inference and physical multiline are **NOT SUPPORTED**. Strict RFC3164 with PRI, BSD time/header and TAG: message may unwrap into KV/JSON/CEF/LEEF only, with year/timezone explicitly unknown and no date cast from the header timestamp. V0.1 enrichment or `exists` classification is rejected when it cannot be represented without loss; it is not silently omitted.

The generator validates both models, then reuses the existing vetted v0.1 compiler. The output's `contract` and `manifest` remain `host-customized-pair.v0.1` so exact historical inspect/ZIP/SHA behavior is preserved. A new additive `recipeReceipt` contains canonical recipe SHA-256, legacy project SHA-256, claimed source SHA-256, sample count and explicit `V01_EQUIVALENT_SUBSET` profile. No raw logs enter the Ruby fragment; only validated configuration is encoded as before.

Receipt flags `sourceHashVerifiedAgainstEvents=false`, `nativeUserParserVerified=false`, `targetImportVerified=false` remain **false**. They cannot be turned into PASS by calling v0.2 validate or generate.

## Offline native qualifications

`bash scripts/qualify.sh` generates ten **public-synthetic-only**, source-SHA-bound v0.2/legacy-identical parser pairs in a fixed isolated fixture directory. The native Ruby 3.2 + Fluentd 1.17.1 smoke verifies:
- strict fixed fixture root, exact HEAD, complete file-name/hash set, no symlink/hardlink substitutions, and source SHA of every golden event;
- generated `.conf` Fluentd AST with the same source/parser receiver port (7501 in these synthetic fixtures) for TCP and UDP, and expected log-index rewriting;
- real Fluentd parser plugin callback and exactly one **typed** normalized record and time for each of seven independent golden cases: JSON, quoted KV-compatible, CSV, CEF, LEEF, RFC5424+CEF and RFC5424+LEEF;
- hard rejection of unrelated fixture roots.

The existing 10-profile / 23-golden-event native suite remains unchanged and runs in the same qualification job. The extra ten cases prove the **synthetic v0.2-to-v0.1 compilation path** but **not** an arbitrary customer parser, proprietary Stellar loader, actual sensor listener, DP import/readback or tenant Interflow E2E.

## Remaining product work

- P0-AP1 backend RFC3164/mixed-event/multiline typed compilation and new native family fixtures.
- Broader v0.2 independent compound routing without depending on v0.1 semantics.
- UI v0.2 client negotiation/update and pinned backend CI SHA once both active lanes are reviewed (no PR merge implied).
- Optional isolated Drain3 inference, LLM consent/egress/authentication, and actual approved DP/sensor/Interflow evidence.

The receiving sensor destination port must **equal** generated `.conf` listener port, with Syslog ports **at least 6800**. Production, actual DP writes and sends, merge/release and user E2E remain separately gated.
