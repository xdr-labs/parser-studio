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

**Supported staged compilation (for identical 0.1 projection only):** `split_event(single-line)`, `unwrap_syslog(version=1, strict_header)`, one of `parse_json`, `parse_kv`, `parse_csv`, `parse_cef`, `parse_leef`; bounded `map_field` and adjacent typed `cast_type`; deterministic `classify(equals)`; terminal `fallback_unparsed(retain_unparsed)`. RFC5424 embedded JSON/KV/CEF/LEEF uses the independently reviewed v0.1 bounded parser implementation. Strictly allowlisted single-line mixed JSON/KV/CEF/LEEF events can now be dispatched using the declarative dispatch_family stage; generic mixed RFC3164/other Syslog envelopes beyond explicit RFC3164 TAG KV and RFC5424 CEF/LEEF, mixed CSV, arbitrary new operators, full RFC3164 time inference and unframed physical multiline are **NOT SUPPORTED**. Strict RFC3164 with PRI, BSD time/header and TAG: message may unwrap into KV/JSON/CEF/LEEF only, with year/timezone explicitly unknown and no date cast from the header timestamp. V0.1 enrichment or `exists` classification is rejected when it cannot be represented without loss; it is not silently omitted.

The generator validates both models, then reuses the existing vetted v0.1 compiler. The output's `contract` and `manifest` remain `host-customized-pair.v0.1` so exact historical inspect/ZIP/SHA behavior is preserved. A new additive `recipeReceipt` contains canonical recipe SHA-256, legacy project SHA-256, claimed source SHA-256, sample count and explicit `V01_EQUIVALENT_SUBSET` profile. No raw logs enter the Ruby fragment; only validated configuration is encoded as before.

Receipt flags `sourceHashVerifiedAgainstEvents=false`, `nativeUserParserVerified=false`, `targetImportVerified=false` remain **false**. They cannot be turned into PASS by calling v0.2 validate or generate.

## Offline native qualifications

`bash scripts/qualify.sh` generates eleven **public-synthetic-only**, source-SHA-bound v0.2/legacy-identical parser pairs in a fixed isolated fixture directory. The native Ruby 3.2 + Fluentd 1.17.1 smoke verifies:
- strict fixed fixture root, exact HEAD, complete file-name/hash set, no symlink/hardlink substitutions, and source SHA of every golden event;
- generated `.conf` Fluentd AST with the same source/parser receiver port (7501 in these synthetic fixtures) for TCP and UDP, and expected log-index rewriting;
- real Fluentd parser plugin callback and exactly one **typed** normalized record and time for each of seven independent golden cases: JSON, quoted KV-compatible, CSV, CEF, LEEF, RFC5424+CEF and RFC5424+LEEF;
- hard rejection of unrelated fixture roots.

The existing 10-profile / 23-golden-event native suite remains unchanged and runs in the same qualification job. The extra eleven native profiles prove the **synthetic v0.2-to-v0.1 compilation path** but **not** an arbitrary customer parser, proprietary Stellar loader, actual sensor listener, DP import/readback or tenant Interflow E2E.

## Remaining product work

- P0-AP1 backend RFC3164/mixed-event/multiline typed compilation and new native family fixtures.
- Broader v0.2 independent compound routing without depending on v0.1 semantics.
- UI v0.2 client negotiation/update and pinned backend CI SHA once both active lanes are reviewed (no PR merge implied).
- Optional isolated Drain3 inference, LLM consent/egress/authentication, and actual approved DP/sensor/Interflow evidence.

The receiving sensor destination port must **equal** generated `.conf` listener port, with Syslog ports **at least 6800**. Production, actual DP writes and sends, merge/release and user E2E remain separately gated.


## Explicit TCP blank-line framed JSON

Separate from the default single-line source, tcpFraming=blank_line_json requires TCP-only + JSON extraction + no arbitrary delimiter. Native Fluentd parses a fixed literal LF LF delimiter; the v0.2 split_event stage must exactly equal blank-line and match the legacy receiver, or compilation is rejected. The synthetic native suite checks two pretty-printed JSON objects in fixed framed order and confirms the generated Fluentd CONF AST and Ruby callback output, **not** a live sensor, open socket, or general Multiline support. See docs/json-blankline-tcp-subset.md for the precise upstream framing requirement.

## P0-AP1 strict mixed RFC5424 CEF/LEEF (additive)

The explicit 2–4 family single-line dispatcher now permits RFC5424+CEF and RFC5424+LEEF wrappers alongside standalone JSON/KV/CEF/LEEF, only when each branch is explicitly allowlisted. Strict header/structured-data parsing is reused; invalid headers and unsupported content are rejected with static diagnostics. Syslog wrappers require the same sensor/CONF listener port >=6800. Native Fluentd evidence includes one new mixed profile, three independent golden variants and eight independent negative inputs; still synthetic-only, with no claim of real Stellar import. See docs/mixed-rfc5424-native-subset.md.

## P0-AP1 additive strict mixed RFC3164 TAG: KV

The v0.1 mixedFormats allowlist and strict v0.2 dispatch_family stage now accept a bounded rfc3164_kv family alongside standalone JSON/KV/CEF/LEEF and RFC5424-wrapped CEF/LEEF. A rfc3164_kv branch is selected only by an explicit PRI + case-sensitive abbreviated-month signature, and the existing native RFC3164 TAG: + KV grammar remains authoritative. RFC3164 *never supplies a year, timezone, or inferred native event timestamp*; syslog_timestamp cannot be cast to a date in a mixed project containing this family. The receiver .conf port is the actual sensor port and must be >=6800 for any Syslog family. Native evidence includes a new 14th synthetic profile, 3 positive mixed RFC3164 cases and 9 malformed/unsupported fail-closed cases. This is not evidence of actual DP target import or live sensor traffic. See docs/mixed-rfc3164-native-subset.md.
\n## Additional bounded RFC5424 JSON/KV mixed families\n\nThe fixed strict mixed dispatcher now accepts rfc5424_json and rfc5424_kv when explicitly chosen. It reuses the same Native-qualified RFC5424 VERSION=1 envelope/header/structured-data grammar and previously qualified JSON object / strict KV body validators. A malformed or unsupported body yields one static extraction diagnostic, not a fallback or silent event loss. No arbitrary mixed CSV, RFC3164 non-KV, unframed multiline or guessed timestamps are implied. The separate Native Ruby+CONF fixture suite now includes 15 profiles with this additional family selection plus 3 independently authored RFC5424 JSON/KV mixed normalizations and 9 fail-closed cases. User generated DRAFT output and proprietary target-import status remain UNVERIFIED.\n\n## Strict RFC3164 TAG: + CEF/LEEF additional mixed body support\n\nThe same fixed, no-executable-code strict family router now accepts rfc3164_cef and rfc3164_leef in a 2–4-family mixed parser. The original RFC3164 TAG: header validator and strict CEF 0 / LEEF body extractors are reused verbatim; neither header year nor timezone can be inferred. A real Native Fluentd synthetic profile demonstrates generated .conf parser port parity and unchanged v0.2→v0.1 paired Ruby SHA. Only explicit family allowlists are legal. Dynamic routing, unframed multiline, unsafe Ruby and arbitrary RFC3164 bodies remain unsupported. See docs/mixed-rfc3164-cefleef-native-subset.md.\n
## P0 bounded TCP LF LF Java exception stack trace\n\nJava exception stack-trace support is limited to an explicitly selected TCP-only source with literal LF LF framing and strict bounded header/frame/cause grammar. The source controls event boundaries; no implicit Java multiline assembler, multiline UDP, or arbitrary regex is introduced. The fixed v0.2 parse_java_stacktrace plus split_event(blank-line) must compile to byte-identical v0.1 Ruby and CONF, with the same sensor/CONF port. The 17th public-synthetic Native Ruby3.2/Fluentd1.17.1 profile covers two Java events plus 9 strict malformed rejection cases. User-parser Native and real Stellar import remain false. See docs/java-stacktrace-blankline-tcp-subset.md.\n
## P1 reviewed mixed CSV subset (opt-in only)

Standalone CSV may now be explicitly selected alongside one to three other reviewed one-line family IDs, with exactly 2–4 mixed families per parser. Mixed CSV requires at least two unique reviewed valid column names and a **mandatory explicit** delimiter (comma, semicolon or TAB). The fixed dispatcher checks known JSON/KV/CEF/LEEF/Syslog signatures first; a CSV branch is allowed only with its fixed column/delimiter schema and a matching delimiter in the row. It never guesses a schema, auto-adds CSV for unknown text or invents a Ruby/regex step. Malformed CSV, mismatched column count, unsupported headers, duplicate KV, unframed multiline and unallowlisted CEF/LEEF are rejected with static safe extraction codes. The v0.2 dispatch_family exact stage must equal the v0.1 allowlist; identical Ruby/CONF SHA is required, and target/native user parser remain NOT VERIFIED. See backend/docs/mixed-csv-native-subset.md for independent fixed Native fixtures.
