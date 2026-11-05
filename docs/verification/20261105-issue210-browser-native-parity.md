# Parser Studio — Issue #210 Parser Runtime Parity Remediation

## Scope

This change fixes eleven independently reproduced browser-versus-generated-Ruby correctness findings against `main` SHA `1f82f0c30af02a73d4d40977cd75b00d08ce3c03`.

It does **not** replace the parsing engine, execute arbitrary JSONata, add any DP/sensor writing path, or claim Stellar Cyber 7.0 target compatibility. The existing two UI workspaces and fail-closed DRAFT export model are retained.

## Corrections

| Finding | Change |
| --- | --- |
| F-01 P1 — Invalid enriched standard fields | Apply a statically pinned Stellar 7.0 mappable scalar-type catalog to every added official enrichment target, then verify the final `proto`/`proto_name` pair. All enrichment operates on a deep JSON-safe copy; on failure, only the previously validated normalization can appear alongside the static error code. |
| F-02 P1 — JSON depth mismatch | Apply native eight-level JSON source value-depth validation to browser JSON extraction, including wrapped JSON and the Auto Parser census. |
| F-03 P2 — Invalid Unicode escape | Reject unpaired UTF-16 surrogate code units in source JSON keys and values without rejecting valid pairs or multilingual UTF-8 data. |
| F-04 P2 — JSON object string mismatch | Implement bounded native JSON serialization with JavaScript-style array-index member ordering and numeric representation, without changing original log bytes. |
| F-05 P2 — ECS `@timestamp` unreachable | Allow exactly one special source identifier, the literal root key `@timestamp`, through browser selectors, JSONata review, UI contract, backend project schema and ParserRecipe source schema. No other special source segment or target field syntax is widened. |
| F-06 P1 — Receiver limit mismatch | Check each browser event against the actual configured receiver message limit in UTF-8 bytes; also include this limit in the value-free Auto Parser envelope census and review identity. |
| F-07 P1 — Bare CR falsely creates events | Keep CRLF-to-LF line ending handling but never silently promote bare CR to an independent physical log message. A bare CR blocks browser readiness. |
| F-08 P2 — TCP multiline JSON workflow | Expose an explicit sender-confirmation action for two or more valid LF-LF-delimited JSON events. Accept only TCP + reviewed blank-line JSON framing and verified backend capabilities; do not infer UDP or arbitrary multiline framing. |
| F-09 P1 — Integral-looking JSON floats | Accept only exactly integral and safe native Float values for integer/port/boolean lexical conversion, matching JavaScript's JSON numeric interpretation; fractional values still fail. |
| F-10 P1 — Native CIDR accepted as IP | Reject native IP values containing network masks and IPv6 zone identifiers before allowing IPAddr host literal validation. |
| F-11 P1 — Invalid ISO offsets/seconds repaired by Ruby | Apply bounded calendar/clock/timezone validation before Time.iso8601, including offset-minute and second-range restrictions. |

## Security and compatibility invariants

- Native project IR remains embedded as **one** Base64 project token with exact recompile-byte parity; the Stellar 7.0 scalar catalog is bundled as a static, code-reviewed JSON resource, not received from a user log or network service.
- The legacy API remains gated to synthetic-only, owner-approved, loopback/null-sink test scenarios. New generated template signatures require explicitly reviewed allowlist pinning, while the preexisting signatures and restrictions remain intact.
- Browser and Ruby error paths do not expose raw customer source lines. A failed enrichment does not emit invalid partially written enrichment values.
- Physical frame boundaries, project revision, source SHA, parsing grammar and source-mapping identity remain independently checked before DRAFT generation.
- Invalid source data is rejected; it is not silently rewritten or sent to an external AI service.

## Verification and release gates

- Frontend fixture tests `src/guided/issue210Parity20261105.test.ts` cover all eleven findings.
- Generated Ruby native tests `backend/test/issue210-parity-native-20261105.test.ts` exercise both base and conditional-family templates. Existing native and API/POC test suites remain required.
- User-like Chromium tests `tests/issue210-e2e.spec.ts` cover the exact 8192-byte receiver rule, TCP LF LF confirmation and `@timestamp` mapping review through generated DRAFT files.
- Exact-commit full frontend Vitest, TypeScript/Vite build, backend Node/Ruby tests, GitHub CI, published documentation scenarios and real browser E2E are required before merge or development-preview release.
- An actual Stellar Cyber 7.0 DP parser import and end-to-end ingestion are **NOT VERIFIED** by this change.

The independently reproduced original failures and source scripts are documented in [Issue #210](https://github.com/xdr-labs/parser-studio/issues/210). Newly executed regression evidence is recorded under `/home/aella/.local/state/parserstudio-issue210-evidence-20261105/`.


## PR #211 independent review correction (2026-11-05)

The review found a further ordered-Enrichment type drift in the initial
F-01 correction. A reviewed set_const(timestamp, ISO text) followed by
uppercase(timestamp to message) used to be accepted by both UI and authored
contract, but the first patch converted the timestamp to epoch milliseconds
during enrichment, making the second step fail only in native Ruby.

The final native contract now validates the timestamp text immediately but
preserves it for all ordered enrichment operators and classification (matching
browser preview). After those steps succeed, and before the record is emitted,
the native parser converts the validated timestamp to epoch milliseconds.
Invalid enrichment remains transactional and cannot expose unapproved fields.
Both native templates and browser fixture tests cover this timestamp-to-text
chain, and the exact reviewed synthetic-only Ruby template SHA was re-pinned
with the existing POC restrictions intact.
