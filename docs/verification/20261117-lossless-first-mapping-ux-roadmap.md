# Lossless-first parsing and progressive mapping — Codex isolated engineering roadmap

Status: ACTIVE EXPERIMENT, 2026-11-17; owner authorized Codex in an isolated clone only.
Baseline: xdr-labs/parser-studio main af7de35; experiment begins after isolated LEEF improvement 20a700f.
Reference UI: read-only clone of datarelay-labs/datarelay-control main-v2 d909b32.
Scope: Auto Parser -> existing Review Fields and Map Fields, and existing ChatGPT Assisted Parser. The product continues to have only TWO top-level modes. No Wizard/Workbench restoration.
Do not push/merge/deploy, do not touch public preview, dev-atlas, original repo or managed DP, do not change known template approval constants. No new dependence on Control runtime/services.

## Owner acceptance hierarchy

1. P0 structural extraction correctness comes first. Preserve ALL source records and byte content, and account for every decoded value, delimiter, field and unparsed span. Merely retaining the raw line is NOT proof of full parsing. Never relabel unknown/partial as FULL without matching actual structured evidence.
2. Mapping cannot recover data lost by extraction. After extraction qualifies, apply safe, evidence-based Stellar Cyber 7.0 dictionary mappings. The goal is not artificial 100% automatic mapping rate.
3. For remaining source paths, offer optional ChatGPT suggestions (manual copy/paste with explicit privacy review, deterministic JSONata subset only), then user-directed searchable Stellar field selection and vendor field preservation.
4. User-selected mappings override AI/automatic proposals. Never let automated suggestions silently overwrite manually approved mappings. Do not invent Stellar fields, coerce incompatible types or hide duplicates/collisions.
5. Unmapped values are never silently discarded. Their original field names are shown to the user (leaf name where unique; full path retained internally to distinguish collisions), and their output disposition is visible. No artificial vendor or project prefixes in displayed leaf names. For unsafe/unaddressable paths, show preserved raw source + explicit mapping limitation. Explicit user opt-out for particular output field is deliberate mapping decision, not parser evidence.
6. Target Ruby 2.4.9, native Fluentd and real Stellar Cyber 7.0 import/indexing are distinct verification levels. Never claim release PASS from browser-only evidence.

## 2026-11-19 final isolated local acceptance (fixed-stop)

[Final host acceptance and external release gates](20261119-final-local-acceptance.md):
local source candidate `1db18cdbffc66c5990188317cb5cdd87c132b64f`
Vitest 2076/2076, Python 191/191 (same product code), TS semantic oracle 6288/6288
(same product code), typecheck and frontend/backend builds PASS,
Chromium novice/manual/AI **9/9** and same-head actual backend DRAFT authoring **2/2** PASS.
The local development phase is **COMPLETE**. LF-0 universal proof,
native Ruby/Fluentd, native-dependent backend suite, real captured vendor source
and managed Stellar Cyber DP7 import/indexing remain **UNVERIFIED** external gates.
No main merge, push or preview deployment.

## 2026-11-19 independent host qualification

[Verified local candidate and unresolved native/DP gates](20261119-lossless-first-host-qualification-v2.md):
Vitest 2,072/2,072, Python 191/191, semantic oracle 6,288/6,288,
Chromium novice/AI 10/10, same-head DRAFT 1/1, and an additional
live source-accounting Chromium 1/1 PASS. Native Ruby/Fluentd and real
Stellar Cyber DP7 import/indexing remain **UNVERIFIED**.

## 2026-11-18 implementation and independent host validation

[Verified local candidate and open gates](20261118-lossless-first-host-qualification.md).
Code HEAD `aac57970f1e7afda5eef20b1e4abb12fb85c3137`:
Vitest 2,063/2,063, Python 191/191, semantic oracle 6,288/6,288,
Chromium novice E2E 7/7 and same-head DRAFT Ruby/conf E2E 1/1 PASS.
Native Ruby 2.4.9/Fluentd and real DP7 target remain **UNVERIFIED**.
This is a local candidate, not a release/merge/deployment.

## Execution roadmap (strict dependency order)

### LF-0 — Baseline and source/value accounting contract [P0]
- [x] Identify and log examples of source completeness vs structured FULL vs output presence. Inspect classifyGenericStructural, lossGuard, fieldPaths, mapping-plan and every parser family involved. Evidence: [LF-0 baseline census](20261117-lossless-first-baseline.md).
- [ ] Produce independent deterministic field/value accounting proof on vendor-derived and adversarial fixtures (nested arrays/null/dotted keys, UTF-8, quoted CSV, CEF/LEEF, syslog, duplicates, >100/1024 fields, unsupported records). For each classify exactly FULL, PARTIAL or UNKNOWN; report bytes, events, leaves and residuals; never call synthetic data "real vendor".
- [x] Add RED tests for actual reproducible gaps, not superficial assertions that raw text survived. Treat nonmappable paths and false success separately. If nothing fails, document honestly and do not change working core code. Evidence: array source-value undercount RED/GREEN in [LF-0 baseline census](20261117-lossless-first-baseline.md); existing structural false-FULL mutation tests remain in `src/grammar/genericLossGuard.test.ts`.
Acceptance: no unaccounted event silently promoted to FULL; raw source hashes and data boundaries preserved; no regression of previously supported families; no change merely to improve percentage.

**Bounded local evidence (2026-11-19):** `src/guided/losslessAcceptanceMatrix.test.ts` supplies an independently authored expected-value subset, exact byte/hash receipt, actual parser status and event counts, and provenance for authored samples plus one vendor-derived RFC5424 holdout. It exercises JSON array/null/dotted keys, 128/1025 paths, mixed JSON/CEF/LEEF, quoted CSV, duplicate records, malformed JSON, empty objects, and a dotted-path collision. All residual receipts are absent, so every accounting proof remains UNKNOWN. This is local deterministic coverage only; it does not satisfy universal field/value accounting or establish vendor-original compatibility. See [final local closure receipt](20261119-lossless-local-closure.md).

### LF-1 — Loss guard and mapping eligibility [P0]
- [x] Fix confirmed generalizable extraction/coverage defects only. Byte-accurate residuals remain visible and repairable; no vendor-specific patchwork.
- [x] Surface independent statuses for retained source events, structural extraction, and mapped output coverage without conflating them. Source-only retention does not count as extracted or mapped. Evidence: the Map Fields coverage and final-event panels distinguish raw-event count, FULL/PARTIAL/UNKNOWN/ERROR counts, and source-present versus output-present values.
- [x] For PARTIAL/UNKNOWN events, show exact unresolved spans and a recovery path before mapping can be relied on.
- [ ] If unmapped parsed leaf cannot be emitted by native compiler, mark unsupported/blocked and retain raw; never count leaf as emitted. User selection to omit field must be explicit and previewed; cannot bypass parsing safety.
Acceptance: positive/negative evidence, sample fingerprint, omission/collision tests, browser+generated Ruby parity whenever native runner available.

**Bounded local UI evidence (2026-11-19):** existing `NormalizationMappingReview.test.tsx` covers browser-only emitted/not-emitted/no-rule/not-mappable states, null/array values, raw retention, manual rename, explicit leave-out and source raw omission toggle. `normalizationValidation.test.ts` covers mapping collision and type errors. Native compiler eligibility remains unverified; therefore the unchecked native-emission item stays open and browser preview is not represented as native output.

### MAP-1 — DR Control-style in-place three-column mapping UI [P1, after LF-0/1]
- [x] In existing Auto Parser "Map Fields" render "Source fields" (Tree/JSON, click to select, event tabs, original value + path + status), "Mapping rules" (source -> destination catalog search/selector, value type, origin, conflicts, user override), "Final event" (normalized preview, raw-vs-output diff, unmapped/omitted and residual warnings).
- [x] Borrow interaction principles, NOT Control runtime dependencies or dropping semantics: frontend/src/components/streams/wizard/wizard-basic-mapping-panel.tsx, mapping-json-tree.tsx, wizard-mapping-output-aside.tsx.
- [x] Field leaf display: source-port remains source-port (internal syslog_sd.element_1.params.source-port), recommended srcport. Likewise destination-port->dstport, raw values/path preserved. Evidence: `NormalizationMappingReview.test.tsx`, `juniperSdNormalization20261104.test.ts`, `vendorFieldNames.test.ts`, verified local [host qualification v2](20261119-lossless-first-host-qualification-v2.md).
- [x] Field-array/null/ambiguous-path choices are not phantom selectable: retain tree data and show NOT MAPPABLE / REVIEW guidance and safe recovery.
Acceptance: novice Chromium path from raw vendor log to source path, manually selected Stellar 7.0 field, preview, DRAFT Ruby/.conf download, accessibility/keyboard; no new top-level mode.

### MAP-2 — Progressive mapping: auto -> ChatGPT -> manual [P1, after MAP-1]
- [x] On first entry run existing deterministic official suggestions without overwriting approved mapping; show confidence, provenance, warnings and counts.
- [x] One contextual "Improve with ChatGPT" for remaining/ambiguous fields reuses JsonataMappingAssistant, manual privacy-reviewed copy/paste, fingerprint, local checks and explicit approval; never auto-send customer logs or run arbitrary JSONata.
- [x] Every original source path, including non-mappable, stays reviewable. Users click a safe source, search Stellar 7.0 field name/description, select or keep original vendor name; manual has highest precedence. Evidence: `NormalizationMappingReview.test.tsx` covers leaf labels/full paths, arrays/null, manual vendor retention, and approved/user-edited precedence; `vendorFieldNames.test.ts` covers nested syslog SD paths.
- [x] Recompute output preview and collision/type checks on each change; do not drop values, replace source labels with vendor/path prefixes or misreport target compatibility. Per-path disposition now uses the selected event's applicable source rule and exact normalized target lookup, and suppresses output claims for current blocking mapping findings. Evidence: `NormalizationMappingReview.test.tsx` reproduces a present rule with absent normalized target, same-event rename and explicit removal; `normalizationValidation.test.ts` covers output collisions and value-type findings. Browser/native output remains preview-only / UNVERIFIED.
Acceptance: mapping-origin precedence and negative tests for injection, approval bypass, conflicts, auto-overriding manual mapping and stale sample/response.

### QUAL-1 — Exact candidate verification [P2, after above]
- [ ] All existing Vitest/Python/backend tests, generated grammar TS->Ruby in sync, semantic oracle, negative corpus and targeted regressions.
- [x] Real Chromium novice E2E: Auto parsing -> automatic mapping -> optional ChatGPT-assisted mapping -> manual fallback -> preview -> DRAFT Ruby/.conf; mixed/multi-event, partial/unknown, unmapped and UTF-8 cases. Exact product-and-test HEAD `1db18cd`: **9/9 novice+AI and 2/2 same-HEAD live backend Chromium PASS**, evidence in [final local acceptance receipt](20261119-final-local-acceptance.md). This qualifies local browser and authoring behavior, not native Ruby execution or DP indexing.
- [x] Focused local-output Chromium journey in `tests/novice-mapping-output-contract-20261119.spec.ts`: same source sample through automatic vendor retention, explicit human field rename, privacy-reviewed JSONata proposal blocked by existing manual mapping, refreshed preview, and a DRAFT Ruby/.conf pair. Independent host Chromium **1/1 PASS** on code HEAD `3d12aee` (log `20261119-output-host-chromium-r5.log`). Backend validate/generate payloads were deterministically mocked: this verifies the UI workflow and same-origin privacy, not native Ruby or DP7 output.
- [ ] Native Ruby 2.4.9/Fluentd parity and no value loss from generated files if isolated runner available; otherwise report UNVERIFIED. Never conflate candidate DRAFT and real DP7 ingress/index proof.
- [x] Independent review, clean local commits and evidence receipt. No push, merge, preview rollout, production or target import without owner authorization.

## Current code and risk pointers

**2026-11-19 isolated increment:** [lossless accounting, Auto Parser UI integration, and exact local evidence](20261119-codex-lossless-accounting-increment.md). The oracle now runs in active Auto Parser Map Fields with index-bound Multi-Pass evidence and bounded async React state; deterministic holdout/adversarial corpus and component regressions are recorded. The independent broad FULL/PARTIAL/UNKNOWN source-value proof, browser E2E, native Ruby/Fluentd, and real DP gates remain open as documented there.

- Existing mapping UI: src/guided/NormalizationMappingReview.tsx (suggestions, Stellar catalog lookup, manual edit); src/guided/JsonataMappingAssistant.tsx (manual AI copy/paste + local review). Reuse; don't write a greenfield mapper.
- Existing mapping UI has "Left out of output", "Unmappable source values", omitSourceRaw and fieldPaths bounds (8 levels, normally 100 paths). These are NOT necessarily extractor loss, but they MUST be visibly distinguished and accounted.
- Existing src/grammar/genericParseStatus.ts has FULL/PARTIAL/UNKNOWN and src/grammar/lossGuard.ts. Do not bypass refusal or count source_raw as extracted leaf.
- Preserve every event, vendor field values, exact UTF-8 spans and residuals. Keep native export constraints, SC7-only mapping catalog. Separate source preservation from optional normalization.
- Work in locally committed units, tests before patch; don't assert complete without evidence.
