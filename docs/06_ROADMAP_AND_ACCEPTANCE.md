# 06. Roadmap, Gates and Next Action

## Overall

**Goal:** Independently build a dependable Parser Studio Web application, with portable authoring and evidence-backed Fluentd/Stellar output.

### R0 — Foundation and product definition (THIS INITIAL REQUEST)

- [x] Create xdr-labs/parser-studio repository, private by default because future artifacts may contain sensitive data.
- [x] Persist product outcome, scope, competitor-driven UX, workbench specification, function backlog, version-neutral architecture and ordered roadmap.
- [x] Adopt Engineering System configuration and execution instructions.
- [ ] Reconfirm exact sample-derived parser compatibility contract **after the owner supplies samples**.
- **Done criterion:** published docs in Git, check actual file presence and commit SHA; no claim that parser execution exists.

### R1 — Samples, truth contracts and model (NEXT PRIORITY)

- [ ] Receive representative raw logs and at least one actual parser artifact from owner.
- [ ] Classify artifacts: Fluentd config, Stellar legacy files, Stellar modular JSON or other.
- [ ] Identify syntax, ingestion/header rules, event families, normalization fields, timestamp policies and unsupported features.
- [ ] Define portable IR v0.1 + JSON Schema and golden fixtures; privacy-screen all fixtures before commit.
- [ ] RED tests for correct extraction, type mapping, failures and native-runtime equivalence.
- **Done:** sample-based contract and fixture expectations; unknowns explicitly recorded.

### R2 — Working web workbench / core parsing (P0)

- [x] Create original app skeleton, 3-pane Workbench, UTF-8 sample upload/paste and raw event viewer (**unit 17/17, build PASS, GitHub Chromium browser 9/9 PASS on commit d751252; full user E2E and native engine remain separate**).
- [ ] Event splitting, format candidates, route variants and field highlighting.
- [ ] Rule builder with regex/JSON/KV/Syslog/CSV support and transformations. Narrow browser-only regex/JSON/KV/CSV/RFC5424 subset implemented; full native semantics and route variants pending.
- [ ] Typed normalization mapper to evidence-backed Interflow fields.
- [ ] Live RAW/EXTRACTED/NORMALIZED stage preview with test runner integration. Browser worker, DIFF, per-event trace, save history and select-value→field-proposal flow implemented; native runner pending.
- **Done:** real sample E2E from paste to normalized preview; affected unit/integration/browser tests green.

### R3 — Native validation, regression and export (P0)

- [ ] Sandboxed pinned Fluentd runner with plugin capability manifest.
- [ ] Fixture suite, per-event diagnostics, error grouping, coverage and before/after diff.
- [ ] Revision storage with deterministic hashes, consistent result export.
- [ ] Fluentd output adapter, actual native-engine test, honest compatibility labels.
- [ ] Implement Stellar-specific export only for formats grounded by sample artifacts and real target evidence.
- **Done:** repeatable test report and proven artifact for each supported adapter (no unsupported success).

### R4 — Production-quality usability / supportability (P1)

- [ ] Templates/library, advanced source mode, import error/loss reports and mapping suggestions.
- [ ] Responsive/accessible UI, English-only labels, security and large dataset behavior.
- [ ] Optional AI assistance under strict opt-in/privacy and deterministic verification.
- [ ] Document packaging, operations, recovery and deployment boundaries.
- **Done:** consistent user journeys, no unsafe feature default, review-ready artifact.

### R5 — User acceptance and release (separate gates)

- [ ] Browser scenario PASS on the actual candidate.
- [ ] Full User E2E by user/operator/admin as applicable, same exact candidate HEAD.
- [ ] Freeze HEAD, qualification/CI/provenance/public smoke as the release contract requires.
- [ ] Owner acceptance; only then release or production deployment with explicit approval.
- **Done:** actual gate evidence, not a narrative assertion.

## Execution order

R0 → R1 → R2 → R3 → R4 → R5. Implement within the current runnable milestone; do not jump to AI helpers/templates ahead of parser correctness. Preserve owner-provided samples and uncommitted work. Follow Engineering System for small deterministic RED→GREEN changes and exact-HEAD evidence.

## Competitive UX adoption / priority lock (2026-10-12)

**Evidence:** [16-product UX/feature/license review + gap matrix](07_COMPETITOR_RESEARCH_AND_GAP.md) and [original UI decisions](08_UI_DESIGN_DECISIONS.md). The preferred synthesis is Cribl-like persistent staged preview, New Relic-like value-selection field authoring, QRadar-like highlighted field diagnosis, Google SecOps-like typed normalization, Datadog/Panther multi-sample test evidence; no vendor-proprietary code or assets reused.

- [x] Survey documented workflows and screenshots, record license constraints, prioritize differentiating functions.
- [x] Original visual shell, event list, stage preview, typed local mapping, source selection→field proposal, preview-only suite, privacy-preserving browser revision scaffolding.
- [ ] **P0-A:** GitHub Chromium browser smoke 9/9 PASS (d751252); developer desktop Chromium is missing system dependencies, so CI is the browser-test environment. Verify accessibility/keyboard traversal and final candidate HEAD before closing P0-A.
- [ ] **P0-B:** multi-family routing and multiline breaking; selected-source highlights and per-rule trace; strengthen regex safety.
- [ ] **P0-C:** native pinned Fluentd sandbox, golden fixtures, regression/baseline comparison.
- [ ] **P0-D:** real owner `.conf` and matching parser characterization, evidence-based target schema/adapter with import/export loss report. Owner-specific artifacts may not be assumed from public documentation.
- [ ] **P1:** English-only interface, advanced source mode, schema explorer populated from validated Interflow catalog, richer test/failure UX.

**Gates preserved:** R1 sample proof stays pending; R2 UI implementation may proceed while R1 is gated but is not a substitution for missing parser contracts. This is not a release or a claim of actual Fluentd/Stellar compatibility. Remaining work executes in the R1 → R2 → R3 → R4 → R5 order where runnable.

## Cross-cutting acceptance

- Version-neutral editor can work without a running Stellar instance.
- All samples (including minority variants) yield explained statuses.
- No hidden data loss or unsupported transformations on import/export.
- Exact artifact/version support explicitly backed by runner or target-import evidence.
- Customer data is isolated and not published by default.
- No production effects in the initial development path.

## Concrete NEXT_ACTION

**Await owner sample log(s) and existing parser(s) as the only missing product-specific input; then immediately begin R1 characterization, IR/fixture contract and RED tests.** Until samples arrive, implementation may proceed only on independently specified, testable UI scaffolding without asserting Stellar export compatibility. Use this file as the single canonical roadmap and carry precise Git/CI/fixture status into future handoffs.

## Owner language decision (2026-10-12)

Every Parser Studio screen, accessibility label, status, error, code comment, test, fixture, and project document must be written in **English only**. A bilingual UI is no longer in scope. All previously established import, target, privacy, and release gates still apply.


## R2 P0-B — Isolated mixed-family browser tests (implementation evidence, 2026-10-12)

A mixed sample set may include independently detected JSON, KV, CSV, bounded RFC5424,
standalone CEF and LEEF records. The Step 2 **Review One Event Family Separately**
control now permits an explicit local-only Web Worker preview of one recognized
extraction family while **preserving the entire original sample and the draft
unmodified**. The plan enforces 64 KiB/500 events and refuses stale, unsupported,
unknown or blank-line grouped source evidence rather than silently dropping
outliers. The summary includes exact source/selected/excluded counts, matched,
extracted, normalized and failed counts, and original physical-line numbers
with value-free diagnostic codes. No unredacted sample values appear in reports,
saved revisions, API requests or evidence downloads. The isolated fixture
stays transiently in browser memory and is passed only to the Web Worker. This is NOT native mixed-family routing,
a second generated parser, a live network sender or target import verification.

R2 P0-B is **partially implemented**; actual multi-parser native routing, robust
multiline event breakers, matched owner fixtures and real Stellar target validation
remain pending their respective backend/owner evidence gates. UI-only testing
continues independently without claiming a release gate has passed.

**Current development discipline:** This file contains historical acceptance
checklists; do not mistake old unchecked boxes for entirely unimplemented
features. Confirm actual HEAD, Work Packet, code and precise tests before
choosing the next runnable work item. Continue in R1 -> R2 -> R3 -> R4 -> R5
order, skipping only owner-input or unavailable runtime gates.


## R2 P0-A — Keyboard-operated source field → mapping correction (2026-10-12)

Extracted source-field chips in Guided Step 2 now have explicit accessible
button names and distinguish **review an existing mapping** from **add a safe
draft mapping**. One keyboard Enter/click action can add a **single reviewed,
conservative string** mapping in Step 3, using only the structural source
identifier produced by the existing safe unmapped-field suggestion contract.
The action preserves all current rules, refuses unknown/unsafe/prototype or
destination-colliding field paths and never stores or sends event values.
An existing mapping is opened without duplicate creation. The active rule is
visually distinguished with an accessible mapping label, and stage navigation
keeps keyboard focus on the destination heading.

This is browser/local draft usability and does NOT verify a vendor metadata
dictionary, type inference beyond the conservative string choice, or real
Fluentd/Stellar export. Keyboard, duplicate prevention, source retention,
privacy and unsafe-name regression paths are exercised through
tests/field-chip-mapping.spec.ts.


## R2 P0-A — Keyboard raw-value selection alternative (2026-10-12)

The no-code Step 2 value-selection path no longer requires mouse-only text
highlighting. A collapsed, explicitly labeled **Keyboard Alternative: Select
an Exact Raw Value** panel lets keyboard-only/mobile users enter a bounded
exact substring of the selected source event, then separately invoke the
existing field proposal workflow. An unmatched, multiline or overlong value
cannot enable the action. Values are transient in browser memory, are cleared
when the source sample changes, and are not stored in revisions, telemetry or
remote requests. The proposal still requires explicit test coverage and
acceptance before any draft rule can change.

Browser scenarios confirm actual keyboard Enter activation, no backend calls,
value-match validation, clearing stale input after sample edits, preserving the
original complete source and responsive 390px viewport layout. This is a
frontend accessibility/usability improvement, not a native runtime proof.

## R2 P0-B — Explicit all-family browser coverage without silent loss (2026-10-12)

The no-code Step 2 includes an explicit **Audit All Detected Families Locally** button in the existing non-destructive family-review workspace. Unlike the earlier single-family preview, this performs a **bounded, sequential Web Worker pass for each recognized supported format** in the current 64 KiB / 500-event source. The suite, original physical event lines, selected/excluded source counts and per-family worker outputs are cross-checked against the exact current draft and sample. Unknown or unsupported source events appear in an explicit ledger, with original line numbers but **no raw event values**. Every original event must be either reviewed in exactly one detected family or explicitly accounted for as unsupported; any stale sample, truncated family, changed worker event or inconsistent count fails closed.

Results contain only format identifiers, integer counts, source line numbers and diagnostic codes; no customer source bytes, normalized values, API keys or credentials are persisted, downloaded or transmitted. The user can still open and review individual family evidence without mutating the original source or draft. A successful browser family audit **does not create a native multi-parser routing rule, prove a Stellar parser export, or satisfy the pinned Fluentd and target E2E gate**. Existing R1 owner-supplied artifacts and R3 native proof are still required; do not mark those tasks complete. Unit tests and Chromium source-preservation/unknown-family/keyboard/privacy regressions are in `src/guided/familyAudit.test.ts` and `tests/all-family-audit.spec.ts`.

## R2/R3 — Redacted all-family audit evidence (2026-10-12)

The all-family local-only audit can now be **explicitly downloaded as metadata-only JSON**. The export recomputes the exact original sample/family allocation and checks the full browser preview, each reviewed family's source-line identity and status, all unsupported events, count invariants and false runtime/target verification flags. It binds the result to SHA-256 hashes of the exact sample and draft but never exports raw records, mapped/normalized field values, arbitrary diagnostic text, private parser fragments, API keys or tenant data. A changed draft/sample invalidates the download path. The full original sample and each unsupported event remain accounted for in the report, while a separate warning makes clear this is **not** native mixed-family routing or Stellar target validation. Download is optional and browser-only; it does not upload or save any customer logs. Unit/browser regression tests assert value-free output, deterministic provenance, and fail-closed behavior for tampered/untrusted metadata.

## R2 P0-B — Whitelisted local audit diagnostics (2026-10-12)

A regression test exposed that an arbitrary, uppercase Web Worker diagnostic code could be copied into browser-visible metadata. This was corrected at the shared family-isolation summarizer: **only fixed, previously reviewed parser diagnostic codes are retained**, and unknown codes are replaced by `DIAGNOSTIC_UNAVAILABLE`. The same allowlist protects both one-family previews and the new all-family reports. Step 2 displays at most eight sanitized source-line/status/diagnostic summaries per family, preserving full aggregate counts and keeping all actual log bodies and diagnostic messages out of reports. Unit tests deliberately inject private-looking worker diagnostic codes and verify neither those identifiers nor messages escape.

## P0-LIVE-0/2 — Owner-scoped offline artifact revision UI (2026-10-12)

Guided Step 6 has an **opt-in** offline revision workspace for exact generated
DRAFT Ruby + CONF pairs. The separately maintained backend supplies
`/api/v1/parser-pairs/revisions/register`, `list`, `diff`, `download`, and
`restore-preview`. The browser verifies the input pair, project-scoped
metadata, revision identity, two file hashes, immutable ZIP SHA-256 and
restore-preview response contract before displaying or downloading anything.
Diffs expose only version, port, filenames and SHA values, never code bodies,
raw sample logs, keys, or tenant identifiers.

No request is made until the owner explicitly clicks an action. All requests
use same-origin authentication; an unconfigured or unauthorized endpoint
returns **403 and stays unavailable**. The backend history is owner/tenant
scoped, temporary and non-persistent. A restore preview returns an old,
verified ZIP for optional manual download: it does not replace the draft,
rollback any actual DP parser, send to a sensor, or invoke any target API.
Native compatibility and actual platform ingestion remain unverified.
Unit regressions: `src/guided/artifactRevisionClient.test.ts`.
Chromium user/denial/tamper scenarios:
`tests/artifact-revision-history.spec.ts`.

## P0-LIVE-2 — Explicit MOCK_ONLY Apply UX (2026-10-12)

When the owner-scoped revision list is explicitly loaded, Step 6 offers a
separately collapsed **MOCK_ONLY Apply Test** for its current immutable DRAFT
revision. A user may check the temporary mock status, then enter a server-issued
mock approval reference and explicitly confirm before submitting a metadata-only
request to `/api/v1/parser-pairs/target/apply`. The client refuses any proof
that is not strictly `MOCK_ONLY` against a `.invalid` HTTPS destination,
does not contain the selected revision's exact file hashes, or claims real
runtime, target import or sensor verification. It never collects or submits
DP URLs, DP API keys, raw logs, sensor addresses, or generated Ruby/CONF bodies.
The default response is 403 unless a trusted server operator enables the mock
gateway. The user cannot turn this into real deployment using browser controls.

This is a pre-production mock contract and does **not** satisfy general-user
DP Apply, actual parser installation, same-port sensor proof, or Full User E2E.
Those separate tasks remain gated by the authenticated real backend
and owner-authorized target evidence.

## R2/P0 Test Lab — Redacted summary and integrity-checked evidence download (2026-10-12)

The existing owner-authorized Test Lab session workspace now has a separately
collapsed, **opt-in offline evidence review** for the authenticated run. Its
read-only same-origin `GET /api/v1/test-lab/sessions/evidence-summary` action
displays bounded stage counts, field match/mismatch/missing and coverage ratios,
and a fixed allowlist of failure codes, never source values. Its separate
`evidence-export` download verifies size, attachment headers, exact run ID,
optional previously reviewed artifact revision ID, UTF-8 JSON schema, per-event
stages and SHA-256 from the backend before downloading the original bytes.
Unsupported or cross-owner endpoints are denied by default (403/404); the
browser never infers authorization from knowledge of a run ID.

The panel does not automatically query, persist evidence, configure a Test Lab
sink or send events. The result is explicitly **OFFLINE_CONTRACT** and remains
unverified for real sensor reception, native Ruby/Fluentd parsing, Stellar DP
ingestion and Full User E2E even when an offline mock field comparison is
reported. No raw logs, private event values, tokens, credentials or target
locations are sent or exported. Synthetic RED→GREEN regression coverage:
`src/guided/testLabEvidenceClient.test.ts` and
`tests/testlab-evidence-report.spec.ts`.

## R2 P0-B — Per-event, per-rule browser-only diagnostics (2026-10-12)

Guided Step 5 now includes a keyboard-accessible **Inspect Rule-by-Rule
Outcome** panel. It consumes the current draft-bound browser Web Worker
preview and shows each mapping rule by numeric index, with fixed diagnostic
states for emitted output, missing source, invalid type, unsafe/unsupported
rule, ambiguous duplicate destination, incomplete extraction or unresolved
output. Users can choose an event number, review a rule, and jump to its
existing editable Step 3 mapping card without changing its field contents.

No raw sample values, normalized values, arbitrary untrusted diagnostic
messages/codes or customer log bodies are copied into the trace. The entire
source remains unchanged and no network request, native runner, sensor send,
DP registration or automatic transformation occurs. Stale source/draft
previews and forged native verification flags are rejected. Unit regression:
`src/guided/browserRuleTrace.test.ts`. Chromium keyboard/navigation,
source-retention, stale-edit and data-leak scenarios:
`tests/browser-rule-trace.spec.ts`.

This completes only the local **per-rule inspection usability** part of
R2 P0-B. Actual multi-family native routing and robust Fluentd multiline
event breaking remain unverified and must not be marked complete.
