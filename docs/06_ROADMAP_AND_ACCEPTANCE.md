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
