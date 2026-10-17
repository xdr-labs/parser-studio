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

- [ ] Create app skeleton, Workbench panes, sample upload/paste and raw event viewer.
- [ ] Event splitting, format candidates, route variants and field highlighting.
- [ ] Rule builder with regex/JSON/KV/Syslog/CSV support and transformations.
- [ ] Typed normalization mapper to evidence-backed Interflow fields.
- [ ] Live RAW/EXTRACTED/NORMALIZED stage preview with test runner integration.
- **Done:** real sample E2E from paste to normalized preview; affected unit/integration/browser tests green.

### P0-ME — Multi-Event Auto Parser: one deployable Stellar parser (owner decision 2026-10-17)

**Status:** PLANNED, not implemented. This is an R1–R4 product-roadmap handoff, **not** authorization to alter the isolated engine PoCs, existing product HEAD, native targets, main, deployment or release.

**Owner-confirmed Stellar capability:** A single Stellar Cyber parser supports multiple event families and family-specific **dynamic conditional normalization across all Stellar versions**. Do not impose a version selector, split one product into one parser per event type, or treat this platform capability as awaiting per-version proof. **Parser Studio's generated artifact and correct runtime behavior** still require native execution evidence before claiming our implementation is verified.

**Required outcome:** One security product may interleave Threat, Alert, User, Asset, Audit and additional/custom event types in the same stream. A user supplies diverse samples once and exports **one Stellar parser artifact**. Internal bounded routing/extraction/normalization variants are allowed; external one-artifact deployment and per-event correctness are mandatory. Event family names are not a hard-coded closed set.

| ID / milestone | Deliverable | Measurable acceptance |
| --- | --- | --- |
| **MEP-0 / R1 P0** | Build a **mixed-event-family source corpus and independent golden contract** with representative events from the same product, including unknown, ambiguous, missing-discriminator and malformed cases. | Per-event source bytes, family labels, extraction fields/values/UTF-8 spans and expected normalized fields are independently frozen; no self-generated oracle; denominators and UNSCORABLE recorded. |
| **MEP-1 / R2 P0** | Reuse the qualified Multi-Pass + Generic Structural + bounded Funnel for **shared envelope and body extraction** before family-specific processing. | Preserve original event/raw bytes, repeated fields, exact source values/spans and explicit unparsed regions; no forced parse success or vendor-by-vendor regex patches. |
| **MEP-2 / R2 P0** | Add **deterministic event-family classification and routing** using explicit type fields/message IDs first, then independently supported structural signatures and documented precedence. | Each event shows its chosen route and evidence. Conflicting, insufficient and unknown classifications abstain or stay PARTIAL/REVIEW_ONLY; no silent first-match misroute. |
| **MEP-3 / R2 P0** | Support **one common field map plus conditional family-specific dynamic normalization**, with typed coercion, precedence, collision and manual override rules. | Threat/Alert/User/Asset/Audit samples normalize to their proper target fields within the same project; no cross-family field leakage or silent key loss; unmapped data remains visible. |
| **MEP-4 / R2–R4 P0** | Add multi-type sample input, automatic family grouping, editable route/mapping review, and per-family RAW → EXTRACTED → NORMALIZED previews. | A beginner can identify and correct the problem family without changing already-correct families. Keep exactly **Auto Parser** and **ChatGPT Assisted Parser** authoring paths; no Wizard/Workbench revival and no automatic raw-log AI transfer. |
| **MEP-5 / R3 P0** | Compile the mixed family routing and dynamic normalization into **ONE deployable Stellar parser artifact**; no separate exported parser per family. | Native runner/import tests prove the generated single artifact actually chooses and normalizes distinct families. Keep runtime/export evidence separate from the owner-confirmed cross-version platform capability; no Stellar-version selection in authoring. |
| **MEP-6 / R3–R5 P0** | Run reproducible **single-artifact mixed-stream Full User E2E** with representative families and unknown/malformed controls. | Publish per-family route confusion/abstention, exact source-field/value/span TP/FP/FN, normalized-field accuracy, unknown/unmapped counts, raw-byte retention and false-complete results; preserve passing families when fixing one; pin candidate HEAD, fixture hashes and native artifact digest before owner acceptance. |

**Acceptance gate:** User creates, tests, reviews and exports **one parser for a mixed event stream**; all independently qualified family fixtures use the intended conditional normalization with no silent loss or false-complete. A successful browser preview or source extraction alone **does not** prove the generated native parser. The unresolved work is Parser Studio compilation/testing, **not** whether Stellar supports multi-event conditional normalization.

### R3 — Native validation, regression and export (P0)

- [ ] Sandboxed pinned Fluentd runner with plugin capability manifest.
- [ ] Fixture suite, per-event diagnostics, error grouping, coverage and before/after diff.
- [ ] Revision storage with deterministic hashes, consistent result export.
- [ ] Fluentd output adapter, actual native-engine test, honest compatibility labels.
- [ ] Implement Stellar-specific export only for formats grounded by sample artifacts and real target evidence.
- **Done:** repeatable test report and proven artifact for each supported adapter (no unsupported success).

### R4 — Production-quality usability / supportability (P1)

- [ ] Templates/library, advanced source mode, import error/loss reports and mapping suggestions.
- [ ] Responsive/accessible UI, bilingual labels, security and large dataset behavior.
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

## Cross-cutting acceptance

- Version-neutral editor can work without a running Stellar instance.
- **Single mixed-event Stellar parser:** multiple event families and conditional dynamic normalization must be authored and exported in one artifact, with native correctness demonstrated for the generated output; no Stellar version selector or one-parser-per-family requirement.
- All samples (including minority variants) yield explained statuses.
- No hidden data loss or unsupported transformations on import/export.
- Exact artifact/version support explicitly backed by runner or target-import evidence.
- Customer data is isolated and not published by default.
- No production effects in the initial development path.

## Concrete NEXT_ACTION

**Await owner sample log(s) and existing parser(s) as the only missing product-specific input; then immediately begin R1 characterization, IR/fixture contract and RED tests.** Until samples arrive, implementation may proceed only on independently specified, testable UI scaffolding without asserting Stellar export compatibility. Use this file as the single canonical roadmap and carry precise Git/CI/fixture status into future handoffs.
