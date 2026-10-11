# 06. Roadmap, Gates and Next Action

## 2026-10-12 Product priority correction

**Owner mandate:** replace external Ruby/Fluentd parser developer with a no-code, six-step Web UI for a nondeveloper. The required first output is the matched `customized_<slug>.conf` + extensionless Ruby `customized_<slug>` file pair matching the inspected `rickmodular` reference contract. Refer to [No-code UI contract](08_NO_CODE_USER_EXPERIENCE.md) and [Backend generation design / evidence](09_BACKEND_PAIRED_ARTIFACT_DESIGN.md). These requirements **take priority over the old Expert Workbench and generic Fluentd export work**. Do not require private raw log samples to start stable IR/compiler contracts or the no-code UI.

## Overall

**Goal:** Independently build a dependable Parser Studio Web application, with portable authoring and evidence-backed Fluentd/Stellar output.

### R0 — Foundation and product definition (THIS INITIAL REQUEST)

- [x] Create xdr-labs/parser-studio repository, private by default because future artifacts may contain sensitive data.
- [x] Persist product outcome, scope, competitor-driven UX, workbench specification, function backlog, version-neutral architecture and ordered roadmap.
- [x] Adopt Engineering System configuration and execution instructions.
- [ ] Reconfirm exact sample-derived parser compatibility contract **after the owner supplies samples**.
- **Done criterion:** published docs in Git, check actual file presence and commit SHA; no claim that parser execution exists.

### R1 — Samples, truth contracts and model (NEXT PRIORITY)

- [x] Inspect real parser artifacts from authorized `rickmodular` in read-only mode: 454 matched CONF + Ruby fragments, aggregate fields, routing and generator markers. Evidence: docs/09.
- [ ] Collect privacy-reviewed *raw event* samples for behavior and golden outputs (structure reference artifacts already inspected).
- [x] Classify observed artifact pair as extensionless Ruby fragment + Fluentd receiver/routing CONF. Official portal legacy/Modular JSON formats require separately proven adapters.
- [x] Identify primary config/source shape, type maps, timestamps and `stellar_log_index` classification from representative artifacts; unusual format subclasses remain to be covered in capability tests.
- [ ] Define portable IR v0.1 + JSON Schema and golden fixtures; privacy-screen all fixtures before commit.
- [ ] RED tests for correct extraction, type mapping, failures and native-runtime equivalence.
- **Done:** sample-based contract and fixture expectations; unknowns explicitly recorded.

### R1.5 — No-code compiler foundation (TOP PRIORITY)

- [ ] Finalize stable typed IR + schema from verified host structural evidence and synthetic tests.
- [ ] Build safe `.conf` + Ruby-fragment renderers for a declared supported subset with filename/name/tag matching and generator-section guards.
- [ ] Validate receiver protocols/port/frame settings, strict type map, date/zone, event classification and unsupported Ruby branches.
- [ ] Add isolated syntax/runtime testing; `ruby -c` alone is insufficient.
- **Done:** reproducible pair for synthetic fixture with verifiable native engine output and clear unsupported capability states, without touching live `rickmodular`.

### R2 — Guided Builder UI and optional Expert Workbench (P0)

- [ ] Commit/push preexisting local workbench scaffold (local dev-drlink: 13 unit/UI tests PASS + Vite build PASS; uncommitted/staged branch preserved). Treat this as optional Expert View, not product-complete.
- [ ] Implement six-step no-code Guided Builder (Upload logs → Extract → Map & enrich → Receive & classify → Native test → Generate two files) for ordinary users.
- [ ] Event splitting, format candidates, route variants and visual field highlighting.
- [ ] Rule builder with regex/JSON/KV/Syslog/CSV support and transformations.
- [ ] Typed normalization mapper to evidence-backed Interflow fields.
- [ ] Live RAW/EXTRACTED/NORMALIZED stage preview with test runner integration.
- **Done:** real sample E2E from paste to normalized preview; affected unit/integration/browser tests green.

### R3 — Native validation, regression and export (P0)

- [ ] Sandboxed pinned Fluentd runner with plugin capability manifest.
- [ ] Fixture suite, per-event diagnostics, error grouping, coverage and before/after diff.
- [ ] Revision storage with deterministic hashes, consistent result export.
- [ ] Verified `host-customized-pair` export adapter and native-engine test; separate conditional `portal-legacy-pair` and `modular-json` adapters.
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
- All samples (including minority variants) yield explained statuses.
- No hidden data loss or unsupported transformations on import/export.
- Exact artifact/version support explicitly backed by runner or target-import evidence.
- Customer data is isolated and not published by default.
- No production effects in the initial development path.

## Concrete NEXT_ACTION

**Start R1.5 stable IR and safe paired-artifact renderer from already inspected `rickmodular` reference files; create synthetic RED→GREEN fixtures and six-step Guided Builder UI.** Do not wait for more parser files; only private raw events and the exact target-portal loader proof remain for end-to-end validation. Preserve the existing staged `feat/ui-workbench-scaffold` branch and move its validated UI toward the Guided Builder rather than duplicating it. Use this file as the single canonical roadmap and carry precise Git/CI/fixture status into future handoffs.
