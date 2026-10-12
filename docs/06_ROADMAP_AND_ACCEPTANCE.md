# 06 — Canonical Roadmap and Acceptance

**Product:** Replace the external Stellar custom parser developer with a complete **no-code** Web UI for field engineers, partners and customers.  
**Primary output:** `customized_<slug>.conf` **and** extensionless `customized_<slug>` Ruby source fragment.  
**Live task state:** [Issue #1](https://github.com/xdr-labs/parser-studio/issues/1) + active Work Packet + actual Git/PR/CI. This document defines stable *intent and done criteria*, not a claim about implementation completion.

For the NEW default three-step Auto Parser and strict development priority read [12](12_AUTO_PARSER_V2_PRIORITY_ROADMAP.md). The *existing secondary* six-step Guided Builder is documented in [08](08_NO_CODE_USER_EXPERIENCE.md); backend pair structure remains in [09](09_BACKEND_PAIRED_ARTIFACT_DESIGN.md). [Start Here](00_START_HERE.md) resolves document authority.

## 0. OWNER OVERRIDE — AUTO PARSER v2.0 IS FIRST (P0-AP, 2026-10-12)

**This section is the current implementation priority, ahead of the historical R1.5/R2/R3/R4 order below.** The current owner explicitly directed that ordinary users must be able to paste logs without knowing their format and generate a validated parser in a **three-step default experience**. Do not undertake further competitor research or redo already completed six-step, native synthetic, Test Lab or version-history functions. Full design, exact acceptance, per-lane first actions and licensing: **[12 — Auto Parser v2.0 Priority Plan](12_AUTO_PARSER_V2_PRIORITY_ROADMAP.md)**. Live progress remains in [Issue #1](https://github.com/xdr-labs/parser-studio/issues/1).

| Rank | Scope | Completion contract |
| --- | --- | --- |
| **P0-AP1 — FIRST** | Align browser auto-detection and backend capabilities; RFC3164/5424 envelope + JSON/KV/CEF/LEEF body; physical vs logical events; explicit mixed/unknown/unsupported ledger | Supported cases compile and pass native tests; unsupported cases never show false PASS; all records accounted |
| **P0-AP2** | Auto Parser is the default: **Add Logs → Review Results → Test & Generate**; keep old six-step Guided Builder as `Edit Details` and Workbench as `Expert` | No mandatory format/Regex/Ruby knowledge for supported happy paths; English Chromium beginner and privacy scenarios |
| **P0-AP3** | Target-independent `ParserRecipe v0.2` staged IR, strict validation/adapter, safe matched Ruby + CONF compiler | Native Ruby/Fluentd output parity for declared supported operators; no lossy silent v0.1 conversion |
| **P0-AP4** | All-sample/holdout regression, per-family coverage and explainable minimal repair proposals | No silent data loss, false compatibility labels, or regressions of previously passing variants |
| P1-AP5 | Isolated Drain3 template mining, representative sample selection, safe parser fingerprint reuse | New-text evaluation and licensing/resource bounds; semantics require review |
| P1-AP6 | Copy AI Prompt + Import AI Recipe, bounded JSONata transform subset, later explicitly opted-in integrated AI | Privacy/redaction/consent and schema/native revalidation; no arbitrary code/third-party log transfer by default |
| P1-AP7 | User-approved automatic repair, reusable patterns, measured task completion | Regression does not break accepted rules; metrics measured rather than presumed |

**Priority execution rule:** Finish only an already-running atomic test/fix/commit without destroying work, then implement the first genuinely incomplete P0-AP milestone **before returning to other runnable historical tasks**. UI PR #7 owns beginner UI/preview/evidence; backend PR #4 owns contracts/codec/compiler/native tests; documentation PR #2 owns planning only. Keep all independent worktrees and WIP intact. Historical R1.5/R2/R3 below are **existing baseline work**, not a competing "first" priority. R5 release gates remain separate and unchanged. Real DP writes, sensor sends, credentials, permissions, release/PR merge require their existing separate authorization. Sensor receiver port equals generated `.conf` listener port, with Syslog >=6800. All screens/code/docs English-only.

## 1. Invariants

- Default new user flow (owner priority): **Add Logs → Review Results → Test & Generate**. Detailed extraction, mapping, receive/classification, repair and export remain available in the **existing secondary six-step Guided Builder** and Expert Workbench. **No Ruby, Regex, Fluentd, or format selection required for supported beginner cases.**
- Version-neutral editing, **separate evidence-backed** host-reference pair, legacy portal pair and modular JSON export profiles. Never label a Ruby fragment as a portal JSON config.
- The reference `rickmodular` is read-only; no changes to running `td-agent`, production config or deployment without separate approval.
- Full correctness means actual native parser tests, typed mappings, routing behavior and target import where applicable. A browser-preview match or `ruby -c` is not full PASS.
- Preserve ongoing implementation work and its branch/HEAD/tests. The docs lane must not alter code or worktrees.

## 2. Verified baseline (read-only research, not current dev status)

| Area | Evidence | Not yet demonstrated |
| --- | --- | --- |
| Repository | Private `xdr-labs/parser-studio`, initial docs on main, no-code design in Draft PR #2 | Latest code/CI progress in the separate development session |
| Host reference | 454 matched `.conf` / extensionless Ruby snippets; one orphan, special receiver variants and embedded mapping metadata | How host snippets are assembled/registered into deployed parser plugins |
| Syntax | Four representative reference fragments returned Ruby `Syntax OK` | Golden raw-log behavior, native parser callback result and import acceptance |
| Real inputs | Real source structures inspected without copying proprietary source into Git | Approved raw event fixtures and validated expected Interflow records |

## 3. Ordered large milestones

### R0 — Product definition and source research
**Status: Documentation completed in Draft PR #2, not merged into main.** Goal, no-code UI, real paired-file structure and security limits documented. This does not mark implementation or runtime verification completed.

### R1 — Additional real-event evidence (parallel input, not a stop gate)
- [x] Inspect paired source structure, naming, normalization keys, receiver config and routing from `rickmodular`.
- [ ] Capture privacy-reviewed actual raw events for multiple event families, including malformed inputs and expected outputs.
- [ ] Confirm the exact real target portal upload/loader transformation contract separately from host reference files.
- [ ] Measure unsupported product-specific Ruby constructs and plugin dependencies.

**Exit:** real fixture/target claims have direct evidence. Work on R1.5 can proceed independently.

### R1.5 — Existing portable IR, validation and two-file compiler **P0 BASELINE (NOT CURRENT FIRST)**
- [ ] Define typed `ParserProject` v0.1 JSON Schema, ordered operators and internal project/fixture reference contract.
- [ ] Implement strict normalization metadata and field maps: `top_fields`, `ns_fields`, `vendor_fields`, `normalized_name`, `data_type`, date/zone and collision handling.
- [ ] Validate receiver protocol, port, framing, parser name/tag and `stellar_log_index` classification; distinguish stored sample port reuse from *active* conflicts.
- [ ] Implement reviewed/escaped templates that emit matching `customized_<slug>` + `customized_<slug>.conf` for a declared supported subset; unknown Ruby stays opaque/unsupported.
- [ ] Add deterministic synthetic RED→GREEN tests, Ruby syntax lint (where isolated available), loss report, pair-name/route consistency and SHA-256 manifest.

**Exit:** generated pair, validators and reproducible tests PASS at exact candidate HEAD. Do **not** claim full native engine compatibility yet.

### R2 — Existing secondary six-step Guided Builder **P0 BASELINE (NOT CURRENT DEFAULT)**
- [ ] Reuse/preserve existing local three-pane scaffold as optional **Expert View**, not a replacement workstream.
- [ ] Guided default: **1 Add Samples → 2 Extract Fields → 3 Map/Enrich → 4 Receive/Classify → 5 Test/Fix → 6 Generate/Download**.
- [ ] Offer visual field selection, multiple variant routing, type-safe Interflow mapping, conditional category rules, UDP/TCP/eligible HTTP controls and plain-language diagnostics.
- [ ] Provide create, basic clone/import, edit, save/reopen, failed-event navigation and honest compatibility/unsupported states.
- [ ] Connect compiled two-file download; do not silently drop unmatched or malformed events.

**Exit:** a nondeveloper completes the workflow with synthetic representative fixtures and produces internally consistent paired files without typing code; focused UI/unit test evidence on exact HEAD.

### R3 — Existing native runtime testing, regression and export **P0 BASELINE**
- [ ] Execute supported generated Ruby/Fluentd parser in an isolated pinned runner (time/CPU/memory/network restrictions); never run on the live reference host.
- [ ] Validate callback output, timestamps, normalization, enrichment, session/threat/syslog routing, failure paths and multi-event sample coverage.
- [ ] Store reproducible suite/run IDs, runner digest, golden output/fixture hashes, changed-field diff, redacted reports and artifact checksums.
- [ ] Export the paired files and manifest with status Draft / Syntax Valid / Engine Tested / Target Import Verified / Partial / Unsupported / Pending Evidence.
- [ ] Implement a vendor portal JSON/legacy adapter only after its exact input contract and real target import are verified.

**Exit:** fixture-based native behavior verified, target import status truthful, export is reproducible; no green on untested cases.

### R4 — Historical coverage and product quality **P1 (new P1-AP tasks specified above)**
- [ ] Expand parser templates, anomaly diagnostics, complex CEF/LEEF/multiline cases, safe extensibility, read-only opaque legacy imports and advanced editor.
- [ ] Accessible/responsive Korean/English UI; optional role-based persistence after separate security design; scale and privacy regression.
- [ ] Optional AI only with user opt-in and deterministic revalidation; never automatically transmit confidential logs.

**Exit:** newly supported capabilities have golden fixtures/tests and security boundaries.

### R5 — Browser acceptance, User E2E, release **GATED**
- [ ] Browser persona test for ordinary user / expert / administrator where applicable.
- [ ] Full User E2E against a real supported target on **same exact HEAD**, with confirmed file generation and import behavior.
- [ ] CI, provenance, machine qualification, review, freeze and public smoke per applicable Engineering System contract.
- [ ] Separate owner approval for release or production deployment.

**Exit:** actual acceptance evidence, never a narrative or syntax-check assertion.

## 4. Sequencing and ownership

**Code is being developed in other independent sessions.** Do not reset their branches or discard work. Finish any atomic in-flight test/commit safely and **then begin the first incomplete P0-AP1 → AP2 → AP3 → AP4 step ahead of any historical R1.5/R2/R3/R4 backlog**. Preserve existing completed work; implement only genuine new gaps, respecting real target/release approval gates. See [12](12_AUTO_PARSER_V2_PRIORITY_ROADMAP.md).

If real raw samples are not yet available, create strictly synthetic fixtures for schema/compiler tests, and mark real compatibility `PENDING_EVIDENCE`. This is not a blanket project blocker. Report only proven owner-action/environment limitations.

Record changing evidence (actual branch, HEAD, worktree, PR/CI, tests, blocker and NEXT_ACTION) in the single [Issue #1](https://github.com/xdr-labs/parser-studio/issues/1) and active Work Packet; keep this document's milestone requirements stable.

## 5. Overall acceptance

A first-time nonprogrammer can reliably turn representative raw logs into an explainable, well-tested Stellar-compatible **paired parser artifact**, with no missing events hidden from results and no manual coding. Native-runtime compatibility and actual vendor loader/import are separate demonstrated gates. No production effects by default.
