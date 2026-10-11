# 06 — Canonical Roadmap and Acceptance

**Product:** Replace the external Stellar custom parser developer with a complete **no-code** Web UI for field engineers, partners and customers.  
**Primary output:** `customized_<slug>.conf` **and** extensionless `customized_<slug>` Ruby source fragment.  
**Live task state:** [Issue #1](https://github.com/xdr-labs/parser-studio/issues/1) + active Work Packet + actual Git/PR/CI. This document defines stable *intent and done criteria*, not a claim about implementation completion.

For the default six-step UX read [08](08_NO_CODE_USER_EXPERIENCE.md). For actual source/CONF pair structure and compiler design read [09](09_BACKEND_PAIRED_ARTIFACT_DESIGN.md). [Start Here](00_START_HERE.md) resolves document authority.

## 1. Invariants

- User workflow: sample logs → visual field extraction → Stellar normalization/enrichment → receiver and event classification → test and fix → generate/download two files. **No Ruby, Regex or Fluentd editing required.**
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

### R1.5 — Portable IR, validation and two-file compiler **P0: FIRST**
- [ ] Define typed `ParserProject` v0.1 JSON Schema, ordered operators and internal project/fixture reference contract.
- [ ] Implement strict normalization metadata and field maps: `top_fields`, `ns_fields`, `vendor_fields`, `normalized_name`, `data_type`, date/zone and collision handling.
- [ ] Validate receiver protocol, port, framing, parser name/tag and `stellar_log_index` classification; distinguish stored sample port reuse from *active* conflicts.
- [ ] Implement reviewed/escaped templates that emit matching `customized_<slug>` + `customized_<slug>.conf` for a declared supported subset; unknown Ruby stays opaque/unsupported.
- [ ] Add deterministic synthetic RED→GREEN tests, Ruby syntax lint (where isolated available), loss report, pair-name/route consistency and SHA-256 manifest.

**Exit:** generated pair, validators and reproducible tests PASS at exact candidate HEAD. Do **not** claim full native engine compatibility yet.

### R2 — Six-step nondeveloper Guided Builder **P0: SECOND**
- [ ] Reuse/preserve existing local three-pane scaffold as optional **Expert View**, not a replacement workstream.
- [ ] Guided default: **1 Add Samples → 2 Extract Fields → 3 Map/Enrich → 4 Receive/Classify → 5 Test/Fix → 6 Generate/Download**.
- [ ] Offer visual field selection, multiple variant routing, type-safe Interflow mapping, conditional category rules, UDP/TCP/eligible HTTP controls and plain-language diagnostics.
- [ ] Provide create, basic clone/import, edit, save/reopen, failed-event navigation and honest compatibility/unsupported states.
- [ ] Connect compiled two-file download; do not silently drop unmatched or malformed events.

**Exit:** a nondeveloper completes the workflow with synthetic representative fixtures and produces internally consistent paired files without typing code; focused UI/unit test evidence on exact HEAD.

### R3 — Native runtime testing, regression and export **P0: THIRD**
- [ ] Execute supported generated Ruby/Fluentd parser in an isolated pinned runner (time/CPU/memory/network restrictions); never run on the live reference host.
- [ ] Validate callback output, timestamps, normalization, enrichment, session/threat/syslog routing, failure paths and multi-event sample coverage.
- [ ] Store reproducible suite/run IDs, runner digest, golden output/fixture hashes, changed-field diff, redacted reports and artifact checksums.
- [ ] Export the paired files and manifest with status Draft / Syntax Valid / Engine Tested / Target Import Verified / Partial / Unsupported / Pending Evidence.
- [ ] Implement a vendor portal JSON/legacy adapter only after its exact input contract and real target import are verified.

**Exit:** fixture-based native behavior verified, target import status truthful, export is reproducible; no green on untested cases.

### R4 — Coverage and product quality **P1**
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

**Code is being developed in another session.** Do not cherry-pick arbitrary priorities, reset its branch, restage its changes or interpret this docs update as a new start. Continue its **exact current unfinished operation** from the latest verified Git/Work Packet, then the first remaining runnable step of R1.5 → R2 → R3 → R4 → R5.

If real raw samples are not yet available, create strictly synthetic fixtures for schema/compiler tests, and mark real compatibility `PENDING_EVIDENCE`. This is not a blanket project blocker. Report only proven owner-action/environment limitations.

Record changing evidence (actual branch, HEAD, worktree, PR/CI, tests, blocker and NEXT_ACTION) in the single [Issue #1](https://github.com/xdr-labs/parser-studio/issues/1) and active Work Packet; keep this document's milestone requirements stable.

## 5. Overall acceptance

A first-time nonprogrammer can reliably turn representative raw logs into an explainable, well-tested Stellar-compatible **paired parser artifact**, with no missing events hidden from results and no manual coding. Native-runtime compatibility and actual vendor loader/import are separate demonstrated gates. No production effects by default.
