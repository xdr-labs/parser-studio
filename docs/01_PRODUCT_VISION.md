# 01. Parser Studio — Product Vision and Scope

**Status:** Approved goal and initial product direction (2026-10-11); detailed output-format contracts pending owner's real samples.

## Product mandate update — owner clarification (2026-10-12)

The primary goal is **replace the external parser developer with a complete no-code GUI for general users**. Primary generated outputs are the two files observed on the authorized rickmodular reference host: `customized_<slug>.conf` and `customized_<slug>` (extensionless Ruby fragment). All routine creation functions must work without typing Ruby, regex or Fluentd configurations. The three-pane Workbench is advanced detail, not the initial guided UX. Official 6.5 modular JSON uploads are a separate adapter; no false cross-version file-equivalence claim. Canonical details: docs/08 and docs/09.

## 1. Problem and outcome

Stellar Cyber Parser Studio does not provide an effective field-engineer workflow for repeatedly developing and correcting custom log parsers. Our product will be a **separate Web application**, not a modification of the vendor's UI.

**Desired outcome:** A field SE or partner can turn representative raw logs into a validated, maintainable, Fluentd-compatible parser and Stellar Cyber-normalized event preview without writing parsing rules from scratch. Advanced users can edit expressions and intermediate representations directly.

## 2. Personas

| Persona | Key tasks | Required experience |
| --- | --- | --- |
| Field SE / Partner | Onboard an unknown product's logs, test and export | Guided, visual, fast correction |
| Parser engineer | Complex conditional routing, nested extraction, transforms | Explicit rules, source editor, trace |
| Reviewer / Customer | Validate samples, mappings and coverage | Readable errors, repeatable evidence |
| Product maintainer | Manage templates, regression fixtures, import/export adapters | Diff, history, reproducibility |

## 3. Principles

1. **Version-independent authoring.** No version choice is required to edit or test. Compatibility is an export and validation concern.
2. **Samples-first.** Work on a meaningful collection of variants, not a single hand-picked matching line.
3. **Explain every failure.** Show whether a record was split, routed, parsed, normalized, validated and exported.
4. **No false green.** An in-browser Regex match is not equal to Fluentd runtime success or Stellar import compatibility.
5. **GUI by default, source when needed.** Visual controls for routine tasks; advanced editor with safe round-trip only where semantics can be preserved.
6. **Privacy by default.** Customer-origin logs stay private, redacted where feasible; external AI is opt-in only.
7. **Reproducibility.** Parsers, schema mappings, test fixtures, test environment and export manifests are separately versioned.
8. **Original UI and implementation.** Use competitor interactions as research, not proprietary source/assets.

## 4. End-to-end user journey

**New parser:** New project → paste/upload logs → group by event family → choose/confirm format → select fields on raw log → create parse rules → map to Interflow → run full sample suite → inspect errors/diffs → save version → export a supported target bundle.

**Fix existing parser:** Import original file(s) → round-trip inspection and explicit unsupported elements → load baseline test suite → edit minimal stage → compare previous/current sample output → record regression report → export without overwriting the original.

**Review:** Open saved version → see exactly which sample datasets were tested, results and runtime profile → examine failures and semantic mapping → approve internal ready-for-export state. This does not grant production release authority.

## 5. In scope

- Multiple raw log samples; event breaking, route variants, format detection, structured and unstructured extraction.
- Fluentd parser configuration support and native runtime validation for supported features.
- Interflow mapping, typed normalization, enrichment/transforms and preview.
- Reproducible diagnostics, regression coverage, templates and version history.
- Compatibility-oriented import/export profiles with explicit verification status.
- Desktop-first, responsive bilingual-ready Web UI.

## 6. Explicit non-goals / boundaries

- No dependence on Stellar Cyber's embedded Parser Studio for editing.
- No implied support for all Fluentd plugins; use capability declarations.
- No promise that undocumented Stellar-specific legacy JSON/CONF and modular JSON are interchangeable.
- No auto-deployment into a live sensor or tenant in the initial phases.
- No direct production changes and no SaaS transfer of customer logs by default.
- No unverified AI-generated parser deployment.

## 7. Unresolved evidence—not blockers for spec work

The owner will provide real **sample logs and sample parser artifact(s)** later. They will establish supported runtime features, vendor-specific file layouts, naming/metadata constraints, Interflow fields and import/export acceptance tests. Until then, mark those adapters as PENDING EVIDENCE, not completed.
