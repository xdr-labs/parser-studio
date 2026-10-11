# 02. Web UI / UX Specification

**Owner-corrected UI hierarchy (2026-10-12):** The default product is a no-code **six-step Guided Builder** from raw logs to a matched parser + CONF pair. It must replace external developer tasks. This document's three-pane technical Workbench is retained as an optional Expert View; see [08_NO_CODE_USER_EXPERIENCE.md](08_NO_CODE_USER_EXPERIENCE.md) for authoritative primary navigation, stages and end-user acceptance.

**Design baseline:** Cribl-like pipeline preview + Datadog-like sample testing + no-code field mapping + precise per-event diagnostics. Build an original visual language and components.

## 1. Optional Expert View, not default navigation

The default product workflow is the six-step **Guided Builder** in [08_NO_CODE_USER_EXPERIENCE.md](08_NO_CODE_USER_EXPERIENCE.md). It is intended for a user who does not know Ruby, Regex or Fluentd. It starts from adding sample logs and ends with generation of two matching files.

The three-pane Workbench below is an **Expert/Detail View** that users can open during extraction, normalization or debugging. It must retain the selected project, rule and sample when switching back to the guided workflow. Workbench tabs for Import, Extraction, Normalization, Transform, Enrichment and Tests must never become mandatory technical steps for a nondeveloper.

Global product navigation is defined by document 08. This document owns only the detailed advanced pane interactions and accessibility characteristics.

## 2. Desktop wireframe (concept)

| Left pane (25%) | Center pane (37%) | Right pane (38%) |
| --- | --- | --- |
| **SAMPLE LOGS** | **PARSER PIPELINE** | **LIVE RESULT** |
| Dataset selector | Event breaker + routing | Selected event status |
| Paste / Upload | Detect / Parse | Raw / Extracted / Normalized tabs |
| Event-family filters | Field extraction rules | Side-by-side IN → OUT diff |
| Events with pass/warn/fail | Normalize / Transform | Typed Interflow JSON / Table |
| Raw text w/ selection highlight | Mapping / Enrichment | Trace + errors + suggestions |
| Multiple sample lines | GUI / source editor toggle | Re-run selected/all |

Persistent top bar: Project / parser name; Dirty status; Undo/Redo; Dataset; Run sample suite; Save Revision; Export. Under the panes: compact validation strip (tested / matched / normalized / errors / unverified outputs) and a filterable diagnostics drawer.

**Widths are starting targets, not a hard-coded fixed layout.** Panels resize. Editor and result can be expanded; long strings wrap or scroll independently.

## 3. Critical workbench interactions

### A. Bring sample logs
- Paste multiline text, upload allowed text-based formats, or open an existing private fixture.
- Preview physical lines vs logical events. Explicitly choose record boundaries for multiline/syslog payloads.
- Auto-detect candidate formats (Syslog, JSON, KV, CEF, LEEF, CSV, regex/text) with confidence and reason; user can override.
- Group events into families when header/body patterns differ. One outlier must not silently reset a working parser.
- Redact sensitive values in UI and exportable reports; raw data never appears in the Git repo by default.

### B. Create extraction rule visually
- User selects a token in the raw event; **Create Field** proposes a span/pattern, name and inferred type.
- Highlight matched spans, and visibly distinguish unmatched lines or ambiguous boundaries.
- Advanced users can edit regex, named groups, JSON path, separator rules or nested transformations.
- Make pattern order, first-match semantics, variants and fallbacks visible.
- Unsafe / unsupported expression constructs show an inline warning before a full test.

### C. Normalize into Stellar Cyber fields
- Two-column map: Extracted Field → Suggested Interflow Field; type and description visible on both sides.
- Auto-suggestions require manual confirmation when confidence is low. Users may search the version-neutral schema dictionary.
- Explicit timestamp units, timezone and parsing outcome; IP, ports, numbers, booleans, enums and required metadata type-check.
- Detect mapping collisions, duplicate output fields, accidental information loss and missing required fields.
- Unmapped raw fields remain discoverable in preview; do not silently discard without an explicit rule.

### D. Test and fix
- Click Run to execute selected record or entire dataset; show progress and actual test-engine identity.
- Preview states: RAW, EXTRACTED, NORMALIZED and DIFF; JSON/Table toggle.
- Per-stage trace: input → route → event break → extraction → conversion → mapping → enrichment → validation.
- Failed events show reason, affected rule, highlight, repro event ID, and a **View failing examples** filter.
- Display actual **match count, normalization pass count and failure count** with denominators; no fabricated percentages or blanket 100% for empty data.
- Differences between working revision and candidate use added/removed/changed fields with precise values (masked if sensitive).
- In-progress, canceled, timeout, unsupported-runtime and unverified-export results are distinct states, not green PASS.

### E. Save and export
- Save draft as a versioned project without implying readiness.
- Export panel lists Fluentd and Stellar-specific target adapters, each with **Verified / Partial / Unsupported / Pending evidence** and supported syntax.
- Generate a bundle only for supported shapes; unsupported steps require clear failure or explicit loss report.
- Show adapter version, engine version, checksum, applied mapping manifest, executed tests, and target profile.
- Installation/deployment guidance may be rendered; initial scope does not push into production.

## 4. Secondary screens

**Parser Library:** cards/table with Vendor, Product, Formats, Last Test, Compatibility, Updated, Owner; search, import, clone, inspect revisions. Draft versus Verified are unambiguous.

**Test Lab:** dataset list; selected sample events; test runtime + version; test matrix (parser revisions × fixture suites); error grouping; golden output comparison; downloadable redacted validation report.

**Schema Explorer:** search field dictionary by source alias, meaning and data type; example valid/invalid values; reserved system fields; version-neutral catalog with catalog revision.

**Export & History:** target capability matrix, artifact download, revision change log, compatibility notes, baseline comparison and rollback download (no live rollback).

## 5. UX behavior / accessibility

- Use a desktop-first workbench with a minimum practical viewport around 1280 px; at smaller widths panes become tabs. Mobile supports browsing/results, not a promise of full dense editor equivalence.
- Korean / English-ready labels; monospace editor, readable large datasets, keyboard focus, non-color-only error indicators.
- Autosave local draft is optional; explicit persisted Save Revision is always identifiable.
- Undo/redo per editing session; Warn before navigating away with unpersisted rules.
- Preserve editor scroll, selected event and error focus between test runs.
- Define clear empty, loading, no-match, parser-error, network-error, engine-unavailable, permission-error, and export-not-verified states.
- No decorative AI button; AI assistance is later, opt-in, clearly separate from tested output.

## 6. Usability acceptance journeys

1. A beginner can paste multiple logs, select a field, map a value and see normalized output on the same screen.
2. An advanced user can edit a supported regex without losing unrelated GUI rules and can identify differences after testing.
3. A wrong timestamp/field type is called out with the exact event and field before export.
4. A sample variant that fails is visible even if all other variants pass.
5. Export cannot appear Verified merely because a UI preview succeeded.
6. A user can identify which dataset, parser revision, schema and runtime produced a given test result.
