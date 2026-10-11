# 08. Web Studio UI Decisions — Research → Implementation

**Decision date:** 2026-10-12. See [07_COMPETITOR_RESEARCH_AND_GAP.md](07_COMPETITOR_RESEARCH_AND_GAP.md) for documented comparisons and source links.

## Visual design specification

### Colors and density
- Shell: midnight #0c1626 / masthead #111d30.
- Canvas: off-white #edf1f5. Panes: white, 1px cool-gray outline, 10px gutters.
- Product action: sea-glass teal #09a1a3. No colored gradient backgrounds or decorative filler; warm orange for warnings, red for failures only.
- Form controls: compact 32-36px height. H1 27px, pane headings 15px, dense metadata 9-11px. Prefer 2-line explanatory errors over tooltip-only content.
- Event/regex/code: readable monospaced type, wrap or horizontally scroll. Selected event has a left edge accent plus semantic status icon.

### Main workbench anatomy
```text
┌──────────────────────────── Navigation & actionable topbar ──────────────────────────┐
│ Project title · dirty revision         New · Save revision · Run whole dataset       │
├─────────────────────┬───────────────────────┬────────────────────────────────────────┤
│ (1) SAMPLE LOGS     │ (2) PARSER PIPELINE   │ (3) LIVE RESULT                        │
│ upload/paste        │ vendor & product      │ browser/native runtime identity       │
│ named sample sets   │ format candidate      │ tabs: RAW EXTRACTED NORMALIZED DIFF   │
│ event/family filter │ extraction rule       │ selected event fields & match spans   │
│ pass/warn/fail list │ field mapping         │ trace, type/route errors & warnings   │
│ highlighted source  │ source editor toggle  │ stage IN/OUT and diagnostics          │
├─────────────────────┴───────────────────────┴────────────────────────────────────────┤
│ Engine identity | total / matched / normalized / failed | export NOT VERIFIED      │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### Interaction invariants
- No modal wizard for the usual path; advanced raw-source mode can open an inspector/drawer.
- Selection creates an **editable proposal**, never commits guessed regex without confirmation. Show match coverage before acceptance.
- Always label separate states: matched, extracted, normalized, native Fluentd verified, proprietary importer verified.
- Rerunning a suite never erases the selected event or silently discards unmatched outlier families.
- Saving a revision saves **rules only** unless the user explicitly opts into a privacy-audited sample fixture store.
- Field mapping must show what is unmapped and the exact failing cast/required attribute.
- An ambiguous round-trip from advanced source editor must show a loss/unsupported report, not silently convert.

### Mobile/tablet contract
- Desktop-first; at 1170px switch to two columns with the results panel below; at 800px stack workbench panes.
- Small devices can inspect examples and drafts; full editing is not promised until the compact UX is tested.
- Keyboard and visual accessibility must be verified by an actual browser scenario; build-only is insufficient.

## Component ownership and implementation location

| Component | Ownership / implementation | Tests |
|---|---|---|
| App shell, nav and 3-pane layout | src/App.tsx + src/styles.css | GitHub Chromium 9/9 PASS at d751252; keyboard/contrast accessibility audit still pending |
| Private sample clipboard/file import | src/App.tsx + src/preview.worker.ts | dataset limits, encoding, fixture/source segregation |
| Pure parser candidates and stages | src/parser.ts + src/model.ts | src/parser.test.ts |
| Runner boundary (browser only now) | src/preview.worker.ts | timeout/status/per-event trace; no native claim |
| Draft/history and safe JSON | src/storage.ts | src/storage.test.ts |
| Selection-to-field proposed rule | src/pattern.ts (planned) | dedicated deterministic generation tests |
| Native runner / export profiles | future isolated backend | native executable & target evidence, NOT browser simulation |

## Objective acceptance criteria

1. User can reach first extracted field within 4 direct workbench interactions after pasting raw logs (selection → field name → confirm → inspect). Explicit user-measured time pending.
2. Every event in a small diverse fixture corpus has its own route, extraction and normalization status and exact cause for failures.
3. Changing one mapping can re-run the preview without refresh; no stale suite status shown as current.
4. Screen at 1440×900 shows all three panes, parser title, run and bottom status strip without scrolling the entire browser; pane content scrolls independently.
5. Saved rules reopen in the same browser, and raw logs are not stored in the serialized revision.
6. Unsupported native runtime, unverified schema, unknown parser syntax and invalid metadata cannot yield a green export status.
7. Keyboard focus, non-color-only errors and minimum contrast are checked by a real browser suite before release.

## Deferred until validated
- AI-generated rules, reusable licensed third-party UI/code, full DAG canvas, concurrent multiuser auth, tenant deployment, production parser upload.
- Fluentd runtime fidelity and Stellar parser export remain NOT VERIFIED until the respective test gates pass.
