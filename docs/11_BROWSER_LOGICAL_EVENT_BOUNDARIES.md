# 11 — Logical Event Boundary Preview (UI-only)

**Scope:** `feat/r2-guided-multiline-boundaries`, isolated Web UI/browser preview. **Not** Fluentd, Ruby, Stellar Cyber parser-runtime or import compatibility evidence.

## User behavior

The first Guided Builder step has a bounded, explicit source-event choice:

1. **One physical line = one event** (`single-line`, the backwards-compatible default): each non-empty line is an independent event.
2. **Blank line separates events** (`blank-line`): non-empty adjacent physical lines form one logical event. A blank line (one or more) closes the record; CRLF/CR newlines are normalized to LF; the logical event records its *first* physical line number.

The input UI reports both counts: non-empty physical source lines and previewed logical records. Changing the boundary mode re-runs the local Web Worker, recomputing parsing/normalization and preserving explicit failures. User selections and separate formatted log variants can be inspected in the same Guided Builder without authoring Ruby.

## Supported local semantics

- `src/parser.ts::splitEvents(input, boundary, limit)` is a pure deterministic local splitter.
- The browser preview supports at most 64 KiB of sample input, 500 logical events and 4096 characters per logical event; limits are *not* bypassed by blank-line grouping.
- Empty lines are separators, not standalone empty events. Unsupported multiline variants (e.g. multiline syslog without a compatible extractor) remain errors, not false matches.
- If the dataset exceeds 500 logical records, the 500th preview item carries `EVENT_LIMIT` and warning status; this is not reported as a complete set.
- Explicit line provenance stays visible in the event trace. The browser worker is an **approximate preview** only.

## UI/backend contract and safety boundary

The browser draft stores `guided.eventBoundary` as `single-line` or `blank-line`; the original sample text remains only in the ephemeral browser session and is excluded from saved revisions and project JSON downloads.

`compilerDraftContract` explicitly **rejects blank-line grouping for paired artifact handoff** until the separate backend compiler supports this boundary mode and native fixtures prove the exact Fluentd/target behavior. Consequently the generated Ruby/`.conf` buttons remain disabled, and even configuration JSON handoff is rejected while this mode is chosen.

No remote port, td-agent file, parser registration, privileged action, production log or customer parser is modified.

## Deterministic acceptance evidence (dev-atlas)

- Vitest **33/33 PASS**; TypeScript/Vite production build **PASS**.
- Focused Chromium tests **2/2 PASS**: multiline synthetic JSON grouping, source line counts, format selection, compiler handoff denied for unverified mode, switch-back/restore of local draft mode.
- Full GitHub Actions CI and integrated backend/native engine proof are **pending** for this branch until their actual results are recorded.

## Later compatibility work

- The backend session must explicitly negotiate the event breaker capabilities through a version-neutral `input.eventBoundary` schema/capability response before enabling a native pair export.
- Richer event breakers (timestamp-start or indentation patterns, stack traces, Syslog/CEF variations) need separate deterministic/golden fixtures; they are **not** implied by the blank-line preview.
