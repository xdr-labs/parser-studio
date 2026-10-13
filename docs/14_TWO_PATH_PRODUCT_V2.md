> **LATEST RESEARCH RECOMMENDATION — 2026-10-13 (PROPOSED, NOT AN APPROVED IMPLEMENTATION CHANGE):** Use [Retrieval-first Adaptive Parser Intelligence](17_PARSER_INTELLIGENCE_ALTERNATIVES_DECISION_20261013.md): reuse permitted compatible parser profiles, automatically decompose known log variants, ask the user a minimal ambiguity question only if necessary, and offer drag-to-teach as optional scoped recovery. Deterministic typed grammar and native compiler verification precede user-directed ChatGPT/Claude/Gemini proposals and actual Stellar deployment. This supersedes drag-selection-first as the product default and preserves exactly Auto Parser + ChatGPT Assisted Parser. This is researched design, NOT an implemented or native-qualified new parser.

# Parser Studio 2.0 — Two Creation Methods and Unified Roadmap

> **LATEST OWNER P0 PRIORITY — 2026-10-13:** Reconsider grammar learning for heterogeneous real security logs before increasing test counts or DP/Sensor UI controls. New analysis and ordered architecture plan: [Corpus-first Parser Synthesis Research](15_CORPUS_FIRST_PARSER_SYNTHESIS_RESEARCH.md), P0-SYN-0..5. Keep exactly the two creation methods and existing release safety gates. Research evidence is not yet a passed vendor benchmark.

> **LATEST OWNER UX OVERRIDE:** [Explainable Progressive Parsing](16_EXPLAINABLE_PROGRESSIVE_PARSING_UX_RESEARCH.md) requires the current two-path UI to highlight exact captured/unmatched spans, explain all selected rules, accept field-role counterexamples and optionally preserve a verified raw tail as an opaque field, without claiming FULL parsing or native Ruby support until proven. P0-TRACE-0..3 precedes additional parser expansion.

**Priority:** P0, overrides all earlier instructions keeping the six-step Wizard or three-pane Workbench. **Implementer:** CHATGPT_CHAT, one integrated session for Web UI, backend, API contracts, Chromium and roadmap. **Source and interface:** English only.

## Product-level navigation: only two choices

### 1. Auto Parser

Add logs → analyze all events locally → detect a supported format → review extracted/normalized fields and correct any mapping in place → test the complete sample → compile a schema-checked Ruby extensionless parser and matching CONF with exact hashes.

Do not require the user to know whether the source is JSON, KV, CEF, LEEF or Syslog, and do not prompt for RegEx. When automatic detection cannot prove a format, show a simple reason and the ChatGPT Assisted Parser choice. Keep the original source in browser memory. No silent event omission, no inferred RFC3164 time, no unsupported parser claims. Results offer verified file downloads, immutable owner-scoped revision review and only explicitly gated target actions.

### 2. ChatGPT Assisted Parser

Enter local raw samples and desired fields → manually redact an example, approve it and inspect the generated copyable prompt → open ChatGPT manually → paste the response as restricted ParserRecipe v0.2 JSON → verify exact source SHA, stage order and allowed schema → perform complete local parsing, and independent holdout regression if the proposal adds one compatible mapping → user explicitly approves → validate/generate with the same pinned backend and SHA-verify both Ruby/CONF outputs.

No API key, automatic external LLM request or source egress. The prompt contains source digest/count/family metadata, declarative reference recipe if locally available, and only the **user-approved masked example**. Unrecognized raw formats, arbitrary regex/Ruby/JSONata, arbitrary stage edits or invalid schema cannot fabricate a deployable parser.

## Removed user journeys

- Remove visible six-step Parser Wizard and its Edit Details route.
- Remove visible three-pane Expert Workbench and Expert Mode/Advanced Wizard routes.
- Retire separate creation modes for Test Lab, Library, Export and Schema Explorer. Their implementation may survive as **internal libraries or context-sensitive result panels**, never as alternate methods.
- Legacy deep links to the retired routes must open Auto Parser, never the retired UI.
- Preserve prior source history and archived test cases without calling them current PASS.

## Context-sensitive result actions

At the Auto Parser result, after a SHA-verified compiler response, provide individual Ruby and CONF downloads, deterministic ZIP, optionally authorized version register/list/compare/re-download/restore preview, and status of DP Apply, Sensor Replay and Interflow verification. Actual real target Apply/Sensor/Interflow actions must remain independent authorization gates. Mock/owner-scoped operations must never be presented as real production validation.

## Unified execution priorities

| Order | Acceptance | Scope and current state |
|---|---|---|
| P0-1 | Exactly 2 methods, legacy UI removed | Implement UI root and explicit navigation/deep-link regression |
| P0-2 | ChatGPT copy/paste validated end-to-end | Exact SHA, reviewed masked samples only, full current-sample/holdout checks, browser+backend generation |
| P0-3 | Reuse all Auto Parser core features | Preserve local source accounting, strictly supported format families, mappings, Ruby/CONF, ZIP |
| P0-4 | Bring useful legacy operations to results | Version history already moved; port proposal, simulation, approved replay/Interflow UI must be re-scoped and tested |
| P0-5 | Existing Chromium tests migrated | 46 obsolete old-workflow spec files preserved under legacy-removed-ui; migrate business/contract assertions to two methods, no false passing counts |
| P0-6 | Independent exact-head qualification | Vitest, TS/Vite, CI Chromium, pinned real localhost backend, Native Fluentd and SHA parity |
| P1-1 | Explicit-schema mixed CSV | Backend 845d4b1 + e7ee1d9: strict JSON/KV/CSV single-line family selection, 2–100 reviewed columns, fixed comma/semicolon/TAB delimiter, Native synthetic qualification; UI Auto Parser shows one inline CSV column review step, with explicit reapproval on source/schema edits and v0.2 DRAFT SHA evidence. Browser/real backend integration is required before marking complete. |
| P1-2 | Native multiline | Bounded explicit TCP LF LF framed Java Stack Trace supported in current backend; arbitrary Java/UDP unframed remains unsupported |
| Gated | Real DP Apply, Sensor send, Interflow, human E2E | Await target credentials/permissions and separately approved test conditions |
| Gated | PR merge / release | Explicit owner release approval only |

**Critical provenance:** The two recovery worktrees (UI PR #7, backend PR #4) are independent; the old common Git worktree metadata is missing. Preserve the original old paths. The separately created /home/aella/parser-studio-two-path-ui-20261013 contains the initial uncommitted ChatGPTAssist draft; its original must not be deleted or overwritten. Integrate changes into PR #7 and pin its CI to exact PR #4 backend HEAD. The original backend contract and synthetic Native tests remain required.

## Acceptance gates

- Browser only shows two method buttons, including on mobile. No Wizard, Workbench, Expert, Advanced Wizard, Test Lab or Library **creation navigation**.
- Auto result can edit mappings without a third mode. No loss of source events. No invented Native verification.
- Manual redaction approval resets when example content changes. A source value must not enter prompt unless the user explicitly supplied the masked example.
- ChatGPT result never executes arbitrary code. Changed supported rules require full local sample and independent holdout review; unchanged canonical recipes may pass directly after manual approval. Both output hashes must agree with the pinned backend's v0.1/v0.2 compiler.
- Browser tests tied to retired UI are archived, not reported as PASS. The new suite must incrementally replace feature requirements and record remaining gaps.
- No unauthorized real DP/sensor writes, no external AI provider by default, no final merge or release without approval.

## P1-1: Mixed CSV in the existing Auto Parser screen

CSV contains no trustworthy field names. When a mixed sample includes candidate CSV rows, Auto Parser shows one inline Review CSV column names control; users enter each name in order and explicitly choose a comma, semicolon or TAB record delimiter. Preview, type conversion, and v0.1/v0.2 generation use exactly that user-reviewed schema, not inferred names. Each edit to a sample, column name, or data delimiter revokes the approval, including an edit followed by a revert.

The backend emits only a 2–4-family reviewed mixed parser, with CSV opt-in requiring 2–100 unique safe column names and one of the three fixed delimiters. Wrong column counts, invalid quotes, unrecognized families, unreviewed prefix, multiline inputs and source/CONF port mismatch must fail closed; no raw log values are sent to the authoring API. No third UI path or legacy Wizard/Workbench is introduced.

The original UI recovery WIP is preserved; this work is integrated from an independent clean review clone into the existing Draft PR #7. Public-synthetic Native tests/CI do not verify proprietary Stellar DP loading or live sensor/Interflow.


### Exact reviewed ParserRecipe v0.2 capability compatibility

Mixed CSV adds the twelfth explicitly reviewed single-line family ID. Its stage review must allow exactly the 12-entry server-owned vocabulary while still accepting previous 4, 6, 7, 9 and 11-entry capability vocabularies only for their own earlier families. The UI blocks any unknown, duplicate or forged entries and validates all selected families before sending source-free v0.1/v0.2 metadata to the backend. The v0.2 backend now advertises the truly unsupported unreviewed mixed CSV schema and unframed generic multiline, not the reviewed CSV / explicitly TCP-framed Java capabilities.


## Browser regression migration: retired ZIP and field-path safety

The original six-step Wizard and three-pane Workbench remain retired, and
their historical test files are **not** restored to current CI. Instead,
five concrete safety contracts have been migrated into the **actual Auto
Parser result and in-place mapping review** in
tests/integrated-backend.spec.ts:

1. A real localhost backend ZIP whose returned SHA-256 has been deliberately
   corrupted must **never** trigger a browser download or claim verification;
   the two independently verified DRAFT source files remain available.
2. A backend whose package capability is omitted must cause the ZIP action to
   **fail before any ZIP POST**, without suppressing prior DRAFT files.
3. A malformed in-place mapping destination (custom..invalid) must prevent
   parser generation and leave the backend untouched. Restoring the exact
   previous mapping must allow the standard three-stage path to revalidate
   and generate the pair, without reviving a third workflow.
4. Two independently valid normalized output names that overlap as ancestor
   and child (for example custom.action and custom.action.child) must be
   rejected before any backend POST; restoring the mapping must enable normal
   schema-tested generation without reviving the retired Wizard or Workbench.
5. The real backend default-deny 403 for revision history must display a
   friendly owner-access denial and no revision data. A forged foreign history
   response containing a raw source value must never be rendered as a
   verified revision, enable ZIP access or initiate target actions.

These tests use an **exact Git-SHA-pinned backend over real localhost HTTP**.
They never contact a vendor DP, send sensor packets, invoke an external AI
provider, or claim full real-user E2E.

The optional Auto Parser result also exposes a **browser-only synthetic replay**
action after a SHA-checked DRAFT pair is present. It reuses the bounded legacy
single-format synthesizer without network delivery, validates every source event
before emitting any result, and stops on explicit Stop, source edit or result
navigation. Unsupported mixed-family or multiline recipes clearly disable local
replay before Start, without losing the generated DRAFT files. Unchanged unknown
fields may be visible locally; this is not a sensor sender, native parser
qualification or Interflow E2E assertion.

A distinct legacy authorization regression uses **Playwright-only synthetic Test Lab
and Interflow intercepts after genuine pinned-backend pair generation**. It
requires independent approvals, verifies that the fixed public sample never
inherits user logs, rejects HTTP 403 and forged raw/verification fields,
permits only field-limited non-verification evidence, and explicitly stops
the simulated session. No real sensor or tenant query is sent.

An owner-approved mock session also exposes a persistent, top-level **Stop Server Session Now** action when switching from Auto Parser to ChatGPT Assisted.
This is not a third creation method, does not create a new session, and still
requires independently authorized backend Stop acknowledgement; failure leaves
the banner visible and does not claim a successful stop.

## Recover an authorized Test Lab run after browser refresh

A server-side Test Lab session is not terminated merely because the browser is
reloaded or the user switches the two supported creation methods. A small
top-level recovery disclosure accepts an exact run ID, makes **no automatic
requests or stored run-ID copies**, and uses an explicit same-origin read-only
session status GET. The backend rechecks owner authorization. Invalid IDs,
foreign owner 403/404, forged source values, mismatched run IDs, fabricated
sensor proof and malformed status metadata must never restore a session or
display raw values. Recovering RUNNING/PAUSED exposes the global Stop action,
even when a lease deadline has passed and the server's status has not yet
confirmed termination. A verified terminal EXPIRED/STOPPED run displays
read-only status, not a Stop/Resume/Start action. Neither recovery nor lookup
deploys a parser or proves sensor ingestion. Four dedicated Chromium migration tests use fixed public synthetic status
interceptions and no target network sends.

## Owner-scoped evidence after browser refresh

The owner-scoped Test Lab evidence review is now a single contextual control
in the top-level session status area, not a duplicated parser-creation
workspace. It remains reachable from either parser path and after a manually
authorized run-ID recovery, even when the original log source and DRAFT parser
were cleared on reload. A run ID never authorizes reads on its own; summary
and export are always separate, explicit same-origin GETs requiring backend
ownership verification. The dedicated pinned-backend Chromium CI executes both the main integration suite
and tests/evidence-recovery.spec.ts; a skipped browser-only test is never
considered verified evidence. The existing strict metadata/field allowlist,
redacted event constraints, exact revision identity and SHA-256 attachment
verification must pass before any JSON file is offered. Untrusted raw records,
403/404 and tampered bytes fail closed, with no tenant/DP/sensor traffic.

## Separately authorized run limits

For an already owner-authorized RUNNING/PAUSED Test Lab session, the Auto Parser
result can request one fixed additional 60-second/20-event quota or adjust the
reviewed rate to 0.2, 1, 2 or 5 events/sec. These are result-only actions, not
new parser creation methods. Each requires an independent, new approval
reference and a separately verified backend capability; no automatic renewal,
quota extension, rate update, sample upload or DP/sensor connection is enabled
by this feature. Renewal responses must preserve run identity, state, source
family, replay mode and rate, increase the quota by **exactly 20 events**, and
extend the actual lease; otherwise the original session remains displayed and
success is not claimed. Rate changes must retain quota and lease unchanged.
Expired/terminal sessions cannot request either action, while the global Stop
remains accessible. GitHub synthetic Chromium intercepts test 403 denials,
per-action approvals and response integrity without real target traffic.

The remaining archived Wizard and Workbench suites still require feature-by-feature **behavioral** migration;
migrating individual behavior groups is not completion of all historical coverage.
