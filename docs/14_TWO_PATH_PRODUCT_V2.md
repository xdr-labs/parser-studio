# Parser Studio 2.0 — Two Creation Methods and Unified Roadmap

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
| P1-1 | Expand safe unsupported formats | Explicit mixed CSV with reviewed column/delimiter schema, reject unknown headers |
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
