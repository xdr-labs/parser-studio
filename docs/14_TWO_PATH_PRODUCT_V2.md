# Parser Studio 2.0 — Two Creation Methods and Unified Roadmap

**Priority:** P0, overrides all earlier instructions keeping the six-step Wizard or three-pane Workbench. **Implementer:** CHATGPT_CHAT, one integrated session for Web UI, backend, API contracts, Chromium and roadmap. **Source and interface:** English only.

> **Owner UX override (2026-10-22):** ChatGPT Assisted Parser takes the exact user-entered log source into a manually copied prompt. The separate synthetic/redacted example editor, masking approval, and extra source-copy action are removed. Show one clear warning that the prompt contains potentially sensitive log values; do not automatically send source data to ChatGPT. An unavailable v0.1 project must not create contradictory null-project instructions: the v0.2 recovery proposal uses the local draft identity and remains REVIEW_ONLY, unverified, and separately validated. Auto Parser presents only the default Multi-Pass analysis and context-sensitive feedback; Tools & Diagnostics and standalone deeper analysis mode are removed. Old tests/documents about the superseded redaction and troubleshooting UX are historical, not acceptance criteria.


## P0 beginner UX cleanup — 2026-10-23

The public desktop multi-format audit found that the optional **Group similar
text logs** (private Drain3) and **Find a similar known log shape** controls
duplicate the primary Analyze Logs workflow without producing an independently
reviewed parser. They are removed from the Auto Parser Add Logs UI. No private
source grouping capability probe or user-log POST is initiated by this screen.
The useful automatic, browser-local *different log shapes* grouping and
reversible selection for repeated unknown events remain available when needed;
this does not add a third parser creation method.

User-directed prefix/postfix selection, declared relay review, existing parser
inspection, and the offline Python test sender remain as opt-in, collapsed
controls. The normal Add Logs → Review Fields → Map Fields → Create Parser path
remains the default. Desktop input is moved ahead of optional manufacturer,
product and listener-port metadata, with a compact introduction and one-line
multi-type action so the original raw-log textbox is visible at first load.
Source/byte-fidelity upload guidance is retained next to the file input's Help
button, not repeated in the default introductory text. For W3C/Zeek headers, explicitly distinguish original
metadata/header lines from logical data events while preserving both in source
accounting. Field extraction does not imply downloadable native support.

## ChatGPT Assisted first-use visual sequence — 2026-10-23

A real 1280×800 desktop Chromium screenshot exposed the original log input
below the first viewport because optional listener-port and manufacturer details
were rendered first. The novice user now pastes **original logs before
optional source identity and receiving-port controls**, without changing how
those fields bind to an approved parser DRAFT. The "3. Paste the ChatGPT result"
number appears **only after** the user has prepared step 2's copyable prompt;
before that action, the result heading explicitly explains it is the later
paste step. This avoids showing a missing step in the untouched first-use UI.
The visible warning and manual copy/paste boundary remain unchanged; no
third-party transfer or automatic AI operation was added.

## Product-level navigation: only two choices

### 1. Auto Parser

Add logs → analyze all events locally → detect a supported format → review extracted/normalized fields and correct any mapping in place → test the complete sample → compile a schema-checked Ruby extensionless parser and matching CONF with exact hashes.

Do not require the user to know whether the source is JSON, KV, CEF, LEEF or Syslog, and do not prompt for RegEx. When automatic detection cannot prove a format, show a simple reason and the ChatGPT Assisted Parser choice. Keep the original source in browser memory. No silent event omission, no inferred RFC3164 time, no unsupported parser claims. Results offer verified file downloads, immutable owner-scoped revision review and only explicitly gated target actions.

### 2. ChatGPT Assisted Parser

Enter local raw samples and desired fields → see the sensitive-data warning and inspect the prompt containing original logs → open ChatGPT manually → paste the response as restricted ParserRecipe v0.2 JSON → verify exact source SHA, stage order and allowed schema → perform complete local parsing, and independent holdout regression if the proposal adds one compatible mapping → user explicitly approves → validate/generate with the same pinned backend and SHA-verify both Ruby/CONF outputs.

No API key, automatic external LLM request or source egress. The prompt contains the original source logs (manually copied only), source digest/count metadata, and a declarative reference recipe if locally available. A sensitive-data warning is always visible. Unrecognized raw formats, arbitrary regex/Ruby/JSONata, arbitrary stage edits or invalid schema cannot fabricate a deployable parser.

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
| P0-1 | Exactly 2 methods, legacy UI removed | **COMPLETE:** current Chromium verifies two-path root, retired deep-link redirects, keyboard flow and mobile no-overflow. |
| P0-2 | ChatGPT copy/paste validated end-to-end | **COMPLETE:** explicit redaction, strict v0.2 Recipe import, current-sample + independent holdout qualification, approval, and exact backend Ruby/CONF generation pass live Chromium. |
| P0-3 | Reuse all Auto Parser core features | **COMPLETE:** source accounting, bounded format families, mappings, Ruby/CONF, ZIP, Dictionary review, visible-redaction preservation and explicit Native verification are integrated. |
| P0-4 | Bring useful legacy operations to results | **COMPLETE:** port review, immutable history, browser-local replay, owner-scoped Test Lab recovery/evidence and gated Interflow actions are contextual result tools with live-backend browser regression. |
| P0-5 | Existing Chromium behaviors dispositioned | **COMPLETE:** all 48 archived suites are machine-accounted as migrated, owner-superseded, or externally gated; archived suites never count as current PASS. Existing Project JSON and Ruby/CONF import/inspection behavior is migrated under Auto Parser Advanced tools. |
| P0-6 | Independent exact-head qualification | **COMPLETE for internal scope:** UI/unit/build/current Chromium + exact pinned backend live Chromium + source-bound Ruby 3.2/Fluentd 1.17.1 Native proof. Proprietary Stellar target and human acceptance remain separate gates. |
| P1-1 | Explicit-schema mixed CSV | **COMPLETE bounded subset:** reviewed 2–100 columns, comma/semicolon/TAB delimiter, reapproval on source/schema edits, v0.1/v0.2 SHA parity, Native synthetic qualification and exact-backend Chromium integration PASS. |
| P1-2 | Native multiline | **COMPLETE bounded subset:** explicit TCP LF LF Java Stack Trace compiles and passes exact-backend Chromium/Native qualification. Arbitrary Java/UDP/unframed multiline remains intentionally unsupported. |
| Gated | Real DP Apply, Sensor send, Interflow, human E2E | Await target credentials/permissions and separately approved test conditions |
| Gated | PR merge / release | Explicit owner release approval only |

**Current integration provenance (2026-10-14):** active UI Draft PR #17 is feat/stellar-export-visual-parity-20261014; active backend Draft PR #4 is feat/r15-parser-pair-backend; active source-engine Draft PR #16 is poc/security-stream-framing-20261014. Preserve historical recovery worktrees and unrelated dirty state. UI quality CI must pin exact backend candidate 10a58c12cd0de5fe0579c14d3943ddf1ba928406; Native/target claims are never inferred from browser-only evidence.

## Internal qualification snapshot — 2026-10-14

- UI PR #17 candidate before this documentation/CI-pin update: f7c5e33c5e8c2e766432f6d2915d19aae18bc196; local **594/594 Vitest**, production build PASS, current browser suite **21 PASS / 28 integration-gated SKIP**, and exact backend e3f4565 integration subset **26/26 PASS**.
- Engine PR #16: 33c23a3242e2ed97ab202fa9053057eefdb07426; visible-mask focused **12/12 PASS**, full engine **321 PASS / 1 SKIP**, exact-head quality CI SUCCESS. Visible markers are preserved exactly and hidden values are never reconstructed.
- Backend PR #4: e3f45651554eafc598a79ed7a61eed55b1b65ea9; backend **339/339 PASS**, pinned Ruby 3.2.3 / Fluentd 1.17.1 qualification PASS, source-bound per-project Native proof **2/2 events exact**, exact-head Native CI SUCCESS.
- Current UI with private verifier injection also completed browser -> v0.1 DRAFT -> v0.2 exact SHA -> Native Fluentd **2/2 exact**; public HTTPS remains Native-verifier disabled by design.
- Public HTTPS development smoke verifies visible redaction review, Existing Parser Advanced surface, 390px no-overflow and no private Native execution button.

Only real Stellar DP/sensor/Interflow proof, owner-supplied proprietary compatibility artifacts, human acceptance, merge and release remain externally gated.

## Acceptance gates

- Browser only shows two method buttons, including on mobile. No Wizard, Workbench, Expert, Advanced Wizard, Test Lab or Library **creation navigation**.
- Auto result can edit mappings without a third mode. No loss of source events. No invented Native verification.
- Changing the original source invalidates the prior prepared prompt. The original source is included only in the prepared prompt, with a visible sensitive-data warning; it is never sent to an LLM automatically.
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

All archived Wizard/Workbench suites now have a machine-checked behavioral disposition in
`tests/legacy-removed-ui/migration-manifest.json`. Archived tests still never count as current
PASS. No archived legacy behavior remains undispositioned; exact Project JSON/Ruby/CONF review is
migrated under Auto Parser Advanced tools, and real target operations remain separately gated.


## Beginner-first parsing UX — 2026-10-15

The default Auto Parser path is now **Add Logs → Fix Problems → Test & Create**. A first-time user sees one primary **Analyze Logs** action; Multi-Pass diagnostics, byte-span details, Dictionary evidence, Drain3, Existing Parser tools and Native evidence are moved behind **Advanced**.

The authoritative analysis is event-framed Multi-Pass rather than competing browser/Multi-Pass status labels. Each unresolved event shows the original source with the unresolved region highlighted, a plain-language explanation and a structure-aware recommendation:
- JSON → direct JSON field paths first; no arbitrary JSONata execution.
- CEF/LEEF/KV → keep the structured parser and repair only the unresolved extension/body.
- positional CSV such as PAN-OS → reviewed or neutral column schema without guessing semantics.
- unresolved text/Syslog message bodies → bounded named-capture parse_regex only after safety checks.

**Ask ChatGPT** builds a copyable, user-reviewed prompt containing the problem event, already-extracted fields, unresolved spans, current parser identity/recipe context, and the strict ParserRecipe v0.2 output contract. No source is sent automatically. A pasted AI recipe must pass current-source parsing plus an independent holdout and explicit approval before it can replace a draft.

Bounded parse_regex is a reviewed compiler subset, not arbitrary Regex: maximum 256 visible characters, named captures required, and backreferences/lookbehind/unsafe nested repetition are rejected. A controlled Cisco FTD-style fallback recovery has browser evidence through holdout approval and exact backend Ruby/CONF DRAFT generation, while the current tested Cisco ASA/FTD fixtures are now automatically source-parsed by the improved engine.

Current internal evidence after this UX increment:
- UI unit: **601/601 PASS**.
- Current Chromium: **28 PASS / 28 integration-gated SKIP**.
- Beginner core regression: Analyze → problem inspector → ChatGPT prompt/import → holdout → approval PASS.
- Cisco FTD exact-backend recovery: full browser journey through verified Ruby/CONF DRAFT generation PASS.
- Product corpus: AWS WAF, Suricata, FortiGate, Cisco ASA/FTD, SonicWall, Zscaler ZIA, SentinelOne, CrowdStrike, CEF and LEEF complete on the tested samples; Check Point is 1/2 complete with one explicit source-metadata review; PAN-OS is 0/2 semantically named because positional values require reviewed/neutral column schema rather than guessed meanings.
- Source engine candidate: 193a4ec74ca1189208814dab410ea5c83f69ced6.
- Backend candidate: 10a58c12cd0de5fe0579c14d3943ddf1ba928406.

Real Stellar DP/sensor/Interflow proof, proprietary parser-loader compatibility, owner human acceptance, merge and release remain separately gated.


## Downloadable Python synthetic log sender (owner scope update, 2026-10-18)

This is an optional utility inside the existing Auto Parser test/results
path, not a third authoring mode and not a live sensor API integration.

After reviewing representative logs, offer Generate Python Test Sender.
Generate and download a self-contained Python 3 script directly from the
browser using no third-party packages, credentials, backend log storage or
automatic sensor connection. On launch, prompt for the destination sensor
IP/hostname and port; validate them, default to UDP with explicit TCP
choice, confirm before connecting, and emit one event per second.
Default to a bounded event count, report progress and stop on Ctrl-C.

For each emitted event replace supported timestamp formats with the
current local/UTC time at transmission and independently randomize
recognized source/destination IP, location, username, email and other
structurally identified field values. Preserve RFC syslog/CEF/LEEF/
JSON/KV/CSV dialects, quoting, escaped delimiters, record boundaries
and constant IDs. Do not blindly substitute unrelated numbers or infer
vendor-specific semantics; unsupported ambiguous values remain
unchanged and are explicitly disclosed.

Only the downloaded Python script, running under user's control on
their machine, sends logs; Parser Studio/browser/backend never
connects to a sensor as a side effect of this feature. The script may
contain user-provided logs in plain text, so show a privacy warning.
This scoped opt-in user utility is distinct from the excluded
server-operated sensor sender, DP parser upload and ingest checking.

Acceptance: stdlib-only Python 3, interactive validated target IP/port,
explicit confirmation, deterministic one-per-second maximum rate,
bounded count/interrupt stop, current timestamps and safe value
randomization, no network API on generator creation, and independent
loopback UDP/TCP listener validation without any real sensor.

## Local experiment history (owner scope update, 2026-10-18)

- Add one optional **Local Versions** workspace accessible from both supported
  parser creation paths, not a third authoring method.
- Save complete current source sample and portable draft/mapping configuration
  as a named, browser-only version; retain multiple versions and compare them
  with each other or the unsaved working copy.
- Restore one complete version without silently overwriting other versions,
  with a browser-local safety checkpoint before replacing unsaved work.
- Use IndexedDB (not the backend artifact revision/history endpoints), with
  a strict bounded schema, digest, capacity guards and visible storage warnings.
- No DP parser upload/apply, sensor send or ingest/index result verification;
  their historical prototype interfaces are not part of the product's scope.
- The owner decides whether to redact a manually copied ChatGPT prompt;
  show a warning without a mandatory masking-consent checkbox.
