# Current engineering completion ledger — 2026-10-20

This ledger supersedes dated next-action statements below. The active product
remains Auto Parser and ChatGPT Assisted Parser. Historical unchecked research
and target-release lists are not a count of unfinished beta implementation.
This candidate records the local qualification available before its source
commit; subsequent CI, main and application receipts are recorded in the
[active work packet](https://github.com/xdr-labs/parser-studio/issues/1#issuecomment-6287789712).

| Scope | Current engineering status | Evidence / boundary |
| --- | --- | --- |
| MAIN-1/2, LOCAL-1/2, MULTI-TYPE-INPUT-1, SCRIPT-1/2/3 and CI-1 | Incorporated in main before this continuation | PR #120; main `00e783520c005a96b37b5fbf5eb4ad81c74381a6`; its qualified public development baseline is recorded in Issue #1 comment 6286114104. |
| DRAFT-1: source-to-parser integration | Complete in PR #121 and current main | Strict RFC5424 SD/free MSG uses the existing raw-body compiler. Additional explicit Generic Structural profiles preserve original Syslog prefix/KV and implicit-TAB LEEF 2.0 source through mappings and downloadable parser files. |
| RECOVERY-1: incomplete text | Complete in PR #121 and current main | Generic quoted bracket labels retain exact source values and UTF-8 spans, repeated/empty occurrences and previously recovered atoms. Residual prose stays PARTIAL. The novice review flow tests source preservation and distinct holdouts before applying a supported recipe. |
| BATCH-1: 100–400-event usability | Complete in PR #121 and current main | Actual request/verification phases, source byte count, elapsed time and cancellation. Source/draft identity checks reject late responses after cancellation, edits or replacement requests. No fabricated percentage or timeout-based success. |
| Profile persistence and format changes | Complete in PR #121 and current main | The selected additional grammar survives Project JSON, recipe projection and browser snapshots. Explicit non-generic format changes clear incompatible metadata; unknown or mismatched imported profiles are rejected. An older Backend without the selected profile shows a source-preserving blocked state and an explicit fresh-capability retry. |
| Previous continuation qualification and public development application | Complete for the frozen PR #121 candidate | Source `19f3f5e7e82717d4c48a5ad8a24e599e84110201`; successful CI run #39416579705; main `ec6df2473612e5dd0cb23de6209801a7dda1548a`; separate public Chromium 109/109 PASS completed at 2026-10-20T12:59:55Z. See [the preserved continuation verification record](verification/roadmap-followup-20261020.md) and [Issue #1 work packet](https://github.com/xdr-labs/parser-studio/issues/1#issuecomment-6287789712). |
| MIXED-PROFILE-1: bounded Generic Structural combination | Implemented and locally qualified | The scalar `syslog_prefix_kv_leef2_implicit_tab_v1` combines the two existing additional grammars with unchanged V15 routes. It preserves the complete safe field union, strict LEEF ownership and existing bounds. A single existing profile remains preferred whenever sufficient; ambiguous normalization destinations retain distinct vendor fields. See [the new verification record](verification/mixed-generic-profiles-20261020.md). |
| Mixed-profile qualification, main and development application | Local qualification complete; CI and application receipts follow the frozen commit | Actual affected Chromium 8/8 PASS, including both mixed orders, exact 22-source mappings, Ruby/CONF downloads, local save/reload/restore, malformed controls and two independent browser users. Initial 6/8 exposed the automatic-adoption gap; a source-aligned strict-grammar correction passed 44/44 focused tests, 3/3 English-policy checks and Web build. Generated Ruby 91/91 and Backend build remain valid for the unchanged Backend candidate. See the current work packet for exact-candidate CI, main and public affected-eight receipts. The earlier interim 112 includes two removed probes and is not a permanent-suite count. |
| Desktop novice first-log entry (2026-10-21 follow-up) | Isolated desktop-only candidate, not yet installed | Existing 1440×900 public first viewport hides the raw input below other instructions. A desktop-only first-screen shortcut focuses the exact unchanged raw textarea; three real Chromium desktop cases, 23 affected frontend tests and Web build passed locally. The separate installed baseline passed a first-time quoted CSV parser-file-download journey. See [desktop first-use verification](verification/desktop-novice-first-entry-20261021.md); exact candidate CI and development application remain separate gates. Mobile expressly excluded. || Desktop novice first-log entry (2026-10-21 follow-up) | Isolated desktop-only candidate, not yet installed | Existing 1440×900 public first viewport hides the raw input below other instructions. A desktop-only first-screen shortcut focuses the exact unchanged raw textarea; three real Chromium desktop cases and Web build passed locally; initial exact CI exposed a separate saved-version comparison race fixed by deterministic delayed-read RED→GREEN, 4/4 desktop browser tests and 29/29 affected frontend tests. The separate installed baseline passed a first-time quoted CSV parser-file-download journey. See [desktop first-use verification](verification/desktop-novice-first-entry-20261021.md); new corrected exact candidate CI and development application remain separate gates. Mobile expressly excluded. |

## Remaining support boundaries

The usable structural beta does not require every possible log grammar to become
an automatically downloadable parser. Unsupported original stream/container
compiler contracts, ambiguous or undeclared CSV schemas, malformed controls and
unrecognized text retain an actionable review state. Existing source framing for
Audit/CRI/Docker, W3C/Zeek and transport streams must not be mistaken for native
compilation of every original wire format. The isolated MIXED-PROFILE-1 candidate
adds only the explicit versioned combination of Syslog prefix/KV and implicit-TAB
LEEF 2.0, gated by a separate Backend capability. Unsupported or malformed
combinations still require review. Additional-profile auto drafts exceeding the
full 60-mapping limit also remain in review rather than silently dropping fields.
Conflicting automatic normalization suggestions preserve their distinct vendor
fields; they do not weaken destination-collision validation. The new profile
does not change DRAFT status or assert native engine or target verification.

Manufacturer/firmware-perfect oracle research and new original-wire compiler
profiles remain optional later development. Owner visual acceptance and any
production/release decision are separate from this runnable engineering work.
Actual DP upload/apply, sensor operations and Interflow readback remain outside
this product roadmap. Standalone downloaded Python sender behavior is already
in scope and is verified with synthetic offline/loopback fixtures.

---

# Historical scope baseline — mainline and browser experiment versions (2026-10-18)

This section supersedes older experimental/release tasks below. Continue with two
user-facing authoring paths only: **Auto Parser** and **ChatGPT Assisted Parser**.

| ID | Priority | Scope | Acceptance |
| --- | --- | --- | --- |
| MAIN-1 | P0 | Consolidate all qualified, product-relevant existing UI/parser/compilation into one verified candidate based on the real main branch | Existing docs-only main is an ancestor of the current 210-commit product. Preserve all Draft PoCs and intentional dirty work; selectively integrate proven features without wholesale merging research-only or non-gating evidence code |
| MULTI-TYPE-INPUT-1 | P0 | Explicit log-type entries for one product in Auto Parser; connect source-preserving grouping to the existing reviewed conditional event-type backend | Candidate implementation: add/remove/name/upload up to 10 separately edited types; show verified per-type source and field evidence; optional explicit discriminator-backed single-parser DRAFT; save/restore type labels; reject empty, duplicate, unframed and unqualified records. Require exact-head Chromium 27/27 (six reviewed routing, four named input, five physical-boundary/legacy-version, ten original-container and two mixed source-bypass cases), unit/build and owner acceptance before integration/deployment. Preserve real LF/CRLF boundaries, never add duplicate physical record delimiters, restore checksum-valid legacy browser snapshots without changing original per-type samples. Type labels NEVER become runtime routing evidence. |
| LOCAL-1 | P0 | Browser-only named snapshots of current source logs, parser draft/format/CSV columns, normalization mappings and dataset identity | Save V1 and V2, compare against each other/current working copy, restore V1 then V2, delete explicitly, reload page and find same snapshots; no save/list/restore endpoint, no server writes; predictable browser quota/errors and no silent loss |
| LOCAL-2 | P0 | Safety for browser-local sensitive data | Client-side IndexedDB per browser profile and site origin, SHA-bounded records, reject corrupted/oversized revisions and forged mapping paths, warn that clearing browser storage or changing site origins loses access; no automatic LLM transfer or synchronization |
| PARSER-1 | P0 | Use qualified generic structural Multi-Pass/Funnel improvements in actual UI/compiler where demonstrably beneficial | Exact same-candidate structural PARSED/PARTIAL/RAW accounting and user review; no false complete; limited finite multi-format representative regression |
| UX-1 | P0 | Resolve common novice/mapping/CSV/prefix/forwarder gaps found in real local tests | Same browser test logs can be revised through several snapshot versions and converted into a downloadable DRAFT parser |
| SCRIPT-1 | P0, after LOCAL-1 | Generate a downloadable standalone Python 3 standard-library-only synthetic log emitter from the current browser-reviewed logs | User downloads a Python script, runs it on their own machine, enters destination sensor IP/hostname and port at runtime, explicitly selects UDP/TCP with UDP default, and sends exactly one log event per second; no server-stored source logs or Parser Studio-initiated sensor network connection |
| SCRIPT-2 | P0, after SCRIPT-1 | Preserve structure while generating changing test fields | At each send, refresh recognized timestamps to the then-current time (preserve supported RFC3164/RFC5424/ISO/epoch time dialects); randomize supported IP address, location, user name, email address and other recognized fields using safe plausible values while preserving delimiters, quoting, escapes, field order and event boundaries; unsupported ambiguous transformations remain unchanged with a visible warning |
| SCRIPT-3 | P0, after SCRIPT-1 | User-controlled offline execution safety and compatibility | Generated script uses only Python built-in libraries; requires user-initiated execution and explicit destination input, validates destination and port, makes no connection before user confirmation, sends at 1-event/second maximum, defaults to a bounded event count and supports Ctrl-C, reports results accurately; no pip or app backend/sensor management API |
| CI-1 | P0 | Reconcile actual browser E2E assumptions and run exact-HEAD local/integration/CI qualification | Do not disable failing scenarios or report green with known CI failure. Existing product #89 CI #39125171427: 52 PASS, 61 FAIL in historical browser suites; pinned backend integration skipped |
| MAIN-2 | P0 gate | Mainline incorporation | Update main only after exact code/contract comparison, conflicts resolved and required qualification; verify remote main HEAD after merge. No production/release automatically follows a merge |
| LAB-1 | Outside scope | Parser Studio-initiated DP parser upload/apply, server-side sensor sends and ingestion/index-result queries | No real device operations in web/backend product. The downloaded, manually executed SCRIPT-1 script is a separate explicitly in-scope user utility, not a Parser Studio live sensor connection |

**Downloaded test emitter boundary (SCRIPT-1/2/3):** Users explicitly choose
Generate Python Test Sender for the current browser sample and download a
self-contained Python 3 script; the browser constructs the file without
uploading log source to Parser Studio or external AI. Launching that script
on the user's own machine interactively requests destination sensor
IP/hostname and port (UDP default, optional TCP); the script, not the app,
sends exactly one synthetically updated log event per second. Prefer a finite
default count and Ctrl-C, no silent infinite network load; confirm the
destination before any socket send. Scripts must preserve log grammar,
supported time dialects and field boundaries, and distinguish values
regenerated versus retained. Each emitted event has a current timestamp
at transmission and fresh values in recognized IP, geographic location,
username, email and similar supported fields. Ambiguous unsupported values
remain unchanged with an explanation instead of broken parsing. The
downloaded Python file contains the source sample in plain text; warn the
user of its sensitivity before download. No native target validation,
server-side log sending, DP API or ingest result checking is part of
this feature. Test using only synthetic fixtures and loopback receivers.

**Storage boundary:** LOCAL-1/2 stores raw sample logs only when a user explicitly
chooses **Save Version**. Raw data is stored unencrypted by the browser's
origin-scoped IndexedDB and may be readable by others with access to that
browser profile/site origin. No server persistence, remote revision calls, or
automatic external AI transmission. Snapshots are not a backup across browsers
or temporary Cloudflare tunnel domain changes. Explicitly warn about browser
data clearing, private browsing, quota, and short-lived test domains.

**Product focus:** user takes one log, tries multiple extraction/mapping choices,
compares results and restores an earlier saved version. The current backend may
validate/generate a stateless parser DRAFT when the user explicitly requests
it; that request is NOT local version saving and does not persist raw sample logs.

---

> **OWNER OVERRIDE — 2026-10-13:** Parser Studio 2.0 exposes ONLY Auto Parser and ChatGPT Assisted Parser. The 6-step Wizard and 3-pane Workbench are retired from the product UI; their previously stated retention/entrypoint requirements are superseded. All useful backend parsing, mapping, testing, versioning and result operations remain available for internal reuse or integration as context-sensitive result tools. The authoritative scope, acceptance and next tasks are [the two-path v2.0 specification](14_TWO_PATH_PRODUCT_V2.md) and [GitHub Issue #1](https://github.com/xdr-labs/parser-studio/issues/1). Legacy sections below are retained as historical implementation context, not current user navigation.

# 06. Roadmap, Gates and Next Action

## Overall

**Goal:** Independently build a dependable Parser Studio Web application, with portable authoring and evidence-backed Fluentd/Stellar output.

### R0 — Foundation and product definition (THIS INITIAL REQUEST)

- [x] Create xdr-labs/parser-studio repository, private by default because future artifacts may contain sensitive data.
- [x] Persist product outcome, scope, competitor-driven UX, workbench specification, function backlog, version-neutral architecture and ordered roadmap.
- [x] Adopt Engineering System configuration and execution instructions.
- [ ] Reconfirm exact sample-derived parser compatibility contract **after the owner supplies samples**.
- **Done criterion:** published docs in Git, check actual file presence and commit SHA; no claim that parser execution exists.

### R1 — Samples, truth contracts and model (NEXT PRIORITY)

- [ ] Receive representative raw logs and at least one actual parser artifact from owner.
- [ ] Classify artifacts: Fluentd config, Stellar legacy files, Stellar modular JSON or other.
- [ ] Identify syntax, ingestion/header rules, event families, normalization fields, timestamp policies and unsupported features.
- [ ] Define portable IR v0.1 + JSON Schema and golden fixtures; privacy-screen all fixtures before commit.
- [ ] RED tests for correct extraction, type mapping, failures and native-runtime equivalence.
- **Done:** sample-based contract and fixture expectations; unknowns explicitly recorded.

### R2 — Working web workbench / core parsing (P0)

- [x] Create original app skeleton, 3-pane Workbench, UTF-8 sample upload/paste and raw event viewer (**unit 17/17, build PASS, GitHub Chromium browser 9/9 PASS on commit d751252; full user E2E and native engine remain separate**).
- [ ] Event splitting, format candidates, route variants and field highlighting.
- [ ] Rule builder with regex/JSON/KV/Syslog/CSV support and transformations. Narrow browser-only regex/JSON/KV/CSV/RFC5424 subset implemented; full native semantics and route variants pending.
- [ ] Typed normalization mapper to evidence-backed Interflow fields.
- [ ] Live RAW/EXTRACTED/NORMALIZED stage preview with test runner integration. Browser worker, DIFF, per-event trace, save history and select-value→field-proposal flow implemented; native runner pending.
- **Done:** real sample E2E from paste to normalized preview; affected unit/integration/browser tests green.

### R3 — Native validation, regression and export (P0)

- [ ] Sandboxed pinned Fluentd runner with plugin capability manifest.
- [ ] Fixture suite, per-event diagnostics, error grouping, coverage and before/after diff.
- [ ] Revision storage with deterministic hashes, consistent result export.
- [ ] Fluentd output adapter, actual native-engine test, honest compatibility labels.
- [ ] Implement Stellar-specific export only for formats grounded by sample artifacts and real target evidence.
- **Done:** repeatable test report and proven artifact for each supported adapter (no unsupported success).

### R4 — Production-quality usability / supportability (P1)

- [ ] Templates/library, advanced source mode, import error/loss reports and mapping suggestions.
- [ ] Responsive/accessible UI, English-only labels, security and large dataset behavior.
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

## Competitive UX adoption / priority lock (2026-10-12)

**Evidence:** [16-product UX/feature/license review + gap matrix](07_COMPETITOR_RESEARCH_AND_GAP.md) and [original UI decisions](08_UI_DESIGN_DECISIONS.md). The preferred synthesis is Cribl-like persistent staged preview, New Relic-like value-selection field authoring, QRadar-like highlighted field diagnosis, Google SecOps-like typed normalization, Datadog/Panther multi-sample test evidence; no vendor-proprietary code or assets reused.

- [x] Survey documented workflows and screenshots, record license constraints, prioritize differentiating functions.
- [x] Original visual shell, event list, stage preview, typed local mapping, source selection→field proposal, preview-only suite, privacy-preserving browser revision scaffolding.
- [ ] **P0-A:** GitHub Chromium browser smoke 9/9 PASS (d751252); developer desktop Chromium is missing system dependencies, so CI is the browser-test environment. Verify accessibility/keyboard traversal and final candidate HEAD before closing P0-A.
- [ ] **P0-B:** multi-family routing and multiline breaking; selected-source highlights and per-rule trace; strengthen regex safety.
- [ ] **P0-C:** native pinned Fluentd sandbox, golden fixtures, regression/baseline comparison.
- [ ] **P0-D:** real owner `.conf` and matching parser characterization, evidence-based target schema/adapter with import/export loss report. Owner-specific artifacts may not be assumed from public documentation.
- [ ] **P1:** English-only interface, advanced source mode, schema explorer populated from validated Interflow catalog, richer test/failure UX.

**Gates preserved:** R1 sample proof stays pending; R2 UI implementation may proceed while R1 is gated but is not a substitution for missing parser contracts. This is not a release or a claim of actual Fluentd/Stellar compatibility. Remaining work executes in the R1 → R2 → R3 → R4 → R5 order where runnable.

## Cross-cutting acceptance

- Version-neutral editor can work without a running Stellar instance.
- All samples (including minority variants) yield explained statuses.
- No hidden data loss or unsupported transformations on import/export.
- Exact artifact/version support explicitly backed by runner or target-import evidence.
- Customer data is isolated and not published by default.
- No production effects in the initial development path.

## Concrete NEXT_ACTION

**Await owner sample log(s) and existing parser(s) as the only missing product-specific input; then immediately begin R1 characterization, IR/fixture contract and RED tests.** Until samples arrive, implementation may proceed only on independently specified, testable UI scaffolding without asserting Stellar export compatibility. Use this file as the single canonical roadmap and carry precise Git/CI/fixture status into future handoffs.

## Owner language decision (2026-10-12)

Every Parser Studio screen, accessibility label, status, error, code comment, test, fixture, and project document must be written in **English only**. A bilingual UI is no longer in scope. All previously established import, target, privacy, and release gates still apply.


## R2 P0-B — Isolated mixed-family browser tests (implementation evidence, 2026-10-12)

A mixed sample set may include independently detected JSON, KV, CSV, bounded RFC5424,
standalone CEF and LEEF records. The Step 2 **Review One Event Family Separately**
control now permits an explicit local-only Web Worker preview of one recognized
extraction family while **preserving the entire original sample and the draft
unmodified**. The plan enforces 64 KiB/500 events and refuses stale, unsupported,
unknown or blank-line grouped source evidence rather than silently dropping
outliers. The summary includes exact source/selected/excluded counts, matched,
extracted, normalized and failed counts, and original physical-line numbers
with value-free diagnostic codes. No unredacted sample values appear in reports,
saved revisions, API requests or evidence downloads. The isolated fixture
stays transiently in browser memory and is passed only to the Web Worker. This is NOT native mixed-family routing,
a second generated parser, a live network sender or target import verification.

R2 P0-B is **partially implemented**; actual multi-parser native routing, robust
multiline event breakers, matched owner fixtures and real Stellar target validation
remain pending their respective backend/owner evidence gates. UI-only testing
continues independently without claiming a release gate has passed.

**Current development discipline:** This file contains historical acceptance
checklists; do not mistake old unchecked boxes for entirely unimplemented
features. Confirm actual HEAD, Work Packet, code and precise tests before
choosing the next runnable work item. Continue in R1 -> R2 -> R3 -> R4 -> R5
order, skipping only owner-input or unavailable runtime gates.


## R2 P0-A — Keyboard-operated source field → mapping correction (2026-10-12)

Extracted source-field chips in Guided Step 2 now have explicit accessible
button names and distinguish **review an existing mapping** from **add a safe
draft mapping**. One keyboard Enter/click action can add a **single reviewed,
conservative string** mapping in Step 3, using only the structural source
identifier produced by the existing safe unmapped-field suggestion contract.
The action preserves all current rules, refuses unknown/unsafe/prototype or
destination-colliding field paths and never stores or sends event values.
An existing mapping is opened without duplicate creation. The active rule is
visually distinguished with an accessible mapping label, and stage navigation
keeps keyboard focus on the destination heading.

This is browser/local draft usability and does NOT verify a vendor metadata
dictionary, type inference beyond the conservative string choice, or real
Fluentd/Stellar export. Keyboard, duplicate prevention, source retention,
privacy and unsafe-name regression paths are exercised through
tests/field-chip-mapping.spec.ts.


## R2 P0-A — Keyboard raw-value selection alternative (2026-10-12)

The no-code Step 2 value-selection path no longer requires mouse-only text
highlighting. A collapsed, explicitly labeled **Keyboard Alternative: Select
an Exact Raw Value** panel lets keyboard-only/mobile users enter a bounded
exact substring of the selected source event, then separately invoke the
existing field proposal workflow. An unmatched, multiline or overlong value
cannot enable the action. Values are transient in browser memory, are cleared
when the source sample changes, and are not stored in revisions, telemetry or
remote requests. The proposal still requires explicit test coverage and
acceptance before any draft rule can change.

Browser scenarios confirm actual keyboard Enter activation, no backend calls,
value-match validation, clearing stale input after sample edits, preserving the
original complete source and responsive 390px viewport layout. This is a
frontend accessibility/usability improvement, not a native runtime proof.

## R2 P0-B — Explicit all-family browser coverage without silent loss (2026-10-12)

The no-code Step 2 includes an explicit **Audit All Detected Families Locally** button in the existing non-destructive family-review workspace. Unlike the earlier single-family preview, this performs a **bounded, sequential Web Worker pass for each recognized supported format** in the current 64 KiB / 500-event source. The suite, original physical event lines, selected/excluded source counts and per-family worker outputs are cross-checked against the exact current draft and sample. Unknown or unsupported source events appear in an explicit ledger, with original line numbers but **no raw event values**. Every original event must be either reviewed in exactly one detected family or explicitly accounted for as unsupported; any stale sample, truncated family, changed worker event or inconsistent count fails closed.

Results contain only format identifiers, integer counts, source line numbers and diagnostic codes; no customer source bytes, normalized values, API keys or credentials are persisted, downloaded or transmitted. The user can still open and review individual family evidence without mutating the original source or draft. A successful browser family audit **does not create a native multi-parser routing rule, prove a Stellar parser export, or satisfy the pinned Fluentd and target E2E gate**. Existing R1 owner-supplied artifacts and R3 native proof are still required; do not mark those tasks complete. Unit tests and Chromium source-preservation/unknown-family/keyboard/privacy regressions are in `src/guided/familyAudit.test.ts` and `tests/all-family-audit.spec.ts`.

## R2/R3 — Redacted all-family audit evidence (2026-10-12)

The all-family local-only audit can now be **explicitly downloaded as metadata-only JSON**. The export recomputes the exact original sample/family allocation and checks the full browser preview, each reviewed family's source-line identity and status, all unsupported events, count invariants and false runtime/target verification flags. It binds the result to SHA-256 hashes of the exact sample and draft but never exports raw records, mapped/normalized field values, arbitrary diagnostic text, private parser fragments, API keys or tenant data. A changed draft/sample invalidates the download path. The full original sample and each unsupported event remain accounted for in the report, while a separate warning makes clear this is **not** native mixed-family routing or Stellar target validation. Download is optional and browser-only; it does not upload or save any customer logs. Unit/browser regression tests assert value-free output, deterministic provenance, and fail-closed behavior for tampered/untrusted metadata.

## R2 P0-B — Whitelisted local audit diagnostics (2026-10-12)

A regression test exposed that an arbitrary, uppercase Web Worker diagnostic code could be copied into browser-visible metadata. This was corrected at the shared family-isolation summarizer: **only fixed, previously reviewed parser diagnostic codes are retained**, and unknown codes are replaced by `DIAGNOSTIC_UNAVAILABLE`. The same allowlist protects both one-family previews and the new all-family reports. Step 2 displays at most eight sanitized source-line/status/diagnostic summaries per family, preserving full aggregate counts and keeping all actual log bodies and diagnostic messages out of reports. Unit tests deliberately inject private-looking worker diagnostic codes and verify neither those identifiers nor messages escape.

## P0-LIVE-0/2 — Owner-scoped offline artifact revision UI (2026-10-12)

Guided Step 6 has an **opt-in** offline revision workspace for exact generated
DRAFT Ruby + CONF pairs. The separately maintained backend supplies
`/api/v1/parser-pairs/revisions/register`, `list`, `diff`, `download`, and
`restore-preview`. The browser verifies the input pair, project-scoped
metadata, revision identity, two file hashes, immutable ZIP SHA-256 and
restore-preview response contract before displaying or downloading anything.
Diffs expose only version, port, filenames and SHA values, never code bodies,
raw sample logs, keys, or tenant identifiers.

No request is made until the owner explicitly clicks an action. All requests
use same-origin authentication; an unconfigured or unauthorized endpoint
returns **403 and stays unavailable**. The backend history is owner/tenant
scoped, temporary and non-persistent. A restore preview returns an old,
verified ZIP for optional manual download: it does not replace the draft,
rollback any actual DP parser, send to a sensor, or invoke any target API.
Native compatibility and actual platform ingestion remain unverified.
Unit regressions: `src/guided/artifactRevisionClient.test.ts`.
Chromium user/denial/tamper scenarios:
`tests/artifact-revision-history.spec.ts`.

## P0-LIVE-2 — Explicit MOCK_ONLY Apply UX (2026-10-12)

When the owner-scoped revision list is explicitly loaded, Step 6 offers a
separately collapsed **MOCK_ONLY Apply Test** for its current immutable DRAFT
revision. A user may check the temporary mock status, then enter a server-issued
mock approval reference and explicitly confirm before submitting a metadata-only
request to `/api/v1/parser-pairs/target/apply`. The client refuses any proof
that is not strictly `MOCK_ONLY` against a `.invalid` HTTPS destination,
does not contain the selected revision's exact file hashes, or claims real
runtime, target import or sensor verification. It never collects or submits
DP URLs, DP API keys, raw logs, sensor addresses, or generated Ruby/CONF bodies.
The default response is 403 unless a trusted server operator enables the mock
gateway. The user cannot turn this into real deployment using browser controls.

This is a pre-production mock contract and does **not** satisfy general-user
DP Apply, actual parser installation, same-port sensor proof, or Full User E2E.
Those separate tasks remain gated by the authenticated real backend
and owner-authorized target evidence.

## R2/P0 Test Lab — Redacted summary and integrity-checked evidence download (2026-10-12)

The existing owner-authorized Test Lab session workspace now has a separately
collapsed, **opt-in offline evidence review** for the authenticated run. Its
read-only same-origin `GET /api/v1/test-lab/sessions/evidence-summary` action
displays bounded stage counts, field match/mismatch/missing and coverage ratios,
and a fixed allowlist of failure codes, never source values. Its separate
`evidence-export` download verifies size, attachment headers, exact run ID,
optional previously reviewed artifact revision ID, UTF-8 JSON schema, per-event
stages and SHA-256 from the backend before downloading the original bytes.
Unsupported or cross-owner endpoints are denied by default (403/404); the
browser never infers authorization from knowledge of a run ID.

The panel does not automatically query, persist evidence, configure a Test Lab
sink or send events. The result is explicitly **OFFLINE_CONTRACT** and remains
unverified for real sensor reception, native Ruby/Fluentd parsing, Stellar DP
ingestion and Full User E2E even when an offline mock field comparison is
reported. No raw logs, private event values, tokens, credentials or target
locations are sent or exported. Synthetic RED→GREEN regression coverage:
`src/guided/testLabEvidenceClient.test.ts` and
`tests/testlab-evidence-report.spec.ts`.

## R2 P0-B — Per-event, per-rule browser-only diagnostics (2026-10-12)

Guided Step 5 now includes a keyboard-accessible **Inspect Rule-by-Rule
Outcome** panel. It consumes the current draft-bound browser Web Worker
preview and shows each mapping rule by numeric index, with fixed diagnostic
states for emitted output, missing source, invalid type, unsafe/unsupported
rule, ambiguous duplicate destination, incomplete extraction or unresolved
output. Users can choose an event number, review a rule, and jump to its
existing editable Step 3 mapping card without changing its field contents.

No raw sample values, normalized values, arbitrary untrusted diagnostic
messages/codes or customer log bodies are copied into the trace. The entire
source remains unchanged and no network request, native runner, sensor send,
DP registration or automatic transformation occurs. Stale source/draft
previews and forged native verification flags are rejected. Unit regression:
`src/guided/browserRuleTrace.test.ts`. Chromium keyboard/navigation,
source-retention, stale-edit and data-leak scenarios:
`tests/browser-rule-trace.spec.ts`.

This completes only the local **per-rule inspection usability** part of
R2 P0-B. Actual multi-family native routing and robust Fluentd multiline
event breaking remain unverified and must not be marked complete.

## R4 — On-demand detailed workspaces and initial JavaScript budget (2026-10-12)

The generated Step 6 revision history, authenticated Test Lab evidence panel
and local per-rule trace are now loaded with React Suspense **only when
needed**, preserving the same server authorization and user-action gates.
They do not initiate network requests on module import, nor start a sender,
runtime runner, vendor query or target operation.

At the prior UI HEAD `1056449`, the Vite initial JavaScript chunk was
**518.94 kB (151.40 kB gzip)**. After separating those three panels into
on-demand chunks, it is **481.70 kB (141.73 kB gzip)**, with independently
loaded 4.16 kB, 11.64 kB and 23.27 kB panel bundles. This is a
build-artifact size improvement, **not** an independently measured browser
load-time, memory or Core Web Vitals PASS. Existing Chromium user flows,
keyboard navigation and disabled-by-default API behavior remain the
required exact-HEAD regression checks.

## R2/P0-A — Beginner-safe local log format recommendation (2026-10-12)

The Guided Builder now provides an **Automatic Format Check · Browser Only**
on import and extraction steps. Users may paste single-line raw logs without
knowing whether the input is JSON, key/value, RFC5424, CEF or LEEF. A bounded,
source-identity-checked browser Web Worker preview proposes **one supported,
homogeneous, successfully extracted format**, with reviewed event counts,
minimum signature confidence and no raw values.

The format is **never changed automatically**: the user must select
`Use Detected Format`. Approval only updates `draft.format`, retaining
the original sample and existing field mappings. Mixed, unknown, unsupported
CSV/generic Syslog/regex, malformed, stale, truncated, oversized, multiline
and untrusted worker previews fail closed or require explicit manual review;
minority events cannot be silently dropped. Format detection does not prove
that native Fluentd/Stellar parser output is verified or deployable. No log
bytes, extracted values, credentials or API requests leave the browser via
this recommendation.

Deterministic RED→GREEN unit and Chromium keyboard, privacy, cross-family
and stale-edit acceptance are maintained in
`src/guided/localFormatAdvisor.test.ts` and
`tests/local-format-advisor.spec.ts`. Native runtime, actual customer-parser
golden fixtures, mixed-family routing and target verification remain separately
gated.

### Manually incorrect format choice (review-only fallback)

When the sample has one high-confidence supported format but the user has
manually selected a different extractor, the browser reports a
`CANDIDATE_UNTESTED` format, with an explicit **Try Detected Format** action.
This is a signature-only suggestion, **not** an extraction PASS. After the
user chooses it, the full unchanged source is parsed again locally.
Malformed records under the already matching extractor remain blocked; mixed
families and unknown events never become a recommended native parser.

## P0-LIVE Test Lab — Separately approved active-session rate adjustment (2026-10-12)

For an already owner-authenticated **RUNNING** or **PAUSED** Test Lab
session, the Step 6 control offers a separately collapsed, **opt-in rate
adjustment** (0.2, 1, 2 or 5 synthetic events/sec). It submits only
`{runId,approvalId,ratePerSecond}` to the existing backend
`POST /api/v1/test-lab/sessions/rate`, after an explicit separate
operator approval reference and checked confirmation. Every request
remains subject to independent backend session ownership, lease,
in-flight transport and approval validation.

Rate changes cannot start a new session, increase the event quota or
extend the lease. The new server status must retain exactly the previous
run ID, lease, maximum events, replay mode and family count; unsupported
`original-gaps` scenarios are not offered the control. Old rates remain
visible on 403/409/422/503 denials. Approval input is cleared after
success or refusal and is not stored. The UI never embeds DP URLs, API
keys, actual sensor addresses, raw customer logs, or a transport client.
Real send/native parsing/target ingestion proof is **not** implied by
a synthetic server rate change.

Affected regression evidence:
`src/guided/approvedTestLabSession.test.ts`,
`tests/approved-testlab-rate.spec.ts`.


## 2026-10-16 Full User E2E implementation checkpoint

This is a historical checkpoint. Use the current engineering completion ledger at the top of this document and Issue #1 for continuation. The original R0-R5 checklist is not a reliable completion percentage.

### Verified development changes

- UI cumulative branch `fix/novice-e2e-cumulative-ui-20261016`, verified commit `6d7143b` (later commits must be checked separately).
- Backend cumulative branch `fix/novice-e2e-cumulative-backend-20261016`, verified commit `1438535` (later commits must be checked separately).
- Isolated historical UI branch `fix/novice-e2e-isolated-ui-20261015`, commit `ba12659`, preserved as history, not an independent release candidate.
- Bounded Funnel remains additive to the qualified Multi-Pass/Generic Structural base. No PR merge, production release, DP/sensor or native-target change is implied.
- WatchGuard alarm/diagnostic/event: 416/416 bounded structural extraction in a source-corpus check; this is **not** a 416/416 native parser or browser E2E claim. Prior novice guided recovery and limited actual Chromium parser generation are recorded in Issue #1.
- Focused UI tests: 45/45 PASS for structural clustering/capabilities/extraction, followed by 5/5 PASS for distinct BSD host-label shape.
- Focused backend tests: 17 PASS, 8 Ruby-runtime-dependent SKIP, 0 FAIL; missing Ruby runtime means native parity is not yet qualified.

### Owner scope override — exclude Stellar DP / sensor closure gates (2026-10-16)

The owner removed real Stellar target execution from Parser Studio product-completion criteria. The following are **out of this roadmap** and must not block product completion:

- real Stellar DP parser upload/import/activation;
- DP syslog/traffic/Interflow index readback as a product acceptance gate;
- sensor packet send/receive verification;
- sensor binding, target listener inventory or target-port reservation;
- production/tenant target mutation.

Those activities may be handled later as a separate target-integration project. Parser Studio continues to use the public Stellar metadata dictionary for normalization authoring and the pinned local Ruby/Fluentd environment for parser artifact verification.

### Historical remaining work recorded on 2026-10-16

1. **R1 — Long-tail parser closure (P0):**
   - Juniper Junos: current recorded grouped-assisted recovery is 95/100. Resolve the residual 5 events only with bounded structural/Parser Set logic; otherwise classify them as explicit safe-abstention. Never force one broad Regex.
   - Defender-style endpoint logs: source extraction is proven, but the compiler/generation gate still needs the same no-loss path to `Create Parser Files`.
   - Cisco Umbrella Proxy quoted 23-column CSV: extraction/grouping works; close the remaining compiler reproduction gate for the homogeneous quoted shape.
   - Pulse Connect Secure and Barracuda are no longer remaining roadmap items: their guided/local DRAFT paths were already demonstrated.

2. **R2 — Large-batch beginner UX (P1):**
   preserve the current accuracy-first behavior but improve perceived progress for large 100–400 event analyses; no timeout-based accuracy shortcuts. Keep source/no-loss, holdout and false-complete gates unchanged.

3. **R3 — Owner visual acceptance (P0):**
   owner reviews the deployed development UI, especially Review Fields → Map Fields → Create Parser, automatic official mapping suggestions, manual override/unmap, collision/type diagnostics and mobile readability. Fix only defects actually found in this review.

4. **R4 — Closure / merge decision (owner gate):**
   after R1–R3 are green, freeze the exact HEAD, retain exact-head CI evidence, then request separate owner approval for PR/merge/release. No DP/sensor work is part of this gate.

### Already complete and not remaining

- integrated Auto Parser + bounded Funnel/Generic Structural candidate;
- official public Stellar 7.0.xs normalization catalog and mapping review UI;
- 89 files / 663 unit tests PASS and production build PASS on the normalization candidate;
- generic Chromium 50 PASS / 28 live-backend-gated SKIP / 0 FAIL;
- security-family normalization E2E 8/8 PASS;
- pinned backend live Chromium/HTTP integration 29/29 PASS;
- final exact-head GitHub Actions run #38843728978 SUCCESS on `7f2015de6ead10ad5bdaa1641ae30c92ec9c822c`.

### Worktree cleanup

Parser Studio development is consolidated to one standalone active repository: `/home/aella/parser-studio-beginner-parser-set-e2e-20261016`. Obsolete Parser Studio worktrees, experimental runtime directories, stale Playwright/Chromium/Vite processes, and prior test-result directories were removed on 2026-10-16. The owner-private `/home/aella/.parser-studio-secrets` credential store is intentionally preserved. The active UI/backend/Multi-Pass development runtime is kept under the active repository as local excluded runtime state and is not Git product content.

## P0-NORM — Stellar Cyber normalization mapping review (owner decision 2026-10-16)

Product flow: Add Logs → Review Fields → Map Fields → Create Parser. Retain the two top-level creation methods. Parsing and normalization must remain independently measurable; preserve original extracted values, and never infer target verification from browser previews.

- [x] NORM-01: official public Stellar Cyber 7.0.xs Metadata Dictionary is revision-pinned by source URL/SHA with scalar/non-scalar/ambiguous/reserved-field fail-closed behavior. Real target-runtime evidence is outside the revised product scope.
- [x] NORM-02: deterministic, explainable field-name/value/type candidate engine with whole-sample confidence, abstention, collision protection, safe replacement of untouched generated custom defaults, and no silent remapping or original-value loss.
- [x] NORM-03: dedicated beginner Map Fields stage shows source values, proposed official destinations, approval/override/unmap, searchable revision-pinned catalog, responsive/keyboard-accessible controls, and explicit catalog provenance.
- [x] NORM-04: selected-event plus whole-sample raw/extracted/normalized comparison, changes-only view, type/timestamp/collision/missing-field and catalog diagnostics; mapping changes revoke prior generated verification evidence through draft identity.
- [x] NORM-05: reviewed official and custom mappings persist in browser revision/portable draft and the existing backend adapter. Uncertain targets remain `custom.*`/vendor fields; no unverified 1:N target mapping was added, and bounded split/merge remains a separately reviewed enrichment contract.
- [x] NORM-06: local native authoring/integration is complete for product scope — exact pinned backend `14385351d65c9732ba9c35cd8688b8c9f223a90d` passed 29/29 live Chromium/HTTP integration scenarios including Ruby/CONF DRAFT generation, SHA/ZIP verification, mixed security formats and fail-closed mapping collisions. DP/sensor execution is excluded by owner scope.
- [x] NORM-07: browser Full User E2E covers EDR/XDR/NDR/EPP/AWS CloudTrail/AWS WAF/IPS/VPN with 8/8 normalization journeys PASS. Evidence: 89 files / 663 unit tests PASS; production build PASS; generic Chromium 50 PASS / 28 live-backend-gated SKIP / 0 FAIL; exact pinned live-backend suite 29/29 PASS; final exact-head GitHub Actions run **#38843728978 SUCCESS** on `7f2015de6ead10ad5bdaa1641ae30c92ec9c822c`.

**P0-NORM engineering scope: COMPLETE.** Owner visual acceptance is tracked separately under R3; real Stellar DP/sensor execution is not part of this roadmap.

## Owner follow-up — Stellar Cyber 7.0-only normalization integrity (2026-10-21)

**Fixed target schema:** published Stellar Cyber 7.0 (`7.0.xs` documentation). No 6.5/6.6 per-version schema, compatibility logic, migration matrix or UI selector. This is a new authorized accuracy workstream, separate from completed PR #123.

1. **NORM7-P0:** Reject malformed IPv6 at the browser conversion and recommendation boundary; remove ambiguous status-to-action aliasing; reject sparse/placeholder-only confidence. Prevent order-dependent bulk mapping of multiple type-compatible sources to one official destination.
2. **NORM7-P1:** Extend the single pinned 7.0 catalog only with explicitly documented and typed nested scalar paths. Enforce official action/hash semantic constraints. Preserve existing vendor-only mappings and original source values, and keep unsupported float/complex types fail-closed.
3. **NORM7-P2:** Run deterministic RED-to-GREEN tests, actual desktop Map Fields Chromium and backend contract checks, then exact-HEAD CI. Existing completed source/CI/public tests must not be repeated solely as a continuation.
4. **Accuracy evidence deferred:** Independent manufacturer source goldens and proprietary Stellar native target behavior are not established by synthetic fixtures. Generated artifacts remain DRAFT and unknown evidence remains UNSCORABLE.

Implementation details: [Stellar 7.0 normalization integrity verification](verification/20261021-stellar7-normalization-integrity.md). Keep the deployed development build, historic worktrees and completed evidence unchanged. Mobile, DP/sensors, production, releases and authorization changes are excluded.

## P2-JSON-DUP — common JSON source/native key integrity (2026-10-21)

Multi-Pass already rejects duplicate JSON object member names. Browser
and compiled Ruby previously risked last-value overwrite.

- [x] Duplicate decoded object names fail-closed in browser extraction
  and automatic source census; original source remains unchanged.
- [x] Apply the same reject semantics to native Ruby DRAFT JSON paths.
- [ ] Exact-HEAD GitHub CI and real Chromium qualified on new candidate.
- [ ] Other Generic Structural prefixed/container JSON families require
  independent native oracles before asserting broader compiler parity.

Evidence: verification/20261021-json-duplicate-source-native-parity.md.

## S7-P2A — fixed 7.0 per-event-type mapping evidence (2026-10-21)

- [x] Type-scoped 7.0 Dictionary candidates for explicitly reviewed event
  families; no cross-type inference, implicit format selection or auto-apply.
- [x] Manual 7.0 top/ns confirmation with additional explicit route approval;
  vendor-only fallback and original source unchanged.
- [x] Official value and type validation before conditional DRAFT acceptance.
- [x] Independently authored synthetic Threat/User/Asset six-event oracle
  with 16 exact expected field/value matches. Two distinct desktop browser
  user journeys verify DRAFT Ruby/CONF download integrity; synthetic
  acceptance is not manufacturer-wide accuracy.
- [ ] Exact-HEAD CI and stacked PR review on the new candidate.
- [ ] Manufacturer/firmware normalization accuracy scoring only when
  independently sourced and authorized golden originals become available.

Evidence: verification/20261021-stellar7-scoped-event-family-mappings.md.
No version-specific schema management beyond the pinned Stellar 7.0 catalog.

## P3-GENERIC-JSON — wrapped JSON source no-loss gate (2026-10-21)

- [x] Reuse common decoded JSON member-name uniqueness checks for
  bounded Generic Structural prefix, short RFC5424 JSON and JSON
  envelope extraction, preserving the literal original source.
- [x] Use the same strict compiled native Ruby JSON decoder for
  prefixed and standard JSON rather than a permissive parallel parser.
- [ ] Exact-HEAD GitHub Actions Ruby acceptance and real desktop
  Chromium qualification before claiming native DRAFT parity.
- [ ] Remaining vendor-wire/container extensions require independent
  positive/negative source oracles. No synthetic manufacturer F1.

Evidence: verification/20261021-generic-json-duplicate-source-parity.md.
Only fixed Stellar Cyber 7.0 normalized fields are in scope; no 6.5/6.6
schema handling, mobile, DP, sensor or production deployment.

## P4-SYSLOG-JSON — strict browser/native source and multiline parity (2026-10-21)

- [x] Refuse repeated decoded JSON object names in explicit RFC5424/RFC3164
  bodies; match the already strict Ruby DRAFT backend source semantics.
- [x] Mark duplicate-key multi-line JSON boundary candidates as
  AMBIGUOUS / REVIEW_REQUIRED with physical source event accounting intact.
- [x] Authored positive and negative oracles, focused source tests and
  two actual Chromium localhost source workflows, no HTTP stubs.
- [ ] Exact-HEAD CI, Draft PR and ACTIVE Work Packet evidence before closure.
  No manufacturer-wide accuracy percentage from synthetic fixtures.

Evidence: verification/20261021-syslog-json-boundary-source-integrity.md.
Stellar Cyber normalization is pinned to 7.0; no 6.5/6.6 schemas,
DP/sensor, mobile, production, proprietary runtime or release changes.

## P5-FRAMING-JSON — GELF/RFC7464 decoded JSON member identity (2026-10-21)

- [x] Original NUL-delimited GELF and RFC7464 JSON Sequence pre-validation
  reject duplicated *decoded* JSON member names via the same strict
  common source hook already used by Docker JSON-file framing.
- [x] Invalid original containers return RAW_ONLY and their exact source
  bytes are preserved. Valid separate object scopes and Unicode text remain
  source-only PARTIAL, never native/target-verified.
- [x] New 7 authored negative cases (framing RED before fix), 3 focused
  Python regression methods, existing 7 transport and 8 Audit/CRI/Docker
  framing regression tests GREEN.
- [ ] Exact-head CI and scoped Draft PR evidence; no target integration.

Evidence: verification/20261021-gelf-jsonseq-source-framing-identity.md.
Stellar Cyber Dictionary remains fixed to 7.0 only; no 6.5/6.6 schemas,
mobile, DP/sensor, production, target import or merge/deployment action.
