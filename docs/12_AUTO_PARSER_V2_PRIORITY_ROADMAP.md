# 12 — Auto Parser v2.0: Owner-Ordered P0 Plan, Design and Acceptance

**Owner direction:** 2026-10-12. **Priority:** **P0-AP / FIRST across Parser Studio UI and backend**, overriding older lists that still call the six-step Guided Builder the default. **Status:** PLANNED, NOT IMPLEMENTED by this roadmap change.

**Sources of truth:** [Issue #1](https://github.com/xdr-labs/parser-studio/issues/1) (current owner priority, ACTIVE Work Packets and exact Git/CI evidence), [06 — canonical roadmap](06_ROADMAP_AND_ACCEPTANCE.md), this detailed acceptance contract. [08](08_NO_CODE_USER_EXPERIENCE.md) is the *existing* six-step Guided Builder; it becomes a secondary detailed editor. [02](02_WEB_UI_SPEC.md) is the existing Expert Workbench. [09](09_BACKEND_PAIRED_ARTIFACT_DESIGN.md) governs the existing paired Ruby/CONF artifact and target verification boundaries.

## 1. Product decision / why this is first

A first-time field engineer, partner or customer must be able to **paste representative raw logs without knowing JSON, RFC3164/5424, CEF, LEEF, Regex, Grok, JSONata or Ruby**, immediately inspect automatically extracted and typed field candidates, and generate a **validated DRAFT pair** (`customized_<slug>` Ruby fragment + `customized_<slug>.conf`) through three clear steps:

1. **Add Logs** — paste/upload; automatically identify *logical events*, wrapping envelope(s), body family, template variants, and unsupported events.
2. **Review Results** — show detected fields and suggested destinations, evidence per sample, ambiguity needing a human decision; corrections are optional rather than required setup.
3. **Test & Generate** — run all applicable samples and native tests for supported operations, show truthful evidence, then download/optionally authorized DP Apply.

Keep existing Guided Builder and Expert Workbench, revision history, Test Lab, target controls and validated artifacts intact, reachable via `Edit Details`/`Advanced`. **Do not delete or rebuild completed functionality.** AI is an opt-in fallback for unknown semantics or unsuccessful deterministic extraction, not a prerequisite for parsing structured logs.

### Verified engineering gap at decision time

- Current `src/parser.ts` browser `detectFormat` recognizes narrow standalone signatures and some Syslog hints, whereas `src/guided/backendAdapter.ts`, `backend/src/types.ts` and `backend/schema/parser-project.v0.1.schema.json` accept a restricted compiler subset. Preview detection **does not guarantee supported Ruby/CONF compilation**.
- RFC3164, Syslog-prefixed CEF/LEEF, diverse outer-envelope/body combinations, mixed families and physical multiline are incomplete or separately preview-only. The current `extractSyslog` browser approximation expects a narrow RFC5424 shape.
- Existing six-step UI can suggest some fields and formats, but a novice still faces separate extraction/mapping/classification/verification tasks. Prior sample/browser/mock PASS cannot be relabeled as true native/DP/sensor PASS.
- Native synthetic Ruby/Fluentd test infrastructure and protected revision/test/DP-mock UX already exist; **reuse these**. Do not re-run previous competitor research, copy previously implemented panels, or claim actual real Stellar deployment compatibility.

## 2. Strict next-work ordering (highest first)

**Immediately after finishing any atomic, already-in-flight test/commit safely, execute P0-AP1.** This priority is an explicit owner override: do not select another historical R2/R3/R4 task before the first uncompleted runnable P0-AP task, unless an exact technical dependency prevents it. Respect separately approved production/target/credential gates. Every lane uses its own branch/worktree; never overwrite another lane.

### P0-AP1 — Consistent universal detection, logical event boundaries and explainable failures (FIRST IMPLEMENTATION)

**Backend + UI, independently coordinated through versioned interface.** Extend deterministic detection and compilation **before** adding an AI UI. Define an envelope/body detector: plain JSON (including nested paths), key/value quoting and ordering, standalone CEF/LEEF, CSV, RFC3164 and RFC5424 Syslog with body routing to JSON/KV/CEF/LEEF/raw as supported. Preserve line origins and original-event denominators. For mixed families, classify each event and propose family-specific handlers, without pretending current v0.1 can compile mixed routing. Treat physical multiline JSON and Java stack traces as explicit logical-boundary candidates with bounded buffers and fail-closed ambiguity.

- **UI deliverable:** one-click `Analyze Logs`, event-family/unknown/malformed ledger, evidence-backed supported/unsupported compiler capability for each candidate; no unsupported `Auto` green status, no raw sample export.
- **Backend deliverable:** reviewed envelope/body capability contract + codecs/validators for incrementally supported combinations; portable snapshot of the supported subset, no arbitrary Regex or payload execution.
- **Tests:** RED→GREEN synthetic RFC3164+KV; RFC5424+JSON; Syslog+CEF/LEEF; standalone JSON/KV/CEF/LEEF/CSV; nested JSON, quoted/escaped KV, field-order changes, unknown, corrupted header, truncated input, malformed CEF, overlong and multiline; deny false sample success and unsupported compilation.
- **Exit:** for each sample, the same candidate has a true browser result and an explicit backend supported/unsupported state. Newly declared supported combos compile and pass native fixtures, not simply browser preview. Each source event is accounted for exactly once; existing supported formats do not regress.

### P0-AP2 — Make Auto Parser the three-step default (no-regression UX)

**UI lane owns:** landing/create flow automatically opens **Auto Parser**, not Workbench/six-step Wizard. (1) Paste/upload logs; (2) preview all extracted values and field types, user-reviewed Stellar destination candidates; (3) test/compile/download. A novice never has to select a format, create Regex, map every benign field, or open receiver internals for the supported happy path. Preserve manual override for ambiguous time formats and field semantics.

- `Review Results` exposes raw → extracted → normalized on selection; highlight per-field source spans and the failed event; show optional `Adjust` and `Advanced` to enter existing editors without losing samples/rules.
- Use **verified** Interflow schema/field dictionary for official mapping suggestions; if catalog evidence is unavailable, keep conservative vendor fields and label any destination `Suggestion / Unverified`, never invent official field names.
- Auto-apply only safe deterministic mappings with provenance; explicit review for source/timestamp ambiguity, timezone absent from RFC3164, source vs destination IP uncertainty, duplicate targets and classification.
- `Generate` is disabled or marked unsupported until all selected operations can compile. Preserve draft-generation and target-qualification distinctions.
- **Exit:** novice can complete the supported three-step example without entering Regex/CEF/JSON/Ruby concepts; Step 2 explains all unknown events; no loss of old Guided/Expert features; real Chromium keyboard, mobile/narrow-screen, source-preservation and privacy user scenarios PASS.

### P0-AP3 — Versioned ParserRecipe v0.2 and safe compound Ruby/CONF compiler

**Backend lane owns contract/compiler; UI lane integrates adapter.** Introduce a target-independent, deterministic `ParserRecipe v0.2` (as a new version, **do not rewrite or silently coerce stored ParserProject v0.1**). Minimum allowlisted staged operations: `split_event`, `unwrap_syslog`, `parse_json`, `parse_kv`, `parse_cef`, `parse_leef`, `parse_csv`, `map_field`, `cast_type`, `classify`, `fallback_unparsed`; explicit stage order, family predicates, sample evidence, type/time policy, supported/unsupported and versioned capabilities. Implement incrementally: prefer reusing existing compiler paths for simple operations.

- Define strict JSON Schema, bounded operator and field identifier allowlists, source path constraints, bounded nesting/depth/length, hard failure on unknown operations and illegal transformations.
- Recompile valid subsets into exactly matching `customized_<slug>` Ruby and `.conf`, checksum/manifest/round-trip revision. Unsupported combinations must report a stable error code and no misleading export.
- Verify Ruby/Fluentd output for multiple event families against the same expected typed outputs. JS Regex, JSONata, OTel stanza, Grok and RE2 must **not** be treated as Ruby/Fluentd-native interchangeable syntax without translation and native tests.
- **Exit:** deterministic and documented v0.1↔v0.2 compatibility/loss report, explicit supported operator matrix and exact pair hash; synthetic native runtime tests match the declared Recipe semantics across supported families; no E2E target-import claim without independent proof.

### P0-AP4 — Whole-sample regression, guided repair and evidence-led release boundaries

**Both lanes:** Evaluate the complete representative suite (not only selected "green" events), hold out events unseen by any candidate-generator, group failures by reason and family, show before/after field diffs; allow explicit small deterministic repair proposals (e.g. a new body-family fallback) without silently mutating accepted rules.

- Test: variant field order, missing/null/duplicate key, quotes/escapes, mixed Syslog envelope, type mismatch, time year/zone ambiguity, payload prompt injection, multiline event boundaries, empty input, malformed/truncated samples and limits.
- Show a finite state machine: `ANALYSIS_FAILED` / `BOUNDARY_AMBIGUOUS` / `EXTRACTION_NO_MATCH` / `TYPE_CONFLICT` / `COMPILER_UNSUPPORTED` / `NATIVE_PENDING` / `NATIVE_FAILED` / `TARGET_NOT_VERIFIED` with an actionable, plain-English next step.
- Release gate remains: relevant RED→GREEN unit + browser scenario PASS, native runner PASS on same tested candidate, sha/revision proof. Real DP/sensor Interflow remains an independent, separately authorized gate.
- **Exit:** zero silent event dropping or mislabeled PASS. Candidate and baseline regressions available; per-family denominators and unrecognized source ledger accounted for.

## 3. P1 follow-ons — after usable deterministic P0 Auto Parser

### P1-AP5 — Unknown-text template mining and parser fingerprint reuse

Evaluate an **isolated** Drain3 template-mining worker for unstructured text (MIT license), cluster/variable extraction, representative-sample selection, and existing approved parser fingerprints based on redacted/hashed metadata. Preserve unknown/uncertain tokens; structural cluster matches alone do not make a meaningful Stellar field mapping. Python worker must be isolated/CPU+memory+timeout bounded; return declarative candidates only, no runtime source execution. Benchmark new, holdout and mixed texts. Avoid modifying reference vendor parser bodies or redistributing proprietary examples.

### P1-AP6 — Copy AI Prompt / Paste AI Recipe, then opt-in integrated AI

First provide privacy-reviewed `Copy AI Prompt` and strict JSON-Schema `Paste AI Recipe` import, with stable typed errors and loss reports. Limit initial JSONata integration to explicitly supported path/transform subset. Only later offer integrated provider AI with explicit tenant/user consent, cost/rate caps, redaction preview, audit, no external network calls by default. All log content is **untrusted**, including prompt injection; no pasted untrusted Ruby/Grok/Regex/JSONata execution in privileged process. LLM must return candidates, never unreviewed executable Ruby/CONF or auto-apply DP.

### P1-AP7 — Controlled automatic repair, reusable patterns and usability experiments

Create an opt-in repair loop: new failures ⇒ bounded candidate update ⇒ regression against prior positives and holdout ⇒ user approves or rejects ⇒ immutable revision. Maintain reviewed reusable template signatures and no-raw-log provenance. Run real user tasks and measure before/after rather than claiming unmeasured speed or accuracy gains.

## 4. Specific acceptance examples and quality objectives

| ID | Exact beginner / system test | Pass condition |
| --- | --- | --- |
| AP-T01 | Paste RFC3164 + spaced/quoted KV records | Header/body separated, typed fields proposed, year/timezone ambiguity explicitly marked |
| AP-T02 | Paste RFC5424 + JSON payload | Nested fields extracted with provenance and correct timestamp |
| AP-T03 | Paste Syslog-wrapped CEF and LEEF | Header unwrap + correct body family, no unsupported false green |
| AP-T04 | Paste standalone JSON/KV/CSV/CEF/LEEF | Existing verified behavior maintained |
| AP-T05 | Log fields reordered, optional fields omitted | Every event accounted for, no accidental no-match or type pass |
| AP-T06 | Mixed families and unknown text | Clear per-family result/unsupported ledgers, no universal single-parser claim |
| AP-T07 | Physical multiline JSON / stack-trace samples | Bounded grouping when deterministic; ambiguous boundaries explicit |
| AP-T08 | Invalid/malicious/oversized input, unsafe syntax | Bounded processing; fail-closed; no raw data leak or arbitrary execution |
| AP-T09 | No selected mappings, invalid time or ambiguous semantics | Clear human-friendly corrective action, no fabricated normalized PASS |
| AP-T10 | Recipe v0.2 compile → native fixture | Output matches expected typed golden for all declared supported stages |
| AP-T11 | New repair candidate on held-out examples | New matches do not regress previous correct outputs; changes diffed and user-approved |
| AP-T12 | Same-pair port and target qualification | `.conf` receiver port equals chosen sensor receiving port; Syslog >=6800; detect collisions separately; DP/Interflow remain NOT VERIFIED until real authorized evidence |

**Product usability goals (targets, NOT results):** supported beginner happy path is 3 UI steps with zero forced format/Regex knowledge; compare completion rate, median user actions/time, first-try extraction, per-family coverage and held-out accuracy against the existing Wizard. Proposed acceptance target: ≥80% task completion by unfamiliar users, ≥50% improvement in median task time; measure before claiming. Maintain 0 silent lost records and 0 unsupported/native/DP false green labels.

## 5. Ownership, safety and evidence

- **UI PR #7** owns default Auto Parser screen, local detection/evidence, human review, safe UI adapter and browser tests. **Backend PR #4** owns durable v0.2 contracts, real compiler operations and pinned native Fluentd evidence. **Docs PR #2** updates intent only. Keep all worktrees and unrelated dirty changes untouched.
- **Actual target verification:** real DP API/loader import, same chosen sensor/.conf port, approved sensor send and independent tenant Interflow readback are not unlocked by synthetic tests. No production writes, release, merges or credential/permission changes without required separate authorization.
- **Privacy:** raw customer logs are session-private by default; no external LLM/AI transmission or raw-log persistence by default; metadata-only reports and redacted examples. Explain all network calls and target mutation separately.
- **External code/license:** [Drain3](https://github.com/logpai/Drain3) MIT, [grex-js](https://github.com/pemistahl/grex-js) Apache-2.0, [OpenTelemetry Collector contrib](https://github.com/open-telemetry/opentelemetry-collector-contrib) Apache-2.0, [JSONata](https://github.com/jsonata-js/jsonata) MIT are candidates subject to provenance/dependency review. [Loki](https://github.com/grafana/loki) AGPL-3.0 and Loghub-2.0 research-use terms => concepts only unless legal permission established. LUNAR/LILAC research code => do not reuse unless LICENSE independently verified.
- **Cross-branch conflicts:** current PR #2/PR #7 both modify roadmap docs; when integrating preserve the latest real implementation evidence, this explicit owner priority and existing security/owner release gates. Do not replace a whole document blindly at merge.

## 6. Immediate NEXT_ACTION (both independent development chats)

Finish only a currently *already-running* atomic test/fix/commit without discarding work, then **P0-AP1 first**. UI: inspect existing `detectFormat`, family detection/coverage and `GuidedBuilder`; RED reproduce RFC3164+KV and Syslog-prefixed CEF as browser failures, add explainable candidate/unsupported result and agreed contract. Backend: inspect existing `ParserProject`, `validate`, `compiler` and native fixture runner; define supported envelope/body contract and RED fixture tests for those same cases, then add genuinely supported codecs. Both lanes continue P0-AP2 → AP3 → AP4 in priority order; P1 begins only when deterministic P0 is implemented/tested or genuinely gated. Commit/push tested work to independent branches and verify exact-head CI or explicitly record unavailable CI.

**Do not repeat the market/GitHub research or previous completed revision history/mocks/test lab features.**
