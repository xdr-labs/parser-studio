# 10 — No-code Guided Builder ↔ Backend R1.5 Integration

**UI lane:** Draft PR #3 plus independent `feat/r2-guided-backend-api-bridge` stacked branch. **Backend lane:** independent Draft PR #4 (`e7455e3`), owned by the other session. **Roadmap:** Issue #1; canonical no-code design: docs PR #2.

## 1. What exists and what does not

- Default Guided Builder has six steps: input logs → extraction → typed mapping → receiver/classification → test/fix → generate. Original 3-pane Expert Workbench remains available and shares a version-neutral rule draft.
- The UI uses a **same-origin development proxy** for the separate backend's `POST /api/v1/parser-pairs/validate` and `POST /api/v1/parser-pairs/generate` endpoints. Backend binds `127.0.0.1:4179` only.
- The user explicitly clicks **백엔드 입력 검사**, runs the current browser suite, and then explicitly requests **DRAFT pair generation**. Nothing sends customer raw sample text when typing, moving steps or performing browser-only preview.
- The currently supported backend output is `customized_<slug>.conf` + extensionless `customized_<slug>` Ruby fragment. It is a **host-reference DRAFT**, not a vendor portal `.json`, installed Fluentd plugin, or proven Stellar import format.
- **No native Fluentd/plugin validation, active-target import verification, production installation, deployment, or credential changes** have been performed. Both DRAFT downloads clearly retain that boundary.

## 2. Actual API contract and zero-loss translation

Source files: `src/guided/contract.ts` (legacy UI authoring), `src/guided/backendAdapter.ts` (strict translation), `src/guided/backendClient.ts` (loopback same-origin API), `src/guided/GuidedBuilder.tsx` (explicit user interaction). PR #4 backend schema and its README remain authoritative for the server.

Backend project `0.1` is a **different wire shape** from the old `PairProjectContract` UI JSON. `toBackendProject(draft)` adds the required `projectId`, `revision`, `sourceCategory`, `msgOriginSource`, `msgClass`, `msgOriginCategory`, and `ignoreValues`. It converts receiver `bindPolicy`→`bindAddress`, `messageLimit`→`messageLengthLimit`, `framing`→`tcpFraming`, and authoring `input.format`→`extraction.format`.

Source/target mapping lists are converted to backend `topFields`, `nsFields`, `vendorFields` source-keyed maps with typed `normalized_name` metadata. The UI `timestamp` type becomes a backend `date` rule with explicit `iso8601` and `UTC`. Object-prototype paths, invalid source identifiers, duplicate source map entries, ambiguous target destinations, and unsupported casts must **fail closed**, never disappear silently.

The backend's classification rules address **normalized top/namespace fields**, not raw source fields. UI `sourceField=action` is translated to its mapped output `custom.action`, and category `Threat`/`Session`/`Syslog`/`Winlogevent` becomes lowercase. Classification references confined to vendor-only groups are reported as unsupported until the backend explicitly supports them. Default `action` now belongs to `top_fields` for the backend-supported subset.

Backend DRAFT authoring now accepts explicit JSON, KV, comma CSV, bounded RFC5424 (raw body), standalone CEF and LEEF only when GET /capabilities confirms that format. The browser's format-specific checks remain an approximation, not the pinned native Fluentd golden fixture test. Generic Syslog, Regex, multiline, Syslog-prefixed CEF and arbitrary LEEF extensions remain blocked; no raw samples are sent to validate/generate requests.

## 3. Safety, test evidence and download qualification

- Backend schema validation is HTTP 200/422 with per-field `{code,path,message}` diagnostics. Missing/contradictory API responses and unreachable backend keep Generate disabled.
- DRAFT generation is available only with **the same draft and sample key**, an explicit current browser test with every event matched/normalized and zero failures, and a successful backend validation. Editing rules or samples invalidates the evidence and hides stale downloads.
- The returned payload must have exactly two filenames derived from the safe slug, correct UTF-8 byte counts, correct SHA-256 hashes of **both contents**, matching manifest hashes, status `DRAFT`, contract `host-customized-pair.v0.1`, and explicit `engineVerified=false`/`targetImportVerified=false`. Any mismatch blocks download.
- Each artifact download requires a separate user click. It is an unverified host-reference Ruby fragment and `.conf`, not an instruction to modify `rickmodular` or deploy to a running Stellar platform.
- The development proxy is **loopback only**. The backend has no multi-user authentication; never expose it publicly. Production/multiuser use requires a separate authenticated/authorized API design.

## 4. Verification matrix and test instructions

- `src/guided/backendAdapter.test.ts`: safe schema translation, normalization grouping, class references, unsupported operators and security.
- `src/guided/backendClient.test.ts`: HTTP 200/422, refusal of malformed manifests or tampered SHA-256, exact two-file pair, no raw log in requests.
- `tests/backend-bridge.spec.ts`: browser mock positive/negative cases plus an opt-in live backend test. Set `PARSER_STUDIO_LIVE_BACKEND=1` only while an isolated backend PR #4 service is running on `127.0.0.1:4179`.
- Normal CI uses mocked browser API cases; the live test is skipped without opt-in. Local exact-HEAD integration is recorded in PR evidence and must never be called native Fluentd qualification.

### Actual dev-atlas proof (2026-10-12)

- Backend PR #4 SHA `e7455e3c95f914555bc636b088df5d919200c8a2` was cloned to an isolated **unchanged** directory; Node check, 8 tests, and build passed.
- The separate Web UI integration candidate passed **39/39 Vitest**, TypeScript/Vite build, and the **four backend-bridge Chromium scenarios with a real loopback backend** (including live two-file download, SHA-256 verification, corrupted response refusal and privacy check). Overall browser regression and exact new PR CI are to be recorded from their own executions.

## 5. Handoff / remaining priority

Keep the current PRs and worktrees isolated: PR #3 Guided Builder, PR #5 field-highlighting UX, PR #6 multiline **preview only**, PR #4 independent backend. Integrate them only after reconciling schema/capability contracts. Next UI work: usability/regression and safe multi-variant workflow. Backend owns Ruby compiler, native Fluentd runner, plugin/wrapper semantics, proprietary portal adapter and actual target qualification.

No production writes, live td-agent reloads, credentials/permissions changes, or unverified success claims.
**UI addition (2026-10-12):** field proposal review highlights the selected source token and structural capture positions in up to 20 sample events, including unmatched variants. The browser Web Worker remains authoritative for full-sample denominators. Highlighting is not native runtime evidence. See `src/guided/fieldHighlights.ts`, `src/guided/fieldHighlights.test.ts` and `tests/guided.spec.ts`.

**Next UI-only backlog:** deeper field dictionary/schema guidance, exact browser/native parity evidence for unusual format variants, accessible correction workflows, saved revisions and same-HEAD full user E2E. Explicit RFC5424, standalone CEF/LEEF, safe enrichment, field validation recovery, comma CSV and preview-only multiline are implemented, not Stellar target verified.

**Do not work on** Ruby fragment templates, native td-agent/Fluentd runner, IR schema/compiler implementation or deployment from this UI lane. The separate backend session owns those deliverables.

### 2026-10-12 — Opt-in legacy pair inspection

The Step 6 advanced inspector accepts a matching customized_<slug>.conf plus extensionless customized_<slug> pair. File selection alone performs no upload or persistence. On explicit user action, the client validates names, size and strict UTF-8, verifies server-advertised read-only inspection support, then POSTs the pair through the loopback same-origin API. The local client cross-checks SHA-256 of both original files, rejects inconsistent editable flags and unrecognized diagnostics, and displays **code-only** structural observations without original Ruby/CONF bodies or server-supplied diagnostic messages.

EDITABLE_EXACT means a byte-identical internal generator output; it does NOT import the IR into the current Guided editor or prove Stellar Cyber target compatibility. Unknown Ruby stays OPAQUE_READ_ONLY. No Ruby execution or host loader changes are requested. Unit tests cover hashing, opaque status, tampering, invalid filenames and oversized inputs; browser checks cover explicit submission and no raw source in results.

### 2026-10-12 — Synthetic, no-code starter templates (R4)

The Step 1 starter selector offers six **entirely synthetic** fixtures: JSON, KV, comma CSV, bounded RFC5424, standalone CEF and standalone LEEF. Selecting a template does nothing by itself; a separate **Apply synthetic example** click explicitly replaces the current draft rules and in-session sample. The UI describes the replacement before the click and resets stale backend validation/generation evidence. Each fresh template includes ordered sample events, matching extraction format, safe source/target mapping, classification defaults and source group metadata. RFC5424 uses header fields and an explicit Syslog fallback; other families use the reviewed action/IP/port demo mapping. No raw customer logs, proprietary example bodies or third-party network calls are bundled. Templates are onboarding aids **not** vendor/native compatibility evidence, saved customer state, deployed parser presets or verified Stellar target imports. Deterministic fixture tests cover the six families and their backend DRAFT IR mapping; Browser E2E covers user-initiated selection and unverified export locks.

### 2026-10-12 — Keyboard focus after validation recovery

Step changes triggered by the six-stage navigation, sample inspector, or backend field-error correction now programmatically focus the destination stage heading **only when the step actually changes**, not on the first render. The heading is programmatically focusable via tabIndex=-1 and the browser E2E recovery scenario verifies the keyboard focus is not lost when the original correction button unmounts. This is a UI accessibility check, not user acceptance of native parser behavior.

### 2026-10-12 — Conservative bulk mapping for nondevelopers

The Guided mapping stage offers an explicit one-click suggestion for up to 50 safe **unmapped source field names** seen across the current local browser sample events. Only field identifiers are inspected; sample **values are never copied into mapping rules** or sent to any endpoint. Candidate names with invalid syntax or prototype-related segments are excluded; destination collisions with existing mappings are skipped. Suggested output targets use the independent `custom.<source_name>` namespace and default to the conservative **string** type (not an unverified official Interflow dictionary). Fields referenced by existing no-code classification rules use a routable top-level group; all other candidates remain vendor-specific. Existing mappings are preserved; no action occurs without clicking. Each suggestion is still user-editable and must pass the same compiler contract, local sample regression and explicit backend validation as a manual mapping.

### 2026-10-12 — Live v0.1 backend authoring schema guidance (R2/R4)

The Guided field-mapping step now has a collapsed, explicit **GET /api/v1/parser-pairs/schema** control. This is for the current loopback backend's ParserProject JSON Schema, **not** an official Stellar Cyber Interflow field dictionary or evidence of actual target loader acceptance. The client checks the exact schema ID/revision, reviewed format/type/category/protocol subsets, fixed identifier grammar, and safe size/port bounds before showing a reduced static guidance summary. It never executes schema-provided regex, renders arbitrary untrusted schema description strings, or sends raw event or mapping values in the request. Unsupported/newer or contradictory schema structures fail closed and show an error instead of verified labels. Backend validate/generate remain independently capability-gated and unchanged; merely opening this guidance never enables exports.

Tests: `src/guided/backendSchemaGuide.test.ts` covers normal and fail-closed shapes; `tests/backend-schema-guide.spec.ts` covers opt-in same-origin GET, visible supported types and bad revision handling. The UI implementation is `src/guided/backendSchemaGuide.ts` plus Step 3 of `src/guided/GuidedBuilder.tsx`. Isolated real backend GET /schema with head 2945c06 verified 6 extraction formats, 6 normalized field types, 128-character identifier limit and bounded receiver port. No native/production verification is implied.

### 2026-10-12 — Field-path preflight alignment

The local Guided contract now rejects malformed dotted field paths (including repeated/trailing periods), unsafe prototype/constructor segments, reserved system-managed output roots and overlapping parent/child destination names **before** presenting a UI validation success or contacting the backend. The accepted name syntax is a conservative subset of the reviewed ParserProject 0.1 schema; backend `/validate` remains authoritative for final compilation, and the UI does not claim an official Interflow field dictionary. The unsupported floating-point `number` conversion remains possible in Expert browser-only preview but is disabled in the Guided export editor. RED→GREEN unit tests in `contract-field-paths.test.ts` and negative Chromium tests in `field-path-validation.spec.ts` protect against ambiguous output and unsafe export.

### 2026-10-12 — Nested JSON field parity and safe path suggestions

The browser's local source lookup now follows the reviewed backend dotted-field convention: check a literal flat key first, then traverse own properties of nested JSON objects using a bounded, safe path. It never follows inherited object keys, `__proto__`, `constructor`, array indices or unreviewed source syntax. Nondeveloper field suggestions and the Step 2 extracted-field name chips/datalist now display safe scalar **leaf paths**, such as `http.request.method`, rather than suggesting a parent object that cannot be mapped consistently. Candidate names are derived from local sample structure only; values stay in the browser. This prevents misleading local normalization failures on valid nested JSON rules and never implies a proprietary parser has accepted the event. Browser regression: `tests/nested-json-mapping.spec.ts`; unit tests: `src/nestedMapping.test.ts` and `src/guided/nestedSuggestions.test.ts`. The selector-only CI failure on option-disabled status in `tests/field-path-validation.spec.ts` was corrected to assert the actual disabled HTML attribute without weakening the no-code export block.

### 2026-10-12 — Field-by-field local sample diagnostics

Each Guided field mapping card now shows sample count, source-field presence, successful browser normalization count, missing field count and typed-conversion failure count. All evidence is local, derived from the existing browser preview output and contains **no original log values**. A user can jump directly to the first problematic sample to correct the extraction mapping without leaving the six-step no-code flow. Nested dotted JSON fields are looked up with the same guarded local traversal as their normalized mapping. The indicator explicitly says browser-preview only and never upgrades an unverified native/Stellar status. `src/guided/mappingCoverage.ts` has deterministic positive/missing/type-failure unit tests, and `tests/mapping-coverage.spec.ts` exercises the visual error-to-sample journey.

### 2026-10-12 — Conservative, opt-in type recommendation from local events

The Guided field-mapping card can recommend a data type only after **at least two nonempty, consistent local sample values**. Supported suggestions are IPv4, port (port-named sources), explicit true/false boolean, timezone-bearing ISO timestamp and integer for clearly count/size-named sources. Ambiguous numeric IDs, `0/1` booleans, mixed or missing values and unsupported IPv6 structures are never automatically promoted. User must click **Apply suggested type** for a specific field; the recommendation itself never changes saved rules or sends log values to a backend or AI service. The displayed evidence consists of the type and event counts, **not source values**, and explicitly remains browser-preview/heuristic guidance rather than an official Interflow dictionary or native Fluentd acceptance. `src/guided/typeSuggestions.ts` supplies the safe projections and `tests/type-suggestions.spec.ts` exercises the opt-in browser path.

### 2026-10-12 — Public Standard Metadata Dictionary reference (curated facts, no target guarantee)

Public Stellar Cyber documentation at https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm contains actual standard metadata field names, types and descriptions, and the Parser Studio 7.0 Normalization workflow explicitly points to the Metadata Dictionary. The Guided mapping editor now exposes a **small curated list of 19 scalar entries** with a direct source link, not a copied entire dictionary or an unverified version-independent schema. All field-name/type pairs are factual, from public 7.0 documentation; the summary labels are concise. UI supports only types reviewed by our own backend IR. For example, `srcip` is documented as IP, while `dstport` is documented as integer but the local backend's narrower `port` cast is used to validate port ranges. Object/list/float fields and system-managed reserved paths are omitted.

Selecting a candidate for an existing field mapping is a **manual explicit action**. It adjusts only the corresponding normalized target, type and top_fields group; validates against duplicate/overlapping targets and never changes source values or sends samples anywhere. Actual availability on older or different Stellar Cyber versions, the host-reference .conf/Ruby loader, per-tenant metadata behavior and target import status remain separately unverified. Browser test `tests/official-metadata.spec.ts`, unit test `src/guided/officialMetadata.test.ts`.

### 2026-10-12 — Two published metadata dictionary versions cross-check

The curated list of scalar standard metadata names/types has been compared against **both** the official [6.5 Standard Metadata Dictionary](https://docs.stellarcyber.ai/6.5.xs/Common/Metadata-Dictionary.htm) and [7.0 Standard Metadata Dictionary](https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm). The no-code field selector links to both source documents and refines event/host/process labels where the published meaning is context-specific. This public reference is **not** target-release compatibility, confirmation that a customer tenant accepts these fields, or permission to overwrite reserved metadata. Existing manual collision handling and DRAFT-only export gates remain unchanged.
