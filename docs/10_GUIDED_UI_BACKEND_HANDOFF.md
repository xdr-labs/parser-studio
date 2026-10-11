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

Only explicit `json` or `kv` extraction can be handed to this backend version. Advanced regex/CSV/Syslog preview still works locally but must not be mislabeled supported by the R1.5 pair renderer. Neither sample text nor browser run outputs are part of the API JSON.

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
