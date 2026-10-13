# P1-AP6 — Explicit, offline AI prompt and review-only Recipe import

## Implemented

- The prompt remains available for **untouched novice auto mode and unknown/unsupported logs**. When the current draft cannot translate to ParserProject v0.1, the metadata explicitly marks its project identity unresolved and asks the external assistant for plain-English diagnosis and manually reviewed redacted examples, not a falsely import-ready parser.
- The advanced optional panel appears without interrupting the default three-step Auto Parser flow. **Prepare Privacy-Safe AI Prompt** constructs a local text draft containing fixed schema expectations, a SHA-256 sample digest, bounded event counts, supported envelope/body names and an explicit rejection of unsupported/ambiguous parsing. **No sample lines, observed field values or mapping paths are included in the generated prompt.** The user can preview the complete text before taking the separate **Copy Prompt Manually** action. There is no outbound API call, provider integration, telemetry, or background upload.
- **Paste AI Recipe** accepts an explicit JSON document of no more than 32 KiB. The locally enforced v0.2 staged typed contract requires exact root and per-stage keys, allowlisted ordered operators, bounded paths and classification rules, `REVIEW_ONLY`, and `nativeVerified=false`/`targetVerified=false`. It must match the local source SHA-256, count, current reviewed ParserProject identity, envelope and body format. Unknown source, forged native claims, Ruby execution, arbitrary transforms, mismatched format and malformed JSON fail closed with fixed error codes.
- Successful import creates a **read-only proposal summary** showing only counts of stage/mapping differences. It never modifies accepted rules, posts the recipe to the v0.1 backend, compiles Ruby, or reports native/DP readiness. If the proposal adds **exactly one** source-present, allowlisted map_field while preserving every existing mapping, family and classification, the user can invoke a bounded v0.1 *candidate* comparison against the full original sample and independent holdout. The candidate still needs the separate AP4 **Approve Reviewed Mapping** action; no unsupported v0.2 operator is executed or silently converted. Unsupported proposals remain review-only.

## Supported integration boundary

The backend now supports **only** the separately capability-negotiated v0.2 staged subset exactly equivalent to an already-validated ParserProject v0.1; it does not execute arbitrary pasted AI recipes. `parserRecipeV2.ts` remains the canonical UI review-only contract. AI-imported stages still require the explicit safe one-field candidate + full-sample/holdout approval flow, and only the verified UI-origin recipe can request a restricted v0.2 DRAFT pair. Do not interpret AI-import PASS as arbitrary compound execution or actual sensor readiness.

Only a narrow JSONata-compatible path subset (`$.event.field` or `event.field`, maximum eight safe segments) is recognized as a candidate property lookup. It performs no JSONata evaluation, only existing safe field-path lookup, and proceeds through the same independent-holdout AP4 approval gate before any mapping changes. Arbitrary expressions/functions/filters/array indexing are rejected.

An integrated LLM provider, token/cost controls, default redaction/consent preview and broader JSONata engine are **not enabled**. User intent and privacy must be explicit before any external transfer; this is a local copy/paste workflow.

## Tests

`aiRecipeExchange.test.ts` validates strict source identity, private value exclusion, fixed success gates and rejection of unknown operators, extra keys, forged verification and oversized inputs. No E2E acceptance is claimed by these unit tests.


## Optional integrated provider interface (P1-AP6)

Manual Copy AI Prompt / Paste AI Recipe remains the default and is never disabled. A separate integrated provider path now exists as an optional, **server-authorized metadata-only candidate generator**, not a customer log upload or arbitrary provider proxy. It requires a privacy-safe prompt for a currently backend-compatible draft and begins with a data-free capability GET. Only after a successful strict response does the UI expose two separately unchecked approvals: metadata-only external provider transfer and the server-advertised output-token reservation (32–1024 tokens). Browser source/draft edits invalidate approvals.

On explicit action the UI recomputes the current browser source SHA-256 and event-family/count census. It posts ONLY enumerated project ID, SHA-256, count, format/census and both approvals to the same-origin private backend. Raw event bytes, IP addresses, usernames, field values, customer API keys, custom prompts and dynamic provider URLs never enter the request. The server rebuilds a fixed prompt and requires a trusted provider adapter, durable/atomic per-actor budget reservation and metadata-only BEFORE/AFTER audit. No provider is installed, configured or contacted in normal backend startup; both endpoints are disabled by default. Token count is a cap/reservation, **not a price quote**.

A provider candidate must pass the v0.2 REVIEW_ONLY schema, source digest/count/project identity, allowed format, capped token usage and native/target false flags before the UI displays it. A separate button copies the candidate into the local paste field; the user must separately validate, compare full sample and independent holdout, and approve at most one safe mapping as before. There is no auto-install, arbitrary Ruby/Regex execution, actual DP Apply or sensor delivery. Source-independent provider claims are never accepted as native/target verification.

Backend exact-head implementation: f865f724703aaa309a81e2cb7c0e35e41cf7d8c8, backend/docs/ai-review-gateway.md. UI client: src/guided/aiIntegratedClient.ts. Tests: src/guided/aiIntegratedClient.test.ts and tests/ai-integrated-review.spec.ts. Real provider activation, tenant access and cumulative cross-restart billing require separate operator approval/provisioning. This synthetic integration does not claim any real provider call or human usability benefit.
