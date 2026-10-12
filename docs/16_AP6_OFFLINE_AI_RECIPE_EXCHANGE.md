# P1-AP6 — Explicit, offline AI prompt and review-only Recipe import

## Implemented

- The advanced optional panel appears without interrupting the default three-step Auto Parser flow. **Prepare Privacy-Safe AI Prompt** constructs a local text draft containing fixed schema expectations, a SHA-256 sample digest, bounded event counts, supported envelope/body names and an explicit rejection of unsupported/ambiguous parsing. **No sample lines, observed field values or mapping paths are included in the generated prompt.** The user can preview the complete text before taking the separate **Copy Prompt Manually** action. There is no outbound API call, provider integration, telemetry, or background upload.
- **Paste AI Recipe** accepts an explicit JSON document of no more than 32 KiB. The locally enforced v0.2 staged typed contract requires exact root and per-stage keys, allowlisted ordered operators, bounded paths and classification rules, `REVIEW_ONLY`, and `nativeVerified=false`/`targetVerified=false`. It must match the local source SHA-256, count, current reviewed ParserProject identity, envelope and body format. Unknown source, forged native claims, Ruby execution, arbitrary transforms, mismatched format and malformed JSON fail closed with fixed error codes.
- Successful import creates a **read-only proposal summary** showing only counts of stage/mapping differences. It never modifies accepted rules, posts the recipe to the v0.1 backend, compiles Ruby, or reports native/DP readiness. If the proposal adds **exactly one** source-present, allowlisted map_field while preserving every existing mapping, family and classification, the user can invoke a bounded v0.1 *candidate* comparison against the full original sample and independent holdout. The candidate still needs the separate AP4 **Approve Reviewed Mapping** action; no unsupported v0.2 operator is executed or silently converted. Unsupported proposals remain review-only.

## Supported integration boundary

The current backend supports only ParserProject v0.1 for actual DRAFT pair generation. `parserRecipeV2.ts` remains the canonical UI review-only contract. Formal v0.2 backend JSON Schema, compound operator compiler and native qualification must be jointly reviewed with backend Draft PR #4 before any AI-proposed staged recipe becomes executable. Do not interpret an AI-import PASS as compilation or actual sensor readiness.

Only a narrow JSONata-compatible path subset (`$.event.field` or `event.field`, maximum eight safe segments) is recognized as a candidate property lookup. It performs no JSONata evaluation, only existing safe field-path lookup, and proceeds through the same independent-holdout AP4 approval gate before any mapping changes. Arbitrary expressions/functions/filters/array indexing are rejected.

An integrated LLM provider, token/cost controls, default redaction/consent preview and broader JSONata engine are **not enabled**. User intent and privacy must be explicit before any external transfer; this is a local copy/paste workflow.

## Tests

`aiRecipeExchange.test.ts` validates strict source identity, private value exclusion, fixed success gates and rejection of unknown operators, extra keys, forged verification and oversized inputs. No E2E acceptance is claimed by these unit tests.
