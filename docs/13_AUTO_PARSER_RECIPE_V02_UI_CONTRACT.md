# Auto Parser v2.0 — Reviewed staged contract and restricted backend compilation

Status of each generated recipe: **REVIEW_ONLY**. Source of truth: `src/guided/parserRecipeV2.ts` and its runtime validator. `parserRecipeDraft.ts` only re-exports that same contract. A separately checked backend capability can compile **only the strict v0.1-equivalent staged subset** into real matched DRAFT files; the recipe alone is not evidence of native user-parser or Stellar target qualification.

## Typed review result

- `contract = parser-studio.recipe.v0.2`, `schemaRevision = 0.2`, `compilerMode = REVIEW_ONLY`.
- `projectId` and exact `sourceFormat` + `bodyFormat`; `sample` contains only a SHA-256 digest and event count, never raw event text.
- Strict ordered `stages`: `split_event`, optional `unwrap_syslog`, one `parse_json|parse_kv|parse_csv|parse_cef|parse_leef`, bounded `map_field` with an adjacent type cast when needed, exactly one `classify`, and a final `fallback_unparsed`.
- All unknown operators, prototype-path segments, duplicate mapping destinations, misplaced casts, forged native/target PASS flags, mismatched body parsers, malformed shapes and source/sample mismatches fail closed.
- `legacyProject` is returned **separately** as the unchanged typed ParserProject v0.1 projection. `V01_SNAPSHOT_PRESERVED` and `lossyOperations: 0` refer **only to this parallel snapshot**, not v0.2 compiler/native semantic equivalence. Project enrichment/receiver semantics are not silently inferred as supported staged operations.
- `nativeVerified`, `targetVerified`, `nativeUserParserVerified` and `targetImportVerified` are **always false** in recipe and receipt. Initial local `v02CompilerAvailable=false` means **not yet negotiated**: an explicit separate request can establish a limited v0.2 backend capability, not native readiness.

## UI and API boundaries

- Beginner default remains **Add Logs → Review Results → Test & Generate**, with the existing Edit Details and Expert routes unchanged.
- v0.2 metadata is shown by the advanced **Review Staged Recipe** action; it is built locally from the exact browser suite and invalidated by source edits. Nothing is posted until the user explicitly selects **Validate and Compile Strict v0.2 DRAFT Pair** after generating the independently validated v0.1 pair.
- Existing v0.1 `validate`/`generate` remain unchanged. The separately pinned backend `f176e6a` exposes `/api/v1/parser-pairs/recipe/v0.2/{capabilities,validate,generate}`. Only the reviewed `{recipe, legacyProject}` pair is transmitted (no raw events). The backend verifies exact mapping/cast/classification equivalence, and the browser independently hashes the recipe, legacy project, returned Ruby+CONF, compiler receipt and file contents, requiring a byte-identical match to the previously generated v0.1 pair. Older backends fail closed without affecting v0.1 downloads.
- Native Fluentd, actual Stellar loader, authenticated DP Apply, approved sensor send, tenant Interflow and two-user E2E remain distinct, independently gated verification claims.

## Backend owner contract handoff (PR #4)

The backend provides a strict JSON Schema, versioned allowlisted capabilities, exact v0.1 metadata equivalence and seven native PUBLIC SYNTHETIC Fluentd/CONF fixtures. This is **not** a general staged engine. The pinned backend now supports a strict RFC3164 TAG/body subset with unknown year/zone. Future native backend work must add broader RFC3164 variants, mixed-family branching, logical multiline support and broaden the independently native-qualified operators before advertising these as supported. Unknown/non-equivalent AI stages must never compile by optimistic coercion.

## Current verification

- Focused source digest, v0.1 preservation, stage order, body-family, native-false, tampered metadata, unsafe field and source-mismatch unit tests: `src/guided/parserRecipeV2.test.ts`, `src/guided/parserRecipeDraft.test.ts`.
- Real Chromium backed by pinned loopback backend tests the advanced review disclosure, no leaked raw addresses and existing generation/download integrity in `tests/integrated-backend.spec.ts`.
- `recipeV2BackendClient.test.ts` verifies capability negotiation, exact receipt/source identity/hash, default-false native/target claims and tampered responses. The exact pinned-backend Chromium scenario also validates the real restricted v0.2 route; backend PR #4 owns the **separate** seven-profile pinned native Fluentd synthetic evidence. None is a customer parser or actual DP/Interflow test.

## RFC3164 bounded UI/backend support

The public-synthetic RFC3164+KV beginner path and the strict RFC3164 CEF/LEEF envelopes can now be reviewed with an explicit, verified backend capability; the browser preserves the YEAR_AND_ZONE_UNKNOWN header policy and prohibits treating that header as a timezone-qualified date. User-provided event bodies are not POSTed to the versioned compiler. The same sensor destination and CONF receiver port must be >=6800. UI pinned backend commit: fd1af8010c9611214d69eb58c3b005af2e093cea. Vendor deployment remains NOT VERIFIED.
