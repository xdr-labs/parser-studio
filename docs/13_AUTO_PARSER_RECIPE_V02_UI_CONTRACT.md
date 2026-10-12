# Auto Parser v2.0 — UI-owned ParserRecipe v0.2 review contract

Status: **REVIEW_ONLY**. Source of truth: `src/guided/parserRecipeV2.ts` and its runtime validator. `parserRecipeDraft.ts` is only an import compatibility shim and does not define a competing recipe or compiler. This is an additive UI-side adapter, **not** a backend v0.2 schema, native parser compiler, or Stellar Cyber import proof.

## Typed review result

- `contract = parser-studio.recipe.v0.2`, `schemaRevision = 0.2`, `compilerMode = REVIEW_ONLY`.
- `projectId` and exact `sourceFormat` + `bodyFormat`; `sample` contains only a SHA-256 digest and event count, never raw event text.
- Strict ordered `stages`: `split_event`, optional `unwrap_syslog`, one `parse_json|parse_kv|parse_csv|parse_cef|parse_leef`, bounded `map_field` with an adjacent type cast when needed, exactly one `classify`, and a final `fallback_unparsed`.
- All unknown operators, prototype-path segments, duplicate mapping destinations, misplaced casts, forged native/target PASS flags, mismatched body parsers, malformed shapes and source/sample mismatches fail closed.
- `legacyProject` is returned **separately** as the unchanged typed ParserProject v0.1 projection. `V01_SNAPSHOT_PRESERVED` and `lossyOperations: 0` refer **only to this parallel snapshot**, not v0.2 compiler/native semantic equivalence. Project enrichment/receiver semantics are not silently inferred as supported staged operations.
- `nativeVerified`, `targetVerified`, `v02CompilerAvailable`, `nativeUserParserVerified` and `targetImportVerified` are **always false** in this UI contract.

## UI and API boundaries

- Beginner default remains **Add Logs → Review Results → Test & Generate**, with the existing Edit Details and Expert routes unchanged.
- v0.2 metadata is available only by opening the advanced disclosure and selecting **Review Staged Recipe**. It is computed locally from the exact browser suite; source edits invalidate it. It is not transmitted, persisted, executed or presented as a downloadable native parser.
- The current pinned backend advertises ParserProject **v0.1**. Existing real backend `validate` and `generate` continue to consume the original v0.1 model and produce a SHA-verified DRAFT Ruby + CONF pair. They **never** receive or compile the v0.2 review recipe.
- Native Fluentd, actual Stellar loader, authenticated DP Apply, approved sensor send, tenant Interflow and two-user E2E remain distinct, independently gated verification claims.

## Backend owner contract handoff (PR #4)

Before promoting any staged operation to compiler-ready, publish and validate a jointly reviewed JSON Schema v0.2 and a versioned capabilities endpoint with an explicit per-operator/family matrix. Implement deterministic compound Ruby/CONF emission and no-loss v0.1 migration only for native-qualified stages. Pin Fluentd fixtures for compound RFC5424/CEF/LEEF, mixed families, casting, classification and all-event fallback. Fail with stable codes when unsupported. Reconcile the typed staged review contract with that backend schema before permitting v0.2 generation. **Do not infer support from the presence of these UI types.**

## Current verification

- Focused source digest, v0.1 preservation, stage order, body-family, native-false, tampered metadata, unsafe field and source-mismatch unit tests: `src/guided/parserRecipeV2.test.ts`, `src/guided/parserRecipeDraft.test.ts`.
- Real Chromium backed by pinned loopback backend tests the advanced review disclosure, no leaked raw addresses and existing generation/download integrity in `tests/integrated-backend.spec.ts`.
- These tests are UI contract/evidence tests, **not** a v0.2 Ruby/Fluentd execution test.
