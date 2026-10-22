# Parser Studio — final integrated-engine audit and assisted multi-type follow-up (2026-10-21)

## Scope and reproducible baseline

- Base repository: `xdr-labs/parser-studio`, integrated `main` `938cffc75c5ebb5500d5065a6befbbfd43203490`.
- Preserve existing accepted source/native compiler and actual development E2E receipt (Issue #1 comment 6312166024). This follow-up does **not** reclassify historical research evidence as new accuracy.
- Eight historical JSON/KV/Stellar normalization corrections were confirmed as **ancestors** of the current main: `637dd2a`, `89c4295`, `3fe42d3`, `d465593`, `a0e3f55`, `b53c82f`, `f083e2e`, `5889afb`. No duplicate cherry-pick was necessary.
- Real mainline call path (not orphaned PoC): `AutoParser.tsx` → `requestMultiPassBatchPreview` → `multipass_preview_api.py` → `security_framing.parse_security_batch` with `parse_security_multipass` and `bounded_funnel`. Normalization and native compilation are separate downstream gates.

## What is integrated, and what is not proved

- Current source/parser regressions cover JSON and nested/duplicate-key safety, CSV quoting and explicit columns, CEF and LEEF escapes, RFC3164/RFC5424 Syslog framing/structured data, KV duplicate/source accounting, W3C/Zeek, and representative container/stream framing. Standard-family recognition or source-preserving PARTIAL does **not** imply every wire framing has an equivalent downloadable Fluentd DRAFT.
- General-purpose Multi-Pass and Generic Structural stages remain in the application execution chain. The product separately exposes `SOURCE_PARSED`, `PARTIAL`, `RAW_ONLY` and residuals; it does not blindly count unrecognized records as parsed.
- Stellar Cyber mapping is fixed to the official **7.0** dictionary. Ambiguous suggestions need review; invalid official scalar values fail closed, including conditional Ruby output. No 6.5/6.6 selection was introduced.
- The generated Ruby remains a reviewed **editor fragment**, not a standalone, registered `parser_customized_*.rb` drop-in; generated CONF topology/final Syslog inverted fallback was previously compared with four read-only installed target examples. No DP, sensor, real vendor target import, or full vendor semantic oracle is asserted.

## New product behavior in this follow-up

1. ChatGPT Assisted Parser accepts optional **solution vendor, product, version/model and log delivery context**, carried into the manually reviewed prompt as JSON **user-declared hints**; producer names are not parser correctness evidence.
2. The same named-log-type editor used in Auto Parser is available in ChatGPT Assisted. Original per-type events are combined without rewriting bytes; 2–10 nonempty, distinct groups are required.
3. Each type has a separate synthetic-default, manually editable **redacted sharing example**. Only the reviewed examples are inserted in the copyable ChatGPT prompt. Original local event values are not automatically included or sent to a third party.
4. Existing `ReviewedEventProfilesPanel` is reused for explicit discriminator, type-specific mappings, unknown-type rejection, capability gating and approval. Unsafe or incompatible grammar combinations remain review-only.
5. New independent group acceptance tests every original group with the candidate browser parser, checks complete normalized coverage and disjoint verified routing identities, and **blocks combined file generation** without reviewed conditional or supported mixed-format routing. No group label is silently treated as an event discriminator.
6. Solution context and redacted sharing examples survive Auto ↔ ChatGPT workspace switches in the browser session; new projects or local-version restores reset the shareable examples.
7. Actual conditional compiler boundary reproduced and corrected: `backend/src/parser-recipe-v02.ts::legacyAllowed` explicitly rejects `normalization.eventProfiles`; sending a reviewed conditional DRAFT through v0.2 caused a real browser generation failure. For conditional event profiles, ChatGPT Assisted now uses the **existing capability-checked, schema-validated, integrity-verified v0.1 conditional Backend pair** after separate original-group checks. Only non-conditional recipes call the strict v0.2 equivalent-subset compiler; no false v0.2 parity claim is made.
8. The shared `main` already integrates the canonical XDR Labs Parser Studio favicon assets (`favicon.svg`, ICO, 16/32/48px PNG, 180px Apple touch and 192px icon) and a standard-library asset test. This branch preserves the newer canonical favicon without adding redundant icon sets or duplicate HTML links.

## Focused acceptance at implementation

- Frontend suite: **145 files / 1,131 tests passed** (new helper and UI tests included).
- TypeScript + Vite production build: **PASS** (normal bundle size warning; no build error).
- First genuine isolated Chromium new-feature test: **1/1 PASS**, including user-entered source context, two named log groups, privacy-safe prompt, workspace continuity and actual SVG HTTP response.
- SVG parser validation: **PASS**. The 32px and 180px PNG raster fallbacks have correct PNG signature.
- Previous exact source main CI and public-browser acceptance must not be counted as acceptance for this new source revision. This new revision requires its own exact-HEAD CI and development deployment / public Chromium checks.

## Decision and non-gating limitations

**Engine decision:** No new reproducible, cross-vendor general grammar defect has been established from this evidence. Preserve the qualified engine rather than add speculative manufacturer-specific regular expressions. Reopen common grammar work only if new reproducible logs show silent record/field loss, false parsed/native readiness, a shared standards defect across sources, or a blocked novice path for an otherwise qualified DRAFT.

Not verified: arbitrary multi-format/native target import, manufacturer/firmware-wide semantic accuracy, raw wire transport output, any proprietary Stellar importer, DP/sensor operations, and mobile coverage. Unsupported mixtures remain visibly blocked or review-only; the prompt alone is not a compiled parser.

## 2026-10-22 isolated consolidation check

Two parallel work packets were independently present and preserved: Draft PR #137 (source head `3d562588b`, exact-head CI #39620864434 SUCCESS) and Draft PR #138 (source head `98d072b`, local frontend 1,131/1,131 PASS and three-family conditional source Chromium PASS). Instead of attempting two overlapping merges, the final isolated integration branch carries both histories and resolves conflicting UI code once.

- The reviewed conditional UI and strict `buildReviewableRecipe` fail-closed guard derive from PR #137, so v0.2 cannot silently lose per-event mappings.
- The independent per-log-type validation, separated redacted examples, optional source-delivery hint, session continuity, and actual Chromium proof derive from PR #138. `ChatGPTConditionalDraft` now validates each named group separately in addition to the complete sample before calling the existing v0.1 conditional authoring/backend pair.
- Main's independently qualified canonical favicon from PR #136 is retained without duplicating SVG/PNG/ICO links.
- Consolidation focused unit test 16/16 PASS; frontend TypeScript/Vite build PASS; built Backend plus genuine Chromium with three-family DRAFT, single-source privacy/context and existing Auto conditional DRAFT 3/3 PASS (isolated loopback). Full exact-head CI, remote main merge and development installation must be qualified separately for this final merged source.

## Source identity DRAFT parity correction

Follow-up integrated test found that separately reviewed ChatGPT producer information could appear in the manually copied prompt but was not synchronized to the actual generated DRAFT identity. The fix reuses the already reviewed `parserIdentitySlug(vendor, product)` and updates `draft.vendor`, `draft.name`, `draft.version` and `draft.guided.slug` whenever the matching producer details change. The log-delivery field remains unverified descriptive context and never claims transport/native support.

The actual isolated Chromium integration test now verifies a three-family downloaded conditional Ruby DRAFT includes `vendor=Example Vendor`, `product=Security Gateway`, `productVersion=9.4`, and `projectId=draft-example_vendor_security_gateway`, together with all three reviewed event branches. Focused source context and identity tests and Vite production build pass. No Stellar Dictionary release selector, vendor grammar patch, or target installation is added.
