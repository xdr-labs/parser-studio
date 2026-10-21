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

1. ChatGPT Assisted Parser accepts optional **solution vendor, product, version/model and log delivery context**, included in a manually reviewed JSON prompt as **user-declared hints**. Vendor/product/version also update the canonical ParserDraft metadata and approved artifact slug, preventing divergence across Auto Parser, Local Versions and generated DRAFT. Producer labels are not correctness evidence.
2. The same named-log-type editor used in Auto Parser is available in ChatGPT Assisted. Original per-type events are combined without rewriting bytes; 2–10 nonempty, distinct groups are required.
3. Each type has a separate synthetic-default, manually editable **redacted sharing example**. Only the reviewed examples are inserted in the copyable ChatGPT prompt. Original local event values are not automatically included or sent to a third party.
4. Existing `ReviewedEventProfilesPanel` is reused for explicit discriminator, type-specific mappings, unknown-type rejection, capability gating and approval. Unsafe or incompatible grammar combinations remain review-only.
5. New independent group acceptance tests every original group with the candidate browser parser, checks complete normalized coverage and disjoint verified routing identities, and **blocks combined file generation** without reviewed conditional or supported mixed-format routing. No group label is silently treated as an event discriminator.
6. Solution context and redacted sharing examples survive Auto ↔ ChatGPT workspace switches in the browser session; new projects or local-version restores reset the shareable examples.
7. The strict Recipe v0.2 equivalent-subset backend explicitly rejects conditional event profiles. The earlier UI reproduced a real failure attempting this projection. The shared buildReviewableRecipe now **rejects conditional eventProfiles** rather than silently dropping mappings. ChatGPT Assisted uses the existing capability-checked, schema-validated, integrity-verified **v0.1 conditional backend DRAFT pair** via a separate reviewer-controlled action after per-named-group checks. Only nonconditional recipes enter the strict v0.2 compiler. The conditional component draws on reviewed parallel Draft PR #137, consolidated with per-group checks here; do not double-merge competing implementations.
8. The shared `main` already integrates the canonical XDR Labs Parser Studio favicon assets (`favicon.svg`, ICO, 16/32/48px PNG, 180px Apple touch and 192px icon) and a standard-library asset test. This branch preserves the newer canonical favicon without adding redundant icon sets or duplicate HTML links.

## Focused acceptance at implementation

- Frontend suite: **146 files / 1,132 tests passed**, including a new conditional Recipe fail-closed regression and UI tests.
- TypeScript + Vite production build: **PASS** (normal bundle size warning; no build error).
- Genuine isolated Chromium new-feature tests: privacy-safe solution/context/favicons **1/1 PASS**; three-type reviewed conditional DRAFT with real backend and Multi-Pass **1/1 PASS**; existing Auto Parser conditional DRAFT **1/1 PASS**. Conditional generation makes zero Recipe v0.2 POSTs.
- Canonical favicon assets: independent favicon unit tests **4/4 PASS**. Public HTTPS read-only probes confirm HTTP 200 and correct MIME types for the SVG, ICO, 32px PNG and Apple touch icon. Already-deployed favicon bytes are independent of this not-yet-deployed feature branch.
- Previous exact source main CI and public-browser acceptance must not be counted as acceptance for this new source revision. This new revision requires its own exact-HEAD CI and development deployment / public Chromium checks.

## Decision and non-gating limitations

**Engine decision:** No new reproducible, cross-vendor general grammar defect has been established from this evidence. Preserve the qualified engine rather than add speculative manufacturer-specific regular expressions. Reopen common grammar work only if new reproducible logs show silent record/field loss, false parsed/native readiness, a shared standards defect across sources, or a blocked novice path for an otherwise qualified DRAFT.

Not verified: arbitrary multi-format/native target import, manufacturer/firmware-wide semantic accuracy, raw wire transport output, any proprietary Stellar importer, DP/sensor operations, and mobile coverage. Unsupported mixtures remain visibly blocked or review-only; the prompt alone is not a compiled parser.
