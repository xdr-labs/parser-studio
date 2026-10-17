# Conservative KV Grammar: Cross-Format and Vendor-Profile Safety Gates (2026-10-17)

**Scope:** isolated source-only PoC, stacked on Draft PR #39. No product parser, main, UI, normalization, DP, sensor, native adapter or deployment modifications. Previously qualified original and mutated security fixtures are used **read-only**. The previous PR #29–#33 verification work is not repeated.

## Frozen read-only source denominators

| Cohort | Original events | SHA-256 of frozen private records.json |
| --- | ---: | --- |
| Juniper / Check Point / Sophos / CrowdStrike vendor holdout | 571 | 3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2 |
| PAN-OS / Cisco Umbrella / Defender external holdout | 790 | dc03215a69e0ca6a74d3cc06f750360d15f6052c9dfe1c43e270419f11e9ed0e |

The new candidate was only audited as a **bounded KV grammar**. Grammatical recognition alone is not evidence of original field accuracy, vendor-format completeness, native execution or source verification.

## Original source fidelity

Of **1,361** frozen original events, the isolated general KV lexer recognizes only **254**, all in the **271-event Sophos XG** subset. The other 1,090 are different formats and do not become KV candidates: PAN-OS positional CSV, Juniper, Check Point, Umbrella and Defender/CrowdStrike JSON.

The independent Sophos source field/value Oracle contains **151 fully qualified events and 4,956 original key/value tokens**. The candidate is lexically eligible for all 151 and agrees with the original Oracle **151/151 exact event fields**. These are source values, not independently certified Sophos semantics.

The unchanged application's existing source-specific Sophos profile is additionally compatible for **150 of those 151**. The final independently source-exact event is not approved by that profile and **must not be silently promoted**. Another 103 syntactically recognized original Sophos events have no independent source Oracle and remain unscored.

## Critical adversarial result

The five pinned mutation sets contain **2,892 invalid or altered inputs**. The general KV lexer syntactically recognizes **600 of 900 Sophos mutations**, while the existing source-specific Sophos vendor profile recognizes **0 of 900**. All other 1,992 malformed mutations (1 known invalid, 1,532 external, 45 Juniper bare and 414 Juniper bracket) are rejected by the lexer.

**KV syntax success is not vendor parser success.** Promoting these 600 to SOURCE_PARSED on lexical evidence alone would be incorrect. Using the already existing Sophos profile **as a veto, not as manufacturer certification**, preserves the distinction: all 600 candidate mutations are held back; zero gain independent original correctness is fabricated.

## New proposed PoC-only vendor qualification gate

The pure source-review classifier reports one of: NOT_KV_CANDIDATE, SOURCE_IDENTITY_REJECTED, EXISTING_VENDOR_PROFILE_VETO, SOURCE_FIELD_MISMATCH, GRAMMAR_ONLY_UNSCORED, PROFILE_MATCH_UNSCORED, SOURCE_EXACT_VENDOR_UNREVIEWED, SOURCE_EXACT_PROFILE_REVIEW_ONLY.

It requires exact original SHA and raw retention, independent source value equality and separate vendor-format compatibility before marking **SOURCE_EXACT_PROFILE_REVIEW_ONLY**. All decisions keep manufacturerSemantics=NOT_CERTIFIED, nativeTarget=NOT_VERIFIED and canAutoPromote=false.

On the Sophos originals, **150** reach source-exact profile review-only, **104** candidate records are vendor-profile-vetoed, and **17** are not KV candidates. All **600** syntactically matched invalid Sophos mutations are vetoed. This classification remains **PoC-only**; existing product behavior is unchanged.

## Reproduction

- node_modules/.bin/vitest run src/poc/vendorProfileReviewGate.test.ts
- node_modules/.bin/vite-node scripts/poc/runConservativeKvAdversarialGates.ts
- node_modules/.bin/vite-node scripts/poc/runSophosVendorReviewGuard.ts
- npm run typecheck
- npm test
- npm run build

The original private source rows, mutation corpora and expected original field-value Oracle remain under ~/.local/state/parserstudio-fresh-vendor-holdout-20261016/ and ~/.local/state/parserstudio-ext-holdout-20261016/ at their existing protected permissions. This report and its runner output intentionally contain no raw log strings or source field names/values.

**Decision:** This review-only source+profile gate is a valuable PoC architectural boundary, not approval to merge the grammar. Manufacturer/transport-specific escape interpretation and the broader native/Stellar acceptance remain separate.
