# Source-to-Stellar Normalization Evidence Boundary — Isolated PoC (2026-10-17)

## Goal and non-goals

This PoC prevents correct **lexical source field extraction** from being mistaken
for correct **Stellar Cyber normalized field semantics**, typed event output,
native parser execution, or production readiness.

It extends the isolated lossless grammar and pinned source-trust PoCs. It does
**not** modify the product's Auto Parser, the existing bounded Multi-Pass Funnel,
the official catalog, target runtime, parser file compiler, or any deployment.

The code lives in `src/poc/sourceNormalizationBoundary.ts`; its regression
tests and privately backed evaluation are in
`src/poc/sourceNormalizationBoundary.poc.test.ts` and
`scripts/poc/runSourceNormalizationReview.ts`.

## Evidence requirements

A review proposal is evaluated only when the exact source event is recognized
by the repo-pinned source reference, including original raw SHA-256, original
prefix, ordered source keys/values, duplicate count and independently replayed
UTF-8 spans. A self-declared fixture cannot qualify. These original source
references are *independent lexical checks*, not human-certified grammar
semantics.

A proposed destination must be present and mappable in the pinned
`STELLAR_METADATA_CATALOG`, with catalog evidence bound to the source file's
`7.0.xs` revision. The boundary uses the existing normalization conversion
and value-range semantics for IPs and ports; a timestamp must include an
explicit timezone. Empty and unknown placeholders are not compatible type
evidence.

It refuses overlapping destination fields, repeated or reused source keys,
missing source fields, catalog non-scalar/reserved/unsupported destinations,
non-numeric/out-of-range ports, malformed IP addresses, and malformed request
names. All requests are bounded to 256 assignments.

Every returned decision is **only a review plan**, with:
- `sourceGrammarApproved: false`
- `sourceMeaningApproved: false`
- `normalizedMappingApproved: false`
- `nativeRuntimeVerified: false`
- `productPromotionAllowed: false`
- `requiresHumanReview: true`

The data-bearing source field **values are never returned** from this
diagnostic plan. No native parser file, normalization output or target request
is generated or transmitted.

## Measured outcome — pinned known-family source records

The original, independently tokenized private SonicWall fixtures from the
preceding PoC were used to exercise the type guard. These are *not* unseen
product test cases and should not be represented as an unbiased accuracy
estimate.

| Criterion | Result |
| --- | ---: |
| Independently pinned original lexical source events | **8/8** |
| Explicit source-to-Stellar mapping proposals | 24 |
| Proposals with source values fitting documented target types | **8** |
| Proposals failing documented target type validation | **16** |
| Independently verified source-field semantics | **0** |
| Approved Stellar target mappings | **0** |
| Native compatibility verified | **0** |
| Automatically promoted candidates | **0** |

The evaluated proposals were `src → srcip`, `dst → dstip` and
`fw_action → action`; none of the vendor-specific meanings were inferred as
approved simply because a name resembles a common security metadata field.

**Interpretation:** 8 of 24 candidates survived the target *type* filter. This
is not a measured normalization success rate; true-positive semantic mapping
requires independent source-field definitions, a human-reviewed Stellar field
destination, and testing against fresh unseen events.

## Reproduce in the isolated PoC worktree

```sh
python3 scripts/poc/fetchLosslessGrammarCorpus.py
python3 scripts/poc/createLosslessIndependentOracle.py --split development
python3 scripts/poc/createSourceTrustPins.py
npx vite-node scripts/poc/runPinnedSourceTrustOracle.ts
npx vite-node scripts/poc/runSourceNormalizationReview.ts
npx vitest run src/poc/sourceNormalizationBoundary.poc.test.ts
npm test
npm run typecheck
npm run build
```

The corpus is SHA-pinned at
`70fb8f5e9e0753c763c66936880d3ca2b8e590cbadeabf0c8c7a674b7e858039`.
The raw log source bytes and independently decoded field-value oracles remain
in the user's private host state only, not in Git.

## Next acceptance gate

Obtain independently auditable *source-field semantic contracts* for selected
vendors: exact log family/version, authoritative field definitions, type/range,
empty semantics, duplicate handling and review provenance. Define and validate
the target mapping contract against the approved Stellar dictionary revision,
including overlapping or conflicting assignments and complete per-field
precision/recall with safe abstention counts on new source files.

Only after those gates should a separate opt-in adapter feed reviewed mapping
proposals into the product's existing bounded Multi-Pass workflow, followed by
same-HEAD browser, native parser and authorized Full User E2E. This PoC has
**not** performed those product integration or deployment gates.
