# Lossless Composite Network Endpoint Grammar — Isolated PoC (2026-10-17)

## Root cause, not a one-vendor rescue regex

A flat source-value tokenizer can correctly preserve `src` and `dst` values
while a later type guard correctly rejects them as invalid **single IP
addresses**. The reason is compositional: a security Syslog endpoint can hold
multiple typed values together as `IPv4:port:interface`, with an optional
resolved hostname. Treating that raw source value as one normalized IP
incorrectly fails type validation; stripping characters destroys source
fidelity.

This grammar is intended as a reusable, strict composition parser for
bounded complete values. It does **not** override the existing product engine,
create an exported parser or turn an unsupported event into a silent success.

Vendor evidence: the SonicWall **SonicOS/X 7.0.1 Log Events Reference Guide**
describes source and destination addresses with optional port, network
interface and resolved name, and publishes standard Syslog examples with
`src=IPv4:port:X0` and `dst=IPv4:port:X1`.

- Official reference:
  https://www.sonicwall.com/ja-jp/techdocs/pdf/SonicOS-X_7.0.1_LogEvents_ReferenceGuide.pdf
- Earlier official NSv reference with the same structural examples:
  https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-4-nsv-series-log-events-reference-guide.pdf

A documented family of examples is **not** proof that every vendor, firmware
or source log uses identical field meaning. Source grammar approval,
normalization semantics and native parser compatibility remain separate
acceptance gates.

## Implementation

- `src/poc/compositeEndpointGrammar.ts` recognizes exactly IPv4, a bounded
  decimal port 0–65535, a conservative interface label and an optional
  validated DNS name. It rejects malformed IPv4, ambiguous IPv6 colon syntax,
  leading-zero ports, unsafe path-like interface names, missing delimiters,
  overflow, whitespace/control characters and extra undelimited fields.
- Every subcomponent gets an exact `SourceSpan` with **UTF-16 and UTF-8 byte**
  offsets against the original raw log. Original raw value and full original
  event remain unchanged.
- Before any target review, the *full event* must match the repository-pinned
  independent source lexical oracle, including field identity, original
  source hash, sequence and byte-span replay.
- The caller explicitly proposes a source/destination role for review; only
  then does the component-level type guard compare IP/port against the pinned
  Stellar metadata catalog's `srcip/srcport` or `dstip/dstport`.
- No user-entered mapping name can waive source trust, type validation or
  original-value preservation.

All review results retain these exact denials:

```text
sourceGrammarApproved: false
endpointSemanticApproved: false
normalizationApproved: false
nativeRuntimeVerified: false
productPromotionAllowed: false
requiresHumanReview: true
```

The review result includes component count, original source byte spans and
review-target labels, **not original source values**. No target API is called
and no native parser file is created.

## Qualification — already known, pinned SonicWall public sources

A separate Python standard-library `ipaddress` and bounded lexical oracle
produced independent **private** field-value reference data without importing
the TypeScript tokenizer.

| Metric | Observed |
| --- | ---: |
| Previously pinned original source events | 8 |
| Independently source-exact `src` and `dst` composite values | **16/16** |
| Exact component values and original byte spans | **48/48** |
| Source-to-target IP/port type review candidates | 32 (review-only) |
| Original event tamper controls rejected | **16/16** |
| Semantic source field mappings approved | **0** |
| Native runtime / Stellar import approvals | **0** |
| Parser product promotions | **0** |

This is *in-sample* validation of a previously known public source family. It
is **not** a generalization or normalization precision/recall estimate.
Decomposing a documented complete source token into lexical subcomponents
does not prove the resulting semantic mapping is the correct target assignment.
The broader 265/222 event sets and the previous Juniper/Sophos oracles remain
separate acceptance denominators.

## Reproduction

```sh
python3 scripts/poc/fetchLosslessGrammarCorpus.py
python3 scripts/poc/createLosslessIndependentOracle.py --split development
python3 scripts/poc/createSourceTrustPins.py
python3 scripts/poc/createCompositeEndpointOracle.py
npx vite-node scripts/poc/runCompositeEndpointOracle.ts
npx vitest run src/poc/compositeEndpointGrammar.poc.test.ts
npm test
npm run typecheck
npm run build
```

Private source records and Python oracle values remain in
`~/.local/state/parserstudio-lossless-fresh-20261017/`, mode 0700/0600.
No raw source log values, IPs from real deployments or credentials are added
to the repository.

## Next acceptance

Independently document the true source log version and role/field semantics,
including optional DNS and IPv6 edge cases. Then obtain separate human source
approval and official Stellar mapping review before allowing typed component
candidates to be mapped to actual normalized fields. Test on entirely new
unseen vendors and log files with per-field precision, recall, mis-mapping,
and abstention denominators.

Only after evidence and full browser/native E2E qualification should any
opt-in adapter be considered for the existing bounded Multi-Pass product.
