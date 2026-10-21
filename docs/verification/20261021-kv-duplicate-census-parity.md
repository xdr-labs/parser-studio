# KV source-census honesty before reviewed parsing — 2026-10-21

Parser Studio field normalization is fixed to Stellar Cyber **7.0** only.
This change is a manufacturer-neutral beginner-UX/source-accounting correction,
stacked after the already isolated source framing Draft PR #129.

## Reproduced discrepancy

- The local KV DRAFT extractor and Ruby parser already reject multiple
  occurrences of the same decoded key as ambiguous.
- The beginner's lighter-weight, value-free, pre-analysis KV grammar census
  did not track field-name identity. It could tell a novice "0 events need
  attention" for records such as action=allow action=deny even though the
  strict native DRAFT grammar refused the same repeated key.
- This affected standalone KV, explicit RFC5424 KV and tagged RFC3164 KV
  source signatures. Quotes containing an equals sign are not a new key.

## Bounded fix and evidence

- Add a bounded, per-record Set of parsed KV source field names in the
  existing lexical token visitor. Preserve source value bytes, quoted
  values and case-sensitive field name identities.
- Duplicate source names produce BODY_MALFORMED in initial event accounting
  while the physical sourceCount/accounted/complete counts remain accurate.
  The safe-census API never discloses source field values.
- A subsequent user-triggered, independently reviewed Multi-Pass source
  recovery is still allowed to preserve and explain repeated occurrences.
  This change **does not** disable that existing behavior or claim that a
  first-pass warning permanently forbids all future reviewed DRAFTs.
- RED: five newly authored duplicate KV/source wrapper examples failed
  before correction. Five independent positive cases already passed.
- Focused Vitest with existing envelope, extraction and source tests:
  29/29 PASS. Real Playwright desktop Chromium, loopback Vite,
  in-repository Python Multi-Pass and built offline Backend: 2/2 PASS.
  No HTTP mocks, live target or external AI.
- Full frontend regression, Web build and hosted exact-HEAD CI must be
  read from their real run evidence before final product qualification.

## Boundaries

No manufacturer-wide F1 or physical device original is inferred. The
reviewed Ruby DRAFT compiler, output schema and target interfaces remain
unchanged. No 6.5/6.6 Dictionary, version selector, release, mobile,
DP upload, sensors, production, merge or public-development apply.
