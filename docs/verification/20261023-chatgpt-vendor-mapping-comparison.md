# ChatGPT Assisted Parser — vendor field correction false regression

2026-10-23. Scope: real first-use Chromium with manually reviewed, controlled
ParserRecipe JSON and known synthetic security-log samples. No external AI
model call, no real DP/sensor, no backend production/owner target deployment.

## Reproduction on actual installed public development Web

Before this patch, `https://app.parser.xdr.ooo/` rejected three operator-
submitted, otherwise structurally valid vendor mapping corrections:

| Input and requested correction | Holdout source | Original public Web result |
|---|---|---|
| Fortinet FortiGate `devname` → `device_hostname` | 2 distinct KV traffic events | Original logs NO, extra logs YES, overall FAILED |
| Suricata EVE `alert.signature` → `attack_signature_reviewed` | 2 distinct EVE alert JSON events | Original logs NO, extra logs YES, overall FAILED |
| AWS CloudTrail `eventName` → `api_operation` | 2 distinct IAM JSON audit events | Original logs NO, extra logs YES, overall FAILED |

Those outputs came from real manually operated Chromium UI, not a mocked API;
traces and logs are in
`/tmp/parserstudio-manual-assistant-proposals-20261023/outcome-v3.log`.
The samples are representative authored examples, not vendor-certified firmware
ground truth. A different first attempt used only one holdout and was correctly
blocked by the independent minimum-two-event evidence gate; that rejection
was not counted as the product defect.

## Root cause

In `src/parser.ts`, mappings in `vendor_fields` normalize into a
manufacturer-scoped object, for example
`normalized.Fortinet.devname`. Top and namespace fields instead normalize
at the root. The ChatGPT result comparison called
`compareMappingCorrectionCandidate` with only the declarative target labels
(`devname`, `device_hostname`) and expected those bare labels to be keys of
the normalized result. They were not: for vendor fields the actual keys have a
manufacturer prefix. The existing scoped-comparison safety check therefore
misclassified unchanged source values as a regression.

## Corrective design

- Add `normalizedMappingOutputPath(draft,mappingId)` to the existing exact
  source-aligned comparison module. Resolve the *specific approved mapping ID*
  and its actual `top_fields`, `ns_fields` or `vendor_fields` output layout.
  For vendor fields use the same exact draft manufacturer namespace as the
  browser parser (falling back to `vendor` when blank).
- Use the before/after resolved paths when comparing one ChatGPT mapping
  correction. Do **not** globally exempt any vendor fields from review.
- Make the scoped comparison require **the old and new source field to exist
  with the same normalized type in each event**, including when unrelated
  unmapped data leaves the baseline in REVIEW status. This avoids type changes
  being mislabeled as regression-free by the comparison.
- Expand only the composed path bound to account for an already validated
  manufacturer namespace plus an independently validated field target.
  The original UTF-8 source, field values, parser grammar, mapping schema,
  Stellar 7.0 dictionary and native compiler are unchanged.

## Acceptance / security evidence

A new repeatable full Web UI Playwright test
`tests/chatgpt-vendor-mapping-correction-20261023.spec.ts` uses the real
source-pinned local backend and Multi-Pass parser: logs →
ChatGPT Assisted → retrieve validated baseline → submit precisely one changed
JSON `map_field` → full current + separately collected independent holdout
checks → confirm explicit owner approval → create real DRAFT Ruby/CONF →
download and inspect listener CONF. **3/3 PASS** after the patch.
The previously failed **3/3** actual public cases serve as RED evidence; this
patch is not installed on public development yet.

Unit regressions in `src/guided/autoParserRegression.test.ts` prove exact
old/new vendor namespace resolution, the existing top-level field path,
strict source accounting, safe comparison without source values in output,
and fail-closed behavior on unrelated field removal, normalized type change,
and one-record insufficient holdout. Focused regression module **11/11 PASS**.

Full candidate frontend unit collection **1,137/1,137 PASS, 146 files**.
Focused browser collection with local source-pinned real services,
including ChatGPT field correction, Full Recovery, multi-type conditionals,
AI split/merge, new vendor change, and complete first-user journey:
**9/9 PASS, zero skip/failure**. Backend check/build PASS.

## Release boundary

Independent source branch `fix/chatgpt-vendor-mapping-comparison-20261023`
was created from exact public baseline main
`2f7a0d876213e5775ca3e2ae04e25bc63d9299f5`.
This is a DRAFT development candidate and must qualify exact-source CI.
PR #149 (source grammar evidence and holdout-claim clarity) and PR #148
(HTTP JSON 64 KiB wire envelope) remain independently verified changes.
No public Web/backend files were modified by this test. Do not merge or
deploy without separate owner-approved development release authorization.
