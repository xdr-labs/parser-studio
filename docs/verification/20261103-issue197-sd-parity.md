# Issue #197 — RFC5424 Structured Data parity and honest source coverage

Date: 2026-11-03 KST
Repository: xdr-labs/parser-studio
Base commit: a4b4e2fba54588fa2b9807e1cfeed49190061927
Branch: fix/auto-rfc5424-sd-field-parity-20261103

## Defect and acceptance

The published Juniper SRX RT_FLOW_SESSION_DENY example was structurally complete in Python Multi-Pass (23 SD-PARAM values, zero residual bytes) but the browser/Ruby default RFC5424 parser previously returned only the raw Structured Data string. The UI said "parsed completely" despite missing security field mappings.

This implementation preserves the raw SD string and adds bounded, ordered syslog_sd.element_N.{sd_id,params} in browser and both Ruby compiler templates. It handles RFC5424 escaping and multiple SD elements. Unsupported parameter names use reversible hex-encoded keys, not invented semantics.

Browser normalization accepts hyphenated destination names supported by the backend schema. Unaddressable nested, array and over-budget source values are now counted rather than silently omitted. UI text explicitly distinguishes structural source parsing and DRAFT file creation from native runtime and Stellar Cyber target verification.

## Verified golden evidence

- Python single/batch source preview baseline: SOURCE_PARSED, 23 SD-PARAM values, zero residual bytes, 31 spans.
- Isolated Chromium Auto Parser (loopback 19986) and candidate backend (19305): 32 mapping sources, 24 SD leaves (SD-ID + 23 params), including source/destination IP, ports and policy.
- Final browser sample: ready=1, need-fixing=0; generated customized_juniper_srx Ruby (39,120 bytes) and matching CONF (836 bytes); manifest=DRAFT, no deployment.
- Actual downloaded Ruby 3.2.3 parser.parse(raw) callback: 23 original SD params extracted; eight critical normalized source values (source/destination IP, port, zone, policy, reason) matched exact expected values; no parser_err_*.
- Independent compiler-native regression test verifies compiled Ruby top-level srcip/dstip/srcport/dstport and vendor policy/reason.
- Synthetic RFC5424 native smoke: two valid plus nine malformed grammar cases PASS; new Juniper SD oracle PASS.
- Synthetic import/tamper inspection: ten exact parser pairs plus ten opaque modification cases PASS.

## Regression gates

- Backend Authoring: 477/477 PASS, including the new actual compiled Ruby golden test.
- TypeScript typecheck: PASS.
- Frontend Vitest: 173/173 files, 1,308/1,308 PASS.
- Frontend TypeScript typecheck and production Vite build: PASS.
- Chromium additional representative regression: 8/8 PASS (PAN-OS, ASA,
  BIG-IP, EDR JSON, log accounting, original user log privacy, and complete
  first-time user download/save/restore journey). The two legacy mapping tests
  were updated to use stable source-field identifiers instead of rendered row
  indices after the vendor-only list was folded in a prior UI change.
- This Chromium flow runs actual interactive UI/Backend and generated Ruby callback, NOT native Fluentd runner certification or Stellar DP import.
- Python source ledger schema differs from browser/Ruby output schema; value-level interoperability is demonstrated, not identical schema.
- 100 browser-leaf and 60 auto-mapping proposal limits still exist; unsupported/excess values are disclosed as unaddressable, not claimed as output.

## Safety and deployment

All modifications remain in a dedicated isolated dev-atlas worktree. Main, public development preview, live backends and credentials were not changed. Only isolated loopback services were used. This report does not authorize merging or release.
