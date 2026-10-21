# Original GELF and RFC7464 JSON Text Sequence — strict decoded key identity

2026-10-21. Parser Studio product normalization remains fixed to Stellar
Cyber **7.0** only; the original stream parser is manufacturer-neutral and
does not provide a native DRAFT decoder for these transport grammars.

## Reproduced source-framing defect

- Docker JSON-file source framing already uses a decoded-name uniqueness
  hook to reject duplicate JSON object keys before accepting a frame.
- GELF NUL-delimited JSON and RFC7464 JSON Text Sequence frame validation
  were still using the permissive standard-library json.loads without that
  hook. They could accept a framing wrapper whose earlier decoded member
  had been silently overwritten.
- Python Multi-Pass's downstream strict source parser might later detect
  that same error, but could still report a seemingly recognized frame
  with PARTIAL status. An invalid original frame must abstain at the
  framing boundary itself.

## Fix and bounded correctness evidence

- Use the exact already-qualified decoded-key hook in both GELF NUL and
  RFC7464 JSON Sequence input validation; preserve all source bytes.
- Malformed root, nested, escaped-equivalent and array-child duplicate
  names are rejected as **UNSUPPORTED_SOURCE_CONTAINER / RAW_ONLY**
  with explicit framing reason codes, no extracted values, no native
  or target verification claim.
- Valid independent-object names and UTF-8 source including Korean/Japanese
  values still produce source-only PARTIAL frames. Exact source-byte
  accounting is preserved across event and framing separator partitions.
- Independent authored negative corpus: 3 GELF and 4 JSON Text Sequence
  duplicate cases (7 invalid source wrappers). Baseline produced frame
  recognition where strict framing refusal was expected (all seven RED).
- New focused Python unittest methods 3/3 PASS after correction; existing
  transport 7/7 PASS and Audit/CRI/Docker framing 8/8 PASS. Individual
  authored subcases are not a manufacturer accuracy denominator.
- Exact-head hosted CI must run the new focused source contract before
  claiming this candidate qualified; previous compiled Ruby and public
  browser E2E gates remain unchanged.

## Product / deployment boundary

This is *source-only framing accuracy*, not a native Fluentd or proprietary
Stellar loader contract. The original GELF and RFC7464 transports remain
in the explicit unsupported-DRAFT category, as do Linux Audit event grouping,
CRI P/F, Docker JSON-file, W3C/Zeek and other original wire containers without
independently reviewed native grammars. Do not enable a simulator, sensor,
DP upload or public deployment to test this change.

No untrusted source values are sent to external AI services. No manufacturer
or target-runtime success rate is inferred from synthetic tests.
