# Independent Security PoC — CEF Native Accuracy and External LEEF

## Decision

Keep the current security engine. The commercial CEF source comparison is now
complete: all 22 original records / 482 native fields are correct in the current
engine and the independent CEF candidate. This is validation, not a new gain.
A CEF-standard boundary candidate fixes measured quote/space/escape errors on
an authored conformance suite. The prior LEEF addon also shows an additional
gain on one independently acquired ExtraHop-format documentation example.
Do not promote these limited results to universal vendor accuracy or a product
release. No main-engine files or production systems were changed.

Baseline: `c2f464444a7aa899bd8b251507234720e4cbdde2`, actual
`security_source.parse_security_source`. Main local/remote heads were checked;
only the committed isolated snapshot was imported, never the main dirty WIP.
Research parent: `bb42d010f2ea2b8a3938b0b05d0525fcce7b0f45`.

## 1. Previously unfinished commercial CEF scoring — completed

The previously denied creation/execution of `cef_reference.py` and
`test_cef_reference.py` succeeded on the same Remote Desktop Commander tool,
dev-atlas device and research paths. The initial state read also succeeded on
one normal exact retry. No alternative tool or path bypass was used.

The independent oracle imports no parser-under-test modules. It reads native
CEF header/extension keys, decoded values, repeated occurrences and UTF-8 byte
positions. The 22 records come from `event.original`, never decoded `message`
prose. Actual baseline predictions reproduce the previously frozen source
predictions after canonical JSON serialization; list/tuple representation is
not treated as a parser-output difference.

| Source collection | Records | Native fields | Current TP / FP / FN | Candidate TP / FP / FN |
| --- | ---: | ---: | --- | --- |
| Check Point | 3 | 83 | 83 / 0 / 0 | 83 / 0 / 0 |
| Cisco ASA | 1 | 75 | 75 / 0 / 0 | 75 / 0 / 0 |
| Forcepoint NGFW/SMC | 10 | 162 | 162 / 0 / 0 | 162 / 0 / 0 |
| Trend Micro | 8 | 162 | 162 / 0 / 0 | 162 / 0 / 0 |
| Total | 22 | 482 | 482 / 0 / 0 | 482 / 0 / 0 |

These are upstream regression records, not independently verified production
captures. Source redaction is unassessed. No field was excluded or normalized.
Exact original typed source trees are checked as well as field/span tuples.
All 22 records are complete in this limited source contract.

## 2. CEF-standard boundary candidate — measured improvement

The ArcSight CEF standard distinguishes header and extension escapes, allows
spaces inside values, assigns all but the last space before the next key to
the preceding value, and discards final trailing spaces. Quotes are retained
as literal source characters in this standard dialect rather than interpreted
as shell/KV quote delimiters.

Primary specification:
https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm

Eight focused tests reproduced four failures in current main: quoted-value
loss, prior-value trailing-space loss, corresponding framed span errors, and
false completion of truncated escapes. All eight pass with `security_cef.py`.
The candidate reuses current header and frame decoders but independently scans
CEF extensions. It never imports the reference oracle, rewrites raw input,
replaces general KV/JSON parsing, or invents missing fields.

| Authored unmasked CEF conformance | Current main | CEF-standard candidate |
| --- | ---: | ---: |
| Records / expected fields | 96 / 900 | 96 / 900 |
| TP / FP / FN | 840 / 36 / 60 | 900 / 0 / 0 |
| Field-value-span F1 | 94.5946% | 100% |
| Exact source tree + all field spans | 48 / 96 | 96 / 96 |
| Incorrectly declared complete | 36 | 0 |
| Raw records preserved | 96 | 96 |

The candidate remains PARTIAL on 12 repeated-key warning cases; 84 are complete.
It does not falsely advertise 96 complete records. Expected synthetic values
and byte ranges are assembled by a separate encoder and independently checked
against the oracle before scoring.

Three Syslog wrappers produce 288 derived cases / 2,700 body fields. Current
main: 2,520 TP / 108 FP / 180 FN. Candidate: 2,700 TP / 0 FP / 0 FN.
These are transformations of the same 96 authored bodies, not 288 additional
source captures. Envelope fields are outside the derived body oracle.

A separate 24-record malformed control set retains every input. Current main
incorrectly declares 18 complete; the candidate declares zero complete, with
zero exceptions. These records are not counted as successful field extraction.

## 3. Fresh external xHH LEEF example — narrow positive result

A new source was acquired after freezing candidate module hashes, without
modifying the prior `security_leef.py`. VirtualMetric's first-party parser
documentation supplies an ExtraHop Reveal(x) 7.8-format LEEF input using `xa6`
and actual `\u00a6` attribute separators.

Source:
https://vdocs.virtualmetric.com/content-management/pipelines/processors/leef-to-csl/

The source page repeats the same LEEF example twice. Both occurrences are
accounted for, but the unique SHA-identified original is scored once. The
JSON example's `message` explicitly contains the complete LEEF input, unlike
the decoded-message descriptions in the Elastic CEF fixtures. No tabs,
placeholders, missing delimiters or source values were reconstructed.

| Unique external documentation example | Current main | Frozen LEEF addon |
| --- | ---: | ---: |
| Records / original fields | 1 / 19 | 1 / 19 |
| TP / FP / FN | 0 / 0 / 19 | 19 / 0 / 0 |
| Exact tree and byte spans | 0 / 1 | 1 / 1 |
| Raw records retained | 1 | 1 |

This demonstrates an additional gain for this specific externally authored
source form. It is a parser-vendor documentation example, NOT an ExtraHop
manufacturer capture or customer production traffic. One sample does not
establish cross-version, rare-subtype or open-world accuracy. Its descriptive
message remains one original field; no sentence mining is performed.

## 4. Non-regression and verification

The CEF and LEEF candidates compose with the current parser and the corrected
source-document layer. All 284 existing WAF/Suricata/FortiGate outputs remain
exactly identical to standalone main, including partial and invalid outcomes.
This does not relabel the five NUL controls as successful parses.

Independent Python suite: **91/91 PASS**, no failures, errors or skips. The
current-main module files are byte-compared to the exact Git commit. The prior
LEEF source freeze remains intact. The original source predictions and new
external predictions reproduce exactly with canonical serialization.

Main WIP fingerprints, local/remote research HEAD and commit-specific generic
repository CI are checked and recorded in the GitHub checkpoint. That workflow
covers application/browser/HTTP checks, not native Ruby/CONF qualification.

## 5. Additive adoption feasibility

- LEEF xHH recognition remains the best narrowly scoped addition: it only runs
  after the base rejects the delimiter, and has both conformance and one fresh
  external documentation example.
- Source-document state isolation preserves the current security parser; keep
  source identity requirements for otherwise indistinguishable table streams.
- The CEF-standard scanner is a qualified research dialect candidate, not a
  global replacement. Vendor-specific quoted-KV conventions can differ; compare
  those explicitly before selecting a production default.
- Raw/source occurrence contracts match the current SourceEvent interface.
  Actual main integration, native compiler parity, DP/sensor verification and
  release remain outside this independent lane.

## Reproduction and remaining evidence

With the existing ignored, rights-reviewed source caches and exact main archive:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/run_security_tests.py
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/benchmark_cef_native.py
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/benchmark_leef_commercial.py
```

No command downloads sources or calls a hosted LLM. Raw fixtures, source HTML
and predictions stay ignored; committed manifests contain URLs and hashes only.

This checkpoint completes the pending CEF comparison and the next focused
external LEEF validation. Remaining evidence priorities are broader genuine
vendor/version examples, explicit CEF-standard versus quoted-KV dialect
admission, and target-capability validation before any product adoption.
Dictionary mapping, masking optimization and prose mining are not next tasks.
No current tool, host or permission blocker requires owner action.
