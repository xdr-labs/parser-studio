# Security Source Follow-on PoC — Executed Results

## Decision

Keep the current main `security_source.parse_security_source` as the base.
Selectively retain two independent candidates: explicit LEEF `xHH` delimiter
support and source-schema state isolation. Do not replace KV/JSON/CEE engines,
merge this research PR, or claim a general vendor accuracy increase.

Comparison baseline: `c2f464444a7aa899bd8b251507234720e4cbdde2`.
Previous independent composition: `d318ca4b9dc99040e90bdc1e48d4eeb791ef958f`.
Both local and remote main heads were checked; main dirty work was not used.
Only `poc/research_validation/` is changed in the independent worktree.

## 1. LEEF delimiter notation — new implementation

The current main accepts literal separators and `0xHH`, but rejects `xHH`.
The new adapter only runs when the existing result reports
`LEEF_DELIMITER_UNSUPPORTED`. It recognizes exactly two hexadecimal digits
after `x`, preserves the original header token, and reuses the existing bounded
extension decoder. Direct, RFC3164, RFC5424 and plain-BSD forms are tested.
No separator substitution, whole-record rewriting or missing-tab repair occurs.

Reference: Tenzir's first-party format documentation explicitly describes both
`0x` and `x` prefixes: https://tenzir.com/docs/reference/operators/read_leef/
This is an original additive implementation, not imported Tenzir code.

| Authored security conformance | Current main | Additive LEEF candidate |
| --- | ---: | ---: |
| Records | 192 | 192 |
| Reference native body fields | 3,552 | 3,552 |
| Exact key/value/byte-span TP | 0 | 3,552 |
| FP / FN | 0 / 3,552 | 0 / 0 |
| Exact field-set and source-tree records | 0 | 192 |
| Falsely complete records | 0 | 0 |
| Original records retained | 192 | 192 |

These deliberately constructed cases cover `x7C`, `x09`, `x5e`, Unicode,
empty strings, repeated keys, embedded equals signs and source-span offsets.
They are NOT new vendor captures or open-world accuracy. The candidate reports
144 SOURCE_PARSED and 48 PARTIAL: repeated-key warnings remain, although all
occurrences and their source spans are correct. Framed syslog header fields
are explicitly outside this LEEF body oracle.

RED control: six new unit tests, three failures and one error with the
unchanged main parser. The additive implementation passes all six.

## 2. Mixed security-source schema isolation — actual reproduced regression

The prior independent document composer applied a declared Zeek table schema
to subsequent JSON/CEF/LEEF records, retained stale state after `#close`, and
classified unknown hash-prefixed records as metadata. Three of six new
regressions failed before the fix. All now pass.

The revised composer resets source schema state correctly, requires new types
after field rotation, sends explicitly framed security records to the current
security parser, and preserves unknown hash-prefixed records as events. It
reuses the existing bounded table decoder; native types are not inferred.

A 293-record constructed mixed stream arranges the EXISTING 284 WAF,
Suricata and FortiGate inputs with six explicit metadata lines, two authored
table records and one unknown hash-prefixed record. This is not 284 new logs.

| Ordinary security records inside the mixed stream | Prior composition | Fixed composition |
| --- | ---: | ---: |
| Inputs / independently field-scored | 284 / 279 | 284 / 279 |
| Correct native key/value/byte spans | 0 | 7,580 |
| Missed fields | 7,580 | 0 |
| False fields | 0 | 0 |
| Ordinary outputs identical to current main | 5 / 284 | 284 / 284 |
| Raw records preserved | 284 | 284 |

The five NUL-corrupted source records remain separately accounted. The single
malformed KV tail is prefix-scored as PARTIAL, not silently excluded. The fixed
composition has 276 fully correct/complete ordinary records, not 284. The core
main parser already handled the ordinary sources correctly; this experiment
fixes the independent composition layer, not a 0%-to-100% core-engine gain.
Unframed, identically shaped interleaved tables still require source identity;
no universal mixed-source discrimination is claimed.

## 3. Fresh external LEEF evidence — no additional gain

Candidate hashes were frozen before acquiring three first-party upstream
fixture files at `tenzir/tenzir` commit
`ebce5bdaecc463d7b2fa3e107d22682da489bd49`.

Eight source records were retained. Four syntactically valid records contain
25 native scalar fields, all exact in BOTH current main and the candidate.
Four missing-delimiter template records remain invalid and are not field-
scored; neither parser falsely declares them complete. There are no `xHH`
records in this small source set, so it does not validate a real-source gain.

Literal backslash-t strings in these fixtures are not replaced with tabs or
used to invent additional fields. The native-token oracle is independent
Python splitting and byte accounting, not Tenzir's semantic normalization.
Source files, upstream output examples and license remain ignored locally.

## 4. Existing security regression evidence retained

- Existing source inputs: 284 retained; 279 field-scored / 7,580 fields, exact
  in current main and selected composition; all 284 original outputs unchanged.
- Official AWS WAF examples: eight valid JSON examples / 268 fields exact;
  two other snippets remain outside field scoring, not successful records.
- Derived CEE transport cases: 264 / 6,836 fields exact. The previously rejected
  whole independent CEE replacement still misses 1,709 fields.
- Zeek: 127 data records / 3,132 fields exact in selected metadata composition;
  metadata/preambles remain in the complete physical-record ledger.

Independent suite: **75 tests PASS, zero failures/errors/skips**, using verified
exact-current main modules. The native Ruby/CONF, product UI, DP/sensor and
production gates are not covered. Generic repository CI is recorded separately
on the committed head and does not replace Python evidence.

## 5. New commercial CEF evidence — field accuracy NOT SCORED

Four SHA-pinned Elastic CEF source collections were acquired: Check Point,
Cisco ASA, Forcepoint NGFW/SMC and Trend Micro. The 22 original records come
from `event.original`; the predecoded `message` descriptions are NOT inputs.
All 22 currently produce SOURCE_PARSED proposals, but there is no independent
new CEF field-gold score and this must not be called 22 accurate parses.

The separate Trend Micro official page supplied 21 textual examples. Some have
omitted delimiters, absent physical tabs or abbreviated values; none was
silently reconstructed to increase a score.

The exact operation to create/run `cef_reference.py` and
`test_cef_reference.py` received two OpenAI security-state denials via Remote
Desktop Commander `start_process` on the same dev-atlas device/path, with a
successful access check between attempts. Neither file exists. No alternate
path/tool was used to perform that operation. Independent LEEF and metadata
work remained available and was completed.

The correct source-only first-pass predictions are
`.cache/cef-leef/frozen-source-predictions.json`. An earlier ignored diagnostic
on the wrong `message` field is NOT a benchmark and must never be reused.
User configuration action: none identified.

## Reproduction

With the existing ignored, licensed source caches and exact main archive:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/run_security_tests.py
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/benchmark_security_followon.py
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/benchmark_leef_upstream.py
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/verify_current_security.py
```

These commands perform no automatic external download or hosted LLM call.
Candidate and oracle source hashes are recorded in aggregate JSON artifacts.

## Remaining order

1. At the next permitted resume, retry the SAME blocked CEF reference operation;
   complete native field/value/span scoring for the 22 acquired original events.
2. Obtain independently sourced, valid commercial `xHH` LEEF examples and rare
   CEF/LEEF variants; freeze before acquisition and retain negative findings.
3. Only evidence-backed additive primitives may be proposed for main-PoC
   integration. Dictionary mapping and masking work remain lower priority.
