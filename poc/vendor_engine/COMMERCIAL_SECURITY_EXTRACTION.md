# Commercial security-source extraction qualification

## Scope and priority

Engine-only source extraction for ordinary security-system logs: AWS WAF,
IPS/IDS, NGFW and EDR. Preserve original keys, values, native types, repeated
occurrences, arrays, unknown fields and exact UTF-8 positions. Do not split
signature/message/payload prose into invented fields. Stellar Dictionary
mapping comes later; masking recognition and visible-token retention are last.

This change extends the existing source/stream lane based on `ba663ba`.
It does not change UI, native Ruby/CONF, Fluentd, DP/sensor configuration,
production, credentials, release state or parser deployment.

## Reproduced gaps and corrections

1. Explicit bracket/colon/quoted-value records from Log Exporter were mistaken
   for RFC5424 structured data. `security_pairs.py` now scans that source
   grammar with bounded loops, complete value boundaries and exact source
   spans. Repeated keys retain ordered values. Quoted semicolons, brackets,
   Unicode, backslashes and unknown keys are data, not new token boundaries.
2. A native key can contain a colon, including `methods:`. The key/value
   delimiter is the colon before the quoted value, not necessarily the first
   colon in a key. Preserve the full native name rather than renaming it.
3. Some source records have invalid timestamps, repeated structured-data
   keys, or trailing structured-data whitespace. The security adapter retains
   these original fields and emits explicit issues. The underlying RFC5424
   function remains strict by default; its opt-in source-preserving mode
   does not certify RFC compliance or fabricate a valid timestamp.
4. PAN-OS-shaped CSV can have a short IETF-like header or a BSD nil application
   tag. Explicit numeric CSV boundaries and valid header tokens now preserve
   those records. PRI+KV also retains its priority instead of discarding it.
   CSV names remain `column_N`; security meanings are not inferred.

Malformed tails, unsafe object keys and field/input limits remain fail-closed.
A completed prefix can be retained with a residual tail; it cannot be labeled
fully parsed. Existing source byte accounting and stream framing are reused.

## Original pinned commercial fixtures

The seven existing fixture sets are FortiGate 6.2/7.2/7.4, Check Point R80/R81,
and PAN-OS threat/decryption, pinned to the repository revision in
`commercial-security-manifest.json`. These are upstream test examples, not
newly captured customer production traffic or comprehensive version coverage.
Candidate development was exposed to these fixtures; this is exploratory
source-correctness evidence, not an untouched-vendor generalization claim.

The source oracle is separate from the implementation: standard-library CSV
and shlex decoding plus complete lexical tokens with original byte intervals.
It does not read semantic expected JSON, event templates or parser predictions
as gold. Header and payload namespaces are compared consistently: introducing
an internal `body` wrapper does not create a fictitious loss/improvement for
otherwise correctly extracted payload fields. True positive requires original
field identity, decoded type/value **and** exact UTF-8 position. Composite
structured-data text is audited separately from its atomic attributes.

| Measure | Frozen ba663ba baseline | Candidate |
| --- | ---: | ---: |
| Total original records, all retained | 392 | 392 |
| Fully reference-scored records | 391 | 391 |
| Reference exclusions (malformed quoted KV) | 1 | 1 |
| Reference atomic source fields | 27,968 | 27,968 |
| Exact identity/type/value/byte-span TP | 26,985 | 27,968 |
| False source captures | 147 | 0 |
| Missing reference fields | 983 | 0 |
| Entire field ledger and tree exact | 355 | 391 |
| Exact composite SD spans, separate | 1/3 | 3/3 |

The excluded FortiGate record has an unterminated quote. It remains original
raw/PARTIAL, not a successful or silently removed input. Zero field errors on
391 reference-scored records does not mean all 392 are fully supported.

The final parser statuses are 166 SOURCE_PARSED and 226 PARTIAL. Of the latter,
223 retain all positional PAN-OS CSV fields but still request schema confidence,
two retain all Check Point fields with source-format warnings, and one has the
malformed FortiGate tail. Extraction correctness and these warnings are distinct.

## First new-fixture validation and exposed follow-up

Ten source modules were frozen before first acquiring three further Check
Point fixture families: authentication, audit, and with-time. The initial
prospective result is immutable in `commercial-prospective-summary.json`:
28 all events, 26 reference-scored, two outside the original key grammar;
687/687 exact atomic fields on the 26, and every raw record retained.

Inspection of the remaining two revealed literal colons in native key names,
not unquoted values or sentence logs. The correction and subsequent reference
extension are explicitly **after exposure**. Their separate evidence in
`commercial-followup-summary.json` shows 28/28 reference-scored records,
779/779 exact source fields, zero FP/FN and every tree/raw event retained.
The baseline on that expanded, identical reference set has TP0/FP196/FN779.
Do not replace the original prospective result with the follow-up or call
these same-vendor/same-revision test families future-version validation.

## Sources and rights

Format context was checked against primary sources:
- Check Point Log Exporter and advanced configuration:
  https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter.htm
  https://sc1.checkpoint.com/documents/Log_Exporter/EN/Content/Topics/Advanced-Configuration.htm
- Splunk Connect for Syslog's Check Point Log Exporter interoperability notes:
  https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Checkpoint/logexporter_5424/
- PAN-OS source CSV field/format documentation:
  https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions

Only source pins, aggregate counts and self-authored controls are tracked.
Original fixtures and source-derived private results stay in ignored research
caches. Upstream license review does not authorize shipping those fixtures as
commercial product assets. No values were reconstructed from masked content.
An absence of visible masking markers is not evidence about prior anonymization.

## Reproduction and remaining acceptance gates

```bash
PYTHONPATH=poc/vendor_engine python3 poc/vendor_engine/benchmark_commercial_security.py
PYTHONPATH=poc/vendor_engine python3 -m unittest discover -s poc/vendor_engine -p 'test_commercial*.py' -v
PYTHONPATH=poc/vendor_engine/.cache/drain_deps:poc/vendor_engine/.cache/logparser:poc/vendor_engine/.cache/logparser_deps python3 -m unittest discover -s poc/vendor_engine -p 'test_*.py' -q
```

The benchmark fails on changed source hashes. Missing local licensed caches
cause explicit skips, not PASS. Web CI, Python source correctness, native
runtime qualification and actual Stellar target qualification are separate.

The immediate commercial-diagnostic/source-comparison task is complete.
Remaining ordered gates: independent CEF/LEEF security-vendor and later-version
examples; rights-cleared reusable corpus/template inventory; consolidated
engine decision versus the separate validation PoC. Product integration and
verified Dictionary work remain subsequent, separately scoped tasks. Generic
prose experiments remain paused and their original worktrees are preserved.

## Final regression qualification

Final unchanged candidate: **233/233 tests PASS**, zero skips/errors/failures.
An initial full-suite run caught an outdated synthetic framing oracle: it
omitted the PRI header and treated the new body wrapper as a different source
identity. The source encoder now explicitly records the original PRI and the
comparator canonicalizes only transport/payload scopes. Version 2 contains
6,048 source fields (the prior 6,036 plus twelve actual priorities); all 216
record trees and all positions agree. The earlier published framing report is
unchanged; the current result is `security-framing-current-summary.json`.

`commercial-security-validation.json` records exact tested source hashes,
initial failure, final test evidence and the separate original/prospective
cohorts. The transient edit safety-check failure succeeded on the identical
request after a session check; no alternate route was used. The former
commercial-source diagnostic block likewise resolved normally. No current
owner-action blocker is known.
