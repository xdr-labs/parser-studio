# Security vendor envelopes — extraction-first PoC

## Scope and ordering

Primary input remains original WAF, IPS/IDS, NGFW and EDR security-system
logs. Preserve native keys, complete payload/rule/message fields, arrays,
values/types and original UTF-8 positions. No sentence-template mining,
Dictionary mapping, masking optimization, UI, native compiler or target IO
is part of this change.

## Reproduced failures and implementation

The existing security parser required a colon-terminated application TAG
for several BSD-wrapped structured bodies. A manufacturer-style header
ending at the device hostname could hide otherwise supported CEF/LEEF/JSON.
PRI-only CSV and CEE JSON also had incomplete source-body routing.

`security_envelope.extract_security_envelope()` validates bounded priority,
month/day/time and a bounded printable hostname. It admits only an explicit
CEF, LEEF, CEE, JSON collection or numeric-first CSV body at the exact header
boundary. It never searches a log message for a convenient format substring.
The security source and batch framers share this header gate; body codecs are
reused, not reimplemented. Existing tagged layouts retain their previous
field trees. Unknown CSV column meanings still require confirmation and keep
`UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION`; source extraction does not assign
semantic roles or claim native compatibility.

Separate CEF/LEEF limit regressions reproduced false PARTIAL results at
exactly 1,024 extension fields when trailing syntax remained. The extension
scanner now distinguishes trailing whitespace/delimiters from a 1,025th
field. An over-limit field remains visible in the raw residual and the event
stays PARTIAL; the limit was not raised or bypassed.

## Evidence and denominators

The previously qualified 77 WAF/Suricata source examples are reused with
six self-authored transport wrappers (three headers, plain JSON or CEE).
These are **462 derived transport cases**, not 462 new original events,
not an untouched vendor/version evaluation and not customer production data.

A standard-library reference decoder plus independent tokenizer provides
original typed paths/values/byte positions. Header fields and their source
positions are constructed before parser execution. Baseline and candidate
run in separate Python processes; baseline is exact commit
`201fa18e923688f7c265f8684d65e834a370632f`.

| Measure | Frozen baseline | Candidate |
| --- | ---: | ---: |
| Derived transport cases | 462 | 462 |
| Expected original field occurrences | 14,200 | 14,200 |
| Exact path/type/value/UTF-8-span TP | 4,605 | 14,200 |
| Incorrect original field occurrences | 77 | 0 |
| Missing original field occurrences | 9,595 | 0 |
| Exact entire source tree and all fields | 77 | 462 |
| Original records preserved | 462 | 462 |

Zero derived cases are excluded. This metric includes source header fields,
not only JSON payload fields. Original payload trees, repeated values and
order are retained. Prior upstream redaction history remains unknown; absence
of explicit visible mask markers is not proof of never-anonymized traffic.

## External verification status

The earlier blocked operation over four AWS WAF/Suricata fixture files was
retried using the same authorized Remote Desktop Commander tool, device and
original worktree. It succeeded. Existing source fixtures were then made
available in this worktree and the previously skipped source regression was
actually run and passed. This closes that earlier blocker, not all future
source validation.

A separate baseline-only acquisition pass collected seven pinned commercial
fixture sets (FortiGate 6.2/7.2/7.4-labeled fixtures, Check Point R80/R81-labeled
fixtures, PAN-OS threat/decryption). At frozen 201fa18, all 392 physical records
were retained; 243 had SOURCE_PARSED status, 114 PARTIAL and 35 RAW_ONLY.
These are parser-assigned statuses, **not independently verified accuracy**.
The original per-file manifest and raw files remain private/ignored under
`.cache/commercial_security_20261014/`.

A subsequent detailed structural diagnostic over the Check Point/PAN-OS
files was blocked twice by OpenAI security-state determination, including an
identical retry after a live session check. No alternate tool, path, host or
read/evaluation route was used for that blocked operation. Consequently the
commercial field-accurate baseline, candidate comparison and Check Point
bracket-pair grammar remain incomplete. The tests in this change use existing
qualified WAF/Suricata inputs and self-authored controls, NOT those blocked
commercial inputs. No hidden or excluded commercial records are successes.

## Reproduce and next action

```bash
python3 -m unittest discover -s poc/vendor_engine -p 'test_security_envelopes.py' -v
python3 -m unittest discover -s poc/vendor_engine -p 'test_security_extension_limits.py' -v
python3 poc/vendor_engine/benchmark_security_envelopes.py
PYTHONPATH=poc/vendor_engine/.cache/drain_deps:poc/vendor_engine/.cache/logparser:poc/vendor_engine/.cache/logparser_deps python3 -m unittest discover -s poc/vendor_engine -p 'test_*.py' -q
```

Next: under newly verified conditions retry the same blocked commercial
source diagnostic, then independently evaluate exact fields/positions and
implement only confirmed Check Point/PAN-OS boundary failures. Preserve
unlabeled CSV positions and malformed original records. No further prose,
Dictionary or masking work takes precedence. No merge/release is authorized.

## Primary format references

- BSD Syslog HEADER/MSG distinction: https://www.rfc-editor.org/rfc/rfc3164.html#section-4.1.2
- Manufacturer tagless CEF example: https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference/311596/ips-log-support-for-cef
- Check Point CEF/LEEF mapping: https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter-Appendix.htm

These references describe syntax; no external literal sample records or
licensed parser templates are redistributed in this commit.

## Exact candidate regression qualification

The final source code passed **215/215 tests, zero skips/failures/errors**,
including the previously skipped WAF/Suricata source regression and the
established 256-event vendor-source corpus. The source hashes match the
benchmark and full-suite execution; see security-envelope-validation.json.
The separately blocked new commercial diagnostic was not part of that suite
and is not represented as passed. Web CI remains an independent gate.
