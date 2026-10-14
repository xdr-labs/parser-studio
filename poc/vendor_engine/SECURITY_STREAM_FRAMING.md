# Security-source stream framing — engine-only PoC

## Owner priority

Ordinary security-system logs are the primary target: AWS WAF, IPS/IDS EVE,
firewall/UTM, CEF, LEEF and security Syslog/KV/CSV. Sentence-like application
logs and Loghub template mining are not the current optimization target.
Verified Stellar Dictionary mapping follows source extraction. Masking is
recognition and exact visible-source preservation only, at lowest priority.

This work is isolated on `poc/security-stream-framing-20261014`, based on
`c2f464444a7aa899bd8b251507234720e4cbdde2`, to preserve concurrent source/CEE
work and all uncommitted body-alignment research in the original worktree.
It reuses the committed `parse_security_source` and CEE adapter; it does not
replace or reimplement those field decoders.

## What is implemented

`parse_security_batch(raw)` identifies exact original record boundaries, then
passes unchanged record slices to the existing security-source parser.
It supports compact NDJSON, multiline nested JSON, adjacent JSON collections,
CEE-prefixed JSON and Syslog-wrapped JSON, alongside line-delimited CEF, LEEF,
KV and CSV. Arrays stay one source record, with original element ordering.
A leading UTF-8 BOM and inter-record whitespace have separate byte ledgers.
Every input byte belongs to exactly one record or explicit separator.

Strings containing braces, brackets, escape sequences, commas and equal signs
must not create false boundaries. Original HTTP header arrays, repeated names,
rule groups, nested matches, Unicode, nulls and empty containers remain intact.
A truncated or ambiguous JSON suffix is retained as RAW_ONLY, not guessed into
apparently successful events. A complete malformed record does not block a
subsequent well-framed valid record. Limits are explicit: default 1 MiB batch,
1,000 records, existing 128 KiB per-event limit, and bounded nesting. The source
byte ledger uses packed integers rather than per-offset Python objects.

The shared JSON decoder also rejects non-finite constants and numeric overflow
instead of publishing NaN/Infinity as verified source numbers. The 1,024-leaf
limit no longer accepts a 1,025th scalar. Empty containers do not consume scalar
leaf quota. Large exact integers and representable finite numbers retain their
original types. Out-of-range numeric records remain raw; no value is invented.

## Independent self-authored evidence

This is **synthetic structural evidence, not upstream/vendor production
accuracy and not a benchmark of the complete Parser Studio ingestion UI**.
The reference encoder records source identity, exact type/value and absolute
UTF-8 byte spans while constructing the input, before parser execution.

The baseline is explicitly physical-line splitting followed by committed
`parse_security_source` at `c2f4644`; the candidate changes record framing.

| Measure | Physical-line control | Structural framing |
| --- | ---: | ---: |
| Input streams | 96 | 96 |
| Expected original records | 216 | 216 |
| Observed records | 8,100 | 216 |
| Exact original record boundaries / trees | 60 | 216 |
| Correct original field identity/type/value/span | 1,320 | 6,036 |
| False source-field captures | 0 | 0 |
| Missing expected source-field captures | 4,716 | 0 |

All 216 self-authored records are unmasked, with zero exclusions or unassessed
synthetic records. The full JSON trees and all expected source spans agree.
`security-framing-summary.json` contains explicit family denominators and code
hashes. Separate malformed/limit tests are not counted as successful extraction
and not mixed into the positive accuracy denominator.

## External-source and safety boundary

New pinned AWS WAF and Suricata upstream test fixtures were acquired in the
original worktree's ignored `.cache/security_sources`. A subsequent local
source-evaluation request was blocked twice by OpenAI security-state
verification, including a same-tool/device/path retry after a session check.
That operation was not bypassed. These newly acquired fixtures are NOT linked
into this worktree; the upstream security-corpus regression is skipped when
its locally restricted fixture set is absent. Do not claim new upstream
accuracy from acquisition or from these synthetic tests.

The parent `c2f4644` has its own independent source/CEE evidence; it is inherited
history, not a new measurement in this stream-framing execution. Earlier
non-security research caches and the established 256-record vendor regression
remain available for permitted regression tests. No raw upstream records,
reference values or derived licensed templates are committed here.

## Reproduce

```bash
python3 poc/vendor_engine/benchmark_security_framing.py
python3 -m unittest discover -s poc/vendor_engine -p 'test_security*.py' -v
python3 -m unittest discover -s poc/vendor_engine -p 'test_benchmark_security_framing.py' -v
PYTHONPATH=poc/vendor_engine/.cache/drain_deps:poc/vendor_engine/.cache/logparser:poc/vendor_engine/.cache/logparser_deps python3 -m unittest discover -s poc/vendor_engine -p 'test_*.py' -q
```

Do not treat a skipped upstream fixture test as PASS. Browser/web CI, local
Python/source tests and actual native Ruby/CONF/DP/sensor compatibility are
separate gates. No product UI, production, credential, hosted LLM, DP, sensor,
merge or release action is part of this engine PoC.

## Primary format references

- AWS WAF log fields: https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
- AWS WAF log examples: https://docs.aws.amazon.com/waf/latest/developerguide/logging-examples.html
- Suricata EVE JSON: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- JSON syntax and number constraints: https://www.rfc-editor.org/rfc/rfc8259

These references guide structural coverage; their sample log payloads are not
copied into the self-authored regression corpus.

## Actual local test evidence

The exact candidate code completed the 204-test full suite with 201 PASS and
three skips, zero failures/errors. Two skips were resolved by linking the
already authorized existing train snapshot and running the six-test affected
module: all six PASS, including both previously skipped tests. No code changed
between those runs. Final unique qualification is **203 PASS, one upstream
security-corpus test SKIPPED**. The blocked new corpus was not linked/read.
This is not 204/204 PASS. Evidence hashes are in
`security-stream-validation.json`.
