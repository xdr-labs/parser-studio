# Phase 3: unmapped field preservation (Q3-1) and FortiGate CEF — verification (2026-11-24)

Scope: Owner decision Q3-1 (keep every extracted field) and the FortiGate `CEF: 0|` grammar, PR #316, range
6e59c36..2b6602c. No main merge, no deployment, KNOWN_TEMPLATES and approval constants unchanged.

## What changed

- **Q3-1** (4a92d06, adf8d3d, 2b6602c): a parser made by the Auto Parser (`normalization.preserveUnmapped`) keeps every
  field its reader extracted that no applied mapping reads, also one the sample never showed, in the vendor namespace
  at its original path (`<vendor>.body.city`). A name another mapping writes from a different source (any event
  family), an enrichment output inside the vendor namespace (target, split targets), or a key holding a dot sends the
  field under `<vendor>.parserstudio_unmapped.<path>`; a mapping may not write that reserved object. Strings are kept
  unchanged; numbers, booleans, arrays and objects as the canonical string mapping renders them (same text in the
  browser and in Ruby); missing values (null, '', 'N/A', '-', blank) are not written, as for mapped fields. Generic
  Structural parsers already keep every field in `parserstudio_source`. Projects without the flag compile unchanged;
  the exact project import keeps it.
- **FortiGate CEF** (7874969, adf8d3d): exactly one space between `CEF:` and the version is CEF (browser, loss
  accounting, Generic Structural, shared grammar contract, Python Multi-Pass, generated Ruby). An RFC 3164 TAG never
  starts a CEF/LEEF claim, and the claim allows SP/TAB around the colon, so a malformed claim is declined instead of
  being read as generic text.

## Measurements (same corpus and scorer as before: Chromium journeys, downloaded Ruby on Ruby 2.4.9)

| Metric | T25 (bdf76cd) | T29 (288db7d) |
|---|---|---|
| Official mapping, downloaded golden cases | 171/182 | 171/182 |
| Official mapping, every golden case (UI-stopped = 0) | 171/242 | 171/242 |
| Original values, downloaded cases | 177/179 | **179/179** |
| Original values, every golden case | 177/239 | 179/239 |
| Event preservation | 99/99 | 99/99 |
| False FULL | 2/64 | **0/64** |
| Holdout correct / wrong | 102 / 0 | 102 / 0 |

Only fortinet_cef changed (values 4/6 → 6/6, the RFC 3164 hostname now mapped); public, Issue #315 and Phase 3 sets
unchanged. 2b6602c differs from 288db7d only in enrichment-target reservation, the nested path kind, project import
and a reserved-name check, which no corpus journey uses.

Q3-1 Chromium E2E at 2b6602c (q31e2e: sample through the Chromium journey, the downloaded Ruby parser on Ruby 2.4.9
with runtime lines that add keys, in order and reversed; every key and value of every runtime line checked in its own
record, no error record, no value of another line): kv_newkey, mixed_root_body (RFC 3164 KV + JSON, root vs body.*),
json_nested_utf8 (arrays, nested objects, non-ASCII names and values, escapes, a key named like a mapped vendor
field), rfc5424_header_body (a body key named like a header field), fortinet_cef (golden lines + a runtime key):
10/10 runs, 0 problems.

Unit and integration: Vitest 2414 passed; Python unit (incl. tests/test_fortinet_cef_space_20261124.py); backend
suite 14 known failures (owner template approvals, environment-only tests); Ruby 3.2 and Ruby 2.4.9 give the same
records for backend/test/unmapped-fields-q31.test.ts and the forwarder-hops test (P1 now verified on Ruby 2.4.9);
semantic oracles, mutants (TS 32/32, family 18/18), AST census 90.36%; Playwright at 288db7d all passed. CI at 2b6602c:
browser shards 6/6, native, Ruby 2.4.9 UDP reception pass; web-quality fails only on the two owner-approval tests.

## Independent audits (separate executors) after 6e59c36

| Audit | Findings | Resolution |
|---|---|---|
| 7874969 | A-1 enrichment target collision (MAJOR), A-2 `<PRI>… CEF: 0|` read with tag CEF (MAJOR), A-3 malformed CEF claims FULL in Generic Structural (MAJOR, older), A-4 dotted key twice, A-5 name per family, A-6 LEEF claim change | A-1..A-5 fixed (adf8d3d); A-6 documented |
| adf8d3d | F-1 split targets (MAJOR), F-2 nested kind swallowed a literal key (MAJOR), F-3 project import (MAJOR), F-4 Python GS claim inside RFC 5424 (MINOR), F-5 reserved name (MINOR) | F-1, F-2, F-3, F-5 fixed (2b6602c); F-4 open |

Every fixed finding has a repro test that fails before the fix (src/guided/unmappedFieldsAudit4.test.ts,
src/guided/unmappedFieldsQ31.test.ts, src/grammar/fortinetCefSpace20261124.test.ts). 2b6602c has not had an audit
of its own.

## Templates (approval pending, constants unchanged)

- Ruby template set: `cefa3150928a9a108cd7ae668bf8cfcf475bf24d922f9ec168ae0d00a94894d1`
- POC template: `1ae4b12dad98ca424aa9efff590f4d308924cac162aaae6ed0e3d969bfd588e2`

These replace b031810f…c8c and 2362d0c6…3e64.

## Remaining

1. F-4: the Python Multi-Pass preview reads `CEF :0|` inside an RFC 5424 envelope as parsed (browser and Ruby decline).
2. Number spelling: a non-string value keeps its value, not its spelling (`1.0` → "1", `1e2` → "100"), the same in browser and Ruby.
3. `<189>CEF: 0|…` with only a PRI: MIXED_OR_UNKNOWN in the browser (older; Python reads it); FortiGate wire format NOT VERIFIED.
4. Golden mapping stays 171/182: Meraki IDS `ip:port` endpoints (4), mixed_types ports without TCP/UDP evidence, r2_invalid_types.
5. 14 golden cases still stop at Review Fields (ChatGPT or user decision needed); no new automatic grammar was added for them.
6. Real Stellar Cyber installation tests are the owner's.
