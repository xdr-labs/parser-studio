# Fresh Original SonicWall RFC3164 KV Source Fidelity Holdout — 2026-10-17

**Scope:** independent PoC only, stacked on the Fortinet third-party bare-KV evidence in Draft PR #35. Zero product/parser implementation changes; no main, consumer branch, DP, sensor, release or deployment operations.

## Source provenance and frozen lexical reference

The independent original third-party source was pinned **before** running the unchanged product parser:

- Public source: https://github.com/santiago-bassett/Alienvault-Demo_scripts/blob/bc8c137fe913ba43a4345850206565b028e8fef8/sonicwall/sonicwall.log.orig
- Exact upstream revision: `bc8c137fe913ba43a4345850206565b028e8fef8`
- Original `sonicwall.log.orig` SHA-256: `949f3d75de0033e64a10ba5be46d156cc1157cc6a7927eded24cc9d605431fd9` (13,709 bytes).
- Original source: **61 distinct yearless RFC3164 records**, all recognized as possible syslog envelopes by independent grammar. Of these, only **59 original events** have a complete, safe, independently qualified KV field list: **759 original name/value fields** across **12 distinct ordered key schemas**. Other 2 are **UNSCORABLE** due to ambiguous KV quotation boundaries, and are not a precision/recall denominator.
- Each original event hash has **zero overlap** with both the earlier Elastic 222-event frozen set and the new Fortinet 1,002-event source set.
- The original third-party `sonicwall.log.orig` is scored, **not** the separate preprocessed/cleaned `sonicwall.log` from the same public repo.
- Private source/oracle: `~/.local/state/parserstudio-fresh-sonicwall-20261017/`, mode 0700 directory / mode 0600 source and frozen Oracle files. Neither original logs nor source values are committed or printed.

The Python independent source scanner (`createFreshSonicwallSyslogOracle.py`) reuses the previously reviewed lexical RFC3164 field reference grammar, **not** product parsing. It independently refuses ambiguous quotes, unkeyed fragments, unsafe keys, duplicates/canonical collisions, and malformed headers. The reference output is immutable once created. No RFC3164 year/timezone, device semantic identity or normalized field meaning is invented.

## Actual unchanged product source-KV projection

Product parser: `parseSecurityInput(originalRaw)`, exactly one event, and **only** the predeclared `event.fields.generic.kv` field name/value map. No fallbacks to raw string, source body, atomized tokens or inferred semantic names.

| Independent check | Measured |
| --- | ---: |
| Total source original records | 61 |
| Complete independently qualified originals | **59** |
| Source KV tokens in qualified originals | **759** |
| Product KV candidate tokens on qualified originals | **759** |
| Exact source name+value matches (TP) | **759** |
| Wrong values at expected names | **0** |
| Missing expected names | **0** |
| Unexpected extracted names | **0** |
| FP/FN | **0/0** |
| Whole qualified events exact | **59/59** |
| Qualified event raw source preserved | **59/59** |
| Qualified parser structural success | **59/59** |
| Qualified original field Precision / Recall / F1 | **100% / 100% / 100%** |
| Original unscorable events | **2/61** |
| Product structural acceptances on those unscorable events | **2/2 (UNVERIFIED, not counted exact)** |

All 59 qualified source events produce `generic.mode=space_kv`. The two source-ambiguous events are accepted at the structural parser API level; this **does not** independently verify their original KV boundaries or source values. They remain UNSCORABLE and should not be reported as source-complete. An independent lexical mismatch or unavailable field reference remains a fail-closed qualification barrier, regardless of a parser `ok:true` result.

The fixtures are third-party original public sample logs, **not independently vendor-certified raw production telemetry**. This PoC does not verify SonicWall semantic normalizations, native Fluentd/Ruby/CONF targets, Stellar mapping, DP delivery or product acceptance. The unrelated Fortinet escaped-string disagreement in PR #34 stays unresolved and counted FP+FN, without global accuracy claims.

## Reproduction (only on isolated dev-atlas PoC worktree)

```bash
python3 scripts/poc/createFreshSonicwallSyslogOracle.py
python3 -m unittest discover -s scripts/poc -p 'testFreshSonicwallSyslogOracle.py' -v
node_modules/.bin/vite-node scripts/poc/runFreshSonicwallSyslogKvFidelity.ts
npm run typecheck
npm run build
```

Before scoring, pin the original outside Git to the exact SHA above. The local score runner checks the reference's source SHA, expected qualified/unscorable denominators, and per-record SHA. Source values and unknown fields are never printed.

**Next:** investigate separately how the two source-ambiguous messages are handled at the product's trust/qualification boundary; specifically ensure that structural acceptances cannot be promoted to VERIFIED source-fidelity without an independent source oracle. Any production parser changes require a separate candidate, original regression gates and independent holdout approval.
