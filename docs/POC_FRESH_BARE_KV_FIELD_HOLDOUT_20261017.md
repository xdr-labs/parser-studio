# Independent Fresh Bare KV Source Holdout — October 17, 2026

**Lane:** separate isolated PoC, stacked on the original Syslog/KV field-fidelity PoC. No product parser, main, UI, DP, sensor, deployment, or native adapter modifications.

## Source provenance and independent pre-scoring

A separate third-party public test fixture source (not the previously studied Elastic 222-event set) was pinned and downloaded privately **before** product parser scoring:

- Upstream project: https://github.com/oelu/fg_log_parser (MIT)
- Exact pinned revision: `716cfcc3724a5765c5db21d8d76c7478cd2e7de9`
- `testlogs/fg.log`: 647 bytes, SHA-256 `e5840c439fd7445dc04eed7c67059df30168f2162d23788976023dceb39cc6e2`
- `testlogs/fg_long.log`: 171,972 bytes, SHA-256 `53250b4ecb5280a9983b5b9d065fc87b1d0bad58c81de981f81faf58fab45440`
- 1,008 physical nonblank records; 6 repeated identical records omitted before scoring.
- **1,002 distinct independently scorable bare KV records**, **11,848 original key/value tokens**; 0 original raw SHA overlaps with the earlier frozen Elastic 222 records.
- 2 records / 22 fields from `fg.log`, and 1,000 records / 11,826 fields from `fg_long.log`.

Original logs and expected key/value field pairs are immutable, private and never committed, under `~/.local/state/parserstudio-fresh-kv-20261017`. `createFreshBareKvOracle.py` uses independent Python lexical scanning without asking the product parser which fields it extracted. Qualifications include bounded input, full key/value tokens, no colliding or unsafe source keys, complete quotation, valid date/time and explicit source/destination identifiers. The stored private oracle is not automatically overwritten.

The **predeclared product projection** is exactly `parseSecurityInput(...).events[0].fields.generic.kv`. Bare date-prefixed unprofiled logs are not falsely claimed as vendor-specific, RFC3164/5424, or Stellar semantic extraction.

## Scored result

| Metric | Result |
| --- | ---: |
| Unique eligible original events | **1,002** |
| Exact original source fields (reference denominator) | **11,848** |
| Product generic KV candidate fields | **11,848** |
| Exact field name + string value (TP) | **11,848** |
| False positive | **0** |
| False negative | **0** |
| Missing original names | **0** |
| Unexpected names | **0** |
| Wrong original values | **0** |
| Exact original whole-KV events | **1,002/1,002** |
| Raw events retained | **1,002/1,002** |
| Precision / recall / F1 | **100% / 100% / 100%** |

The candidate extractor consistently reported `space_kv` for these 1,002 records. This newly sourced test suite is a **third-party fixture holdout**, not sampled production telemetry, and appears to exercise a comparatively narrow bare space-delimited grammar. A high number of records does not imply high independent vendor or version diversity.

The preceding **Fortinet escape-semantics disagreement on one Elastic record remains unresolved** (PR #34). These fresh unescaped/ordinary examples do not adjudicate vendor-authorized escape decoding. This result cannot be pooled into a claimed cross-vendor accuracy rate or used to mark a product parser, native target or Stellar field mapping VERIFIED.

## Reproduction

```bash
python3 scripts/poc/createFreshBareKvOracle.py
python3 -m unittest discover -s scripts/poc -p 'testFreshBareKvOracle.py' -v
node_modules/.bin/vite-node scripts/poc/runFreshBareKvFieldFidelity.ts
npm run typecheck
npm test
npm run build
```

The two upstream files must first be saved at the exact pinned hashes in the private directory. This PoC does not store or print them. The frozen Oracle must be generated and verified before the product runner; scorer refuses corpus changes, source hash mismatches or denominator drift, and counts wrong values as both FP and FN.

**Qualification:** SOURCE_LEXICAL_EXACT on a fresh third-party fixture subset only; NOT_CERTIFIED for manufacturer semantic interpretation, native Fluentd/Ruby/CONF, Stellar Dictionary normalization, DP import, or production generalization. Unsupported prose and ambiguous forms stay abstained from exact-source claims.
