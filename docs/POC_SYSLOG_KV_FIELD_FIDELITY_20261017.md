# Independent Syslog/KV Source Field Fidelity — October 17, 2026

**Scope:** PoC evidence only, on the isolated `poc/syslog-kv-field-fidelity-20261017` branch. No product parser, main branch, DP, sensor, production or deployment changes.

## Evidence and fixed denominators

The pre-existing, private Python source oracle is `scripts/poc/createSyslogKvFieldOracle.py`. It independently reads the frozen Elastic Integrations public-source record store, rather than trusting the product parser's extracted fields. The private raw corpus and expected values remain outside Git in `~/.local/state/parserstudio-lossless-blind-20261017/`; neither logs nor field-value pairs are included in this report.

- Source record manifest SHA-256: `153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32`
- Upstream pinned revision: `ee918d03f4a90dacd32673546c64a633308796ef`
- Frozen corpus: 222 records, original parser baseline 217/222 structurally accepted and 217/217 source raws retained.
- Independently complete, non-JSON KV references: **185 records / 4,160 original fields**.
- SonicWall: 178 records / 3,869 fields; Fortinet: 7 records / 291 fields.
- Explicitly **unscored here**: 22 JSON source events (separate PR #33 evidence) and 15 Cisco ASA prose events. No fabricated KV names, timestamps, years or timezones.

## Comparison to the actual, unchanged product output

The scorer uses only the existing fixed parser field contracts: `event.fields.generic.kv` for SonicWall, and `event.fields.fortinet.fields` for Fortinet. It does not infer values from `body`, translate semantic names, or accept guessed mappings.

| Metric | SonicWall | Fortinet | Total |
| --- | ---: | ---: | ---: |
| Source original name/value tokens | 3,869 | 291 | **4,160** |
| Parser contract name/value candidates | 3,869 | 291 | **4,160** |
| Exact original name and value (TP) | 3,869 | 290 | **4,159** |
| Wrong value at correct name | 0 | 1 | **1** |
| Missing source names | 0 | 0 | **0** |
| Additional unexpected names | 0 | 0 | **0** |
| False positives (wrong + unexpected) | 0 | 1 | **1** |
| False negatives (wrong + missing) | 0 | 1 | **1** |
| Complete exact KV record | 178/178 | 6/7 | **184/185** |
| Same-source event raw retained | 178/178 | 7/7 | **185/185** |

**Exact field-name and value precision = 4,159 / 4,160 = 99.9759615%. Exact recall = 4,159 / 4,160 = 99.9759615%; F1 = 99.9759615%.** Wrong values count as both FP and FN. Both source and candidate denominators are explicit; exact *name sets* (185/185) do not imply exact *values* (184/185 events).

The single Fortinet value disagreement is an **escaped-character interpretation difference**: the independent lexical reference preserves an escape that the existing strict KV parser consumes. This is reported as a real mismatch, **not repaired or silently discarded**. Vendor semantics are not independently authenticated; distinguishing literal escape preservation from vendor-authorized decoding requires further source evidence and a genuinely unseen field-scorable holdout.

## Reproduction / safety gates

From the isolated worktree on dev-atlas:

```bash
python3 scripts/poc/createSyslogKvFieldOracle.py
python3 -m unittest discover -s scripts/poc -p 'testSyslogKvFieldOracle.py' -v
node_modules/.bin/vite-node scripts/poc/runBlindSyslogKvFieldFidelity.ts
node_modules/.bin/vitest run src/poc/syslogKvFieldFidelity.test.ts
npm run typecheck
npm test
npm run build
```

The independent reference script refuses to overwrite an existing frozen oracle when content differs. The TypeScript runner requires the fixed manifest/revision, identical per-record SHA-256, exact event and field denominators, and unchanged 217/217 source-preservation baseline; the scorer rejects malformed/duplicate/colliding names and unexpected types. Synthetic negative tests cover invalid PRI, ambiguous headers, duplicate names, unsafe keys, unkeyed tokens, malformed quotation, value mismatch, spurious/missing names and wrong types. Neither runner prints original field names/values nor raw records.

**Qualification:** POST_HOC_IN_FAMILY. These source records were inspected in previous PoC work; this is a reproducible independent lexical comparison, **not** an unbiased fresh unseen vendor holdout. It does **not** certify semantic Stellar mapping, parser Ruby/CONF native execution, deployment safety, or target import. Unsupported prose remains unscored / RAW_ONLY or PARTIAL as applicable. Any future source parser modification requires the designated independent holdouts and safety regression gates; there are **no source parser modifications in this PR**.
