# Sophos XG Optional Empty KV — Source-Fidelity Qualification (2026-10-16)

## Scope and provenance

This qualified research change is confined to the independent Parser Studio
`poc/syslog-envelope-foundation-20261016` branch. It does not change the active
product worktree, any Stellar target, sensor, deployment, or release.

The source is the pinned 271-event Sophos XG subset of the 571-event public
Elastic Integrations holdout, using upstream revision
`ee918d03f4a90dacd32673546c64a633308796ef`.
The original file hashes are recorded in
`scripts/poc/freshVendorHoldout.manifest.json`.

All original fixtures, Python field-value oracles, mutations, and reports stay
in the owner-local private evaluation directory and are not committed.

## Root-cause classification

All **39** Sophos XG original structural failures were initially blocked
by the strict space-separated `key=value` scanner.

- **33** first failed at a literal empty unquoted value, e.g.
  `src_country_code=` followed by the next named field.
- **5** first failed at a bare unkeyed fragment, including source ID or
  vendor message boundaries that cannot be reconstructed reliably from the
  current record alone.
- **1** first failed at a malformed quoted value (`subject="`).

Empty optional fields are genuine field occurrences and should be retained as
empty strings, not silently discarded or assigned fabricated field values.
Broken quoting and unkeyed fragments are **not** equivalent to empty values.

## Architecture and implementation

1. `strictKeyValues` supports a bounded **opt-in**
   `allowEmptyUnquoted` policy. Default behavior remains unchanged.
   The optional mode requires a real KV key and a valid field separator,
   and still rejects duplicate/unsafe keys and malformed quoting.
2. Only the reviewed `device="SFW"` source-body grammar enables the
   optional empty-value policy. Existing Fortinet, UTM, CEF, LEEF, and
   unrelated generic parsing are not relaxed.
3. Sophos optional network and port fields may retain **literal empty**
   values in the source extraction. Every **nonempty** IP/port remains
   subject to the shared strict network token validators.
4. A strong source-shape guard prevents a rejected Sophos event from being
   reclassified as a successful loose `space_kv` extraction, including
   PRI-only Syslog wrappers. This preserves the fail-closed boundary.
5. The engine does not infer semantic source field names from generic KV
   matches or silently reassemble unkeyed device-identification fragments.

## Re-measured output

| Measure | Before change | Qualified candidate |
| --- | ---: | ---: |
| Sophos structurally parsed | 232 / 271 | **256 / 271 (94.5%)** |
| Sophos source-specific, strictly validated leafs | 119 / 271 | **150 / 271** |
| Generic-only structural matches (not source-certified) | not separately gated | **106 / 271** |
| Explicitly unparsed (including known-shape rejects) | 39 / 271 | **15 / 271** |
| All four-vendor holdout structured | 497 / 571 | **521 / 571 (91.2%)** |

A preliminary permissive candidate emitted 263/271 Sophos successes.
The adversarial audit found that **seven** of those were generic-fallback
acceptances of source-shaped records failing strict validation. The corrected
candidate deliberately excludes them; the lower numeric rate is the
more trustworthy result.

**Structural success is not semantic or value-level certification.** The
106 generic-only Sophos matches must not be counted as source-verified parser
accuracy. The original 571-event suite has now been used for tuning, so these
figures are *qualification* rather than unbiased future holdout performance.

## Independent field-value oracle

`scripts/poc/createSophosKvOracle.py` independently tokenizes the public
source records using Python code, rather than reusing the TypeScript parser.
It stores expected field names and exact string values privately:

- 271 input records.
- 151 independent full-record KV oracles were obtainable.
- 150 / 151 oracle-eligible records emitted a qualified Sophos source leaf.
- **150 / 150** qualified results matched **all** oracle field names and
  source values exactly; **0** column/value mismatches.
- **150 / 150** original complete source records were retained unchanged.
- One eligible record uses a different modern XG source layout beginning
  with `device_name/timestamp/device_model`, not the reviewed
  `device="SFW" date/time` signature. It remains generic-only and is **not**
  incorrectly certified as a Sophos-specific extraction.
- The other 120 original records could not be fully certified by this
  strict independent tokenizer; no accuracy guarantee is invented for them.

## Adversarial tests

The oracle generator created **900** controlled invalid variations across
the 150 independently recognized `device="SFW"` records:

- Impossible calendar date.
- Altered source identifier.
- Duplicate required source key.
- Unclosed quoted field.
- Invalid IPv4 address.
- Invalid TCP/UDP port.

The qualified parser rejected **900 / 900**, with **zero false acceptance**
among these defined controls. These are controlled regression cases, not
comprehensive security fuzzing.

## Reproduction

Run from the isolated PoC worktree:

```sh
python3 scripts/poc/fetchFreshVendorHoldout.py
python3 scripts/poc/createSophosKvOracle.py
npx vite-node scripts/poc/runSophosKvOracle.ts
npx vite-node scripts/poc/runFreshVendorHoldout.ts
npx vite-node scripts/poc/runPublicSecurityHoldout.ts
npx vitest run src/sophosEmptyKv.poc.test.ts src/applianceSecurityProfiles.poc.test.ts
npm test
npm run typecheck
npm run build
```

The 15 residual Sophos records, remaining Juniper/Check Point failures,
parser compilation, semantic mapping, and product UI acceptance remain
separate research/acceptance tasks. Source ambiguities must not be hidden
through generic fallback or vendor-specific full-line regex patching.
