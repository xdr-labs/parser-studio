# Juniper SRX Junos Bracket / Syslog Strictness PoC (2026-10-17)

## Scope and reproducible source

This work is isolated to branch `poc/syslog-envelope-foundation-20261016`
in `xdr-labs/parser-studio`. It has **not** been merged into the active product
worktree, deployed, or verified against a Stellar target parser/DP/sensor.

Evaluation inputs are the same pinned public Elastic Integrations files
(`ee918d03f4a90dacd32673546c64a633308796ef`), with per-file SHA-256
and byte counts in `scripts/poc/freshVendorHoldout.manifest.json`.
All raw logs, derived field oracles and corrupted variants are stored privately
in `~/.local/state/parserstudio-fresh-vendor-holdout-20261016`, not in Git.

## Motivation and root cause

The original 105-event Juniper SRX evaluation was **72/105** structurally
parsed. After introducing source-qualified Junos bracket recognition, an
intermediate candidate reached **86/105**. An independent negative suite
revealed **121/414 malformed Junos variants were incorrectly accepted**:
55 duplicate parameters were downgraded to the generic RFC5424 structured-data
path; 66 truncated bracket records were downgraded to PRI-based `space_kv`.

These were **false positives**, not verified field extraction. In the qualified
candidate:

- Junos-specific structured-data validation rejects duplicate key arrays
  instead of accepting the generic RFC5424 path.
- A PRI+generic KV fallback refuses input claiming `[junos@` structure,
  requiring the source grammar to validate the full record.
- The source-specific body parser remains bounded, recognizes valid bracketed
  `key="value"` attributes and handles optional unzoned timestamp only when
  the source has a qualified Junos event shape. Unknown timezone is explicit
  (`timezone_missing=true`), never guessed.
- Normalized attribute keys reject duplicate normalization collisions,
  unsafe keys, unsupported escape sequences, and malformed quotation.
- Plain RFC5424 prose and non-certifiable smart-quoted or mixed-text fragments
  remain unstructured rather than being counted as success.

Five earlier generic-only Juniper successes were removed from the denominator
of accepted events through fail-closed validation; all 69 independently
validated Junos field sets remain intact.

## Structural and source-fidelity results

| Metric | Before Junos work | Intermediate, permissive | Qualified |
| --- | ---: | ---: | ---: |
| Juniper structurally parsed | 72/105 | 86/105 | **81/105 (77.1%)** |
| Qualified Junos SD attribute oracles | not measured | 69/69 exact | **69/69 exact** |
| Malformed Junos variants accepted | not measured | 121/414 | **0/414** |
| Juniper generic-only structural successes | not separately gated | 17 | **12** |
| Juniper free-text syslog safely left unstructured | not separately gated | 13 | **13** |
| Four-vendor corpus structurally parsed | 521/571 | 535/571 | **530/571 (92.8%)** |

`scripts/poc/createJunosBracketOracle.py` is an independent Python tokenizer:
69/105 records contain a qualified `[junos@` attribute sequence with a
complete, valid bracket and quote structure. For **69/69**, all attribute
names and values from the TypeScript source-specific extraction exactly match
the Python oracle, with **0** missing and **0** mismatched. All 81 successful
raw event strings were preserved unchanged.

The 36/105 records without an independent Junos bracket oracle include
regular free text, malformed structure and other source-body dialects. Their
generic structural results are **not** claimed to be value-level accurate.

## Negative controls

The independent Python script generates six deterministic mutations per
69 source records: impossible calendar date, invalid PRI, duplicate attribute,
unsafe attribute, unclosed quotation, and missing closing bracket. All
**414/414** are rejected. Invalid known-source records must not be reclassified
as successful generic KV or generic structured-data parsing.

This is a regression control on defined mutations, not comprehensive fuzzing
or proof of every possible Junos log shape.

## Reproduction

From the isolated PoC worktree:

```sh
python3 scripts/poc/fetchFreshVendorHoldout.py
python3 scripts/poc/createJunosBracketOracle.py
npx vite-node scripts/poc/runJunosBracketOracle.ts
npx vite-node scripts/poc/runFreshVendorHoldout.ts
npx vite-node scripts/poc/runSophosKvOracle.ts
npx vite-node scripts/poc/runPublicSecurityHoldout.ts
npx vitest run src/junosBracketFallback.poc.test.ts
npm test
npm run typecheck
npm run build
```

Use `PARSER_STUDIO_FRESH_HOLDOUT_DIR` to run both Juniper and four-vendor
oracles offline against an already pinned, private corpus. Runners fail
nonzero if exact-value, negative-control or measured-count gates drift.

## Remaining research and acceptance boundary

The four-vendor test still contains **41** safe abstentions:
Juniper 24, Sophos 15, Check Point 2. Two Check Point samples use malformed
RFC5424 timezones and should remain rejected, rather than weakening the
common envelope. Further Juniper and Sophos repair requires independently
verifiable field-level oracles for new source dialects, not a universal regex
or arbitrary generic fallback. Field semantics, normalization, parser-file
generation, browser Full User E2E, and target runtime remain outside PoC
acceptance.

The 571-event dataset was used to tune this candidate. **92.8% is in-sample
qualification on these public fixtures**, not an unbiased future
generalization estimate.
