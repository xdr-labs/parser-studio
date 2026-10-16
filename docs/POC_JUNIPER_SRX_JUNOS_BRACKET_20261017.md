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

Five Juniper bare-bracket flow events that were previously removed as
unverified generic-only successes are now accepted by a *source-qualified*
`RT_FLOW` body grammar, not by reopening the permissive fallback. They use
`[source-address="..." source-port="..." destination-address="..."
destination-port="..." ...]` rather than `[junos@...]`.
The grammar requires valid source and destination IPs and ports, bounded
quoting, unique safe attribute names, and a qualified Syslog envelope.
The other 12 generic-only successes remain unverified at source-field level.
All 69 independently validated `[junos@]` field sets remain intact.

## Structural and source-fidelity results

| Metric | Before Junos work | Intermediate, permissive | Qualified strict `junos@` | Qualified bare-bracket addition |
| --- | ---: | ---: | ---: | ---: |
| Juniper structurally parsed | 72/105 | 86/105 | 81/105 | **86/105 (81.9%)** |
| Qualified `junos@` attribute oracles | not measured | 69/69 exact | 69/69 exact | **69/69 exact** |
| Qualified bare-bracket attribute oracles | not measured | not measured | not measured | **5/5 exact** |
| Malformed `junos@` variants accepted | not measured | 121/414 | 0/414 | **0/414** |
| Malformed bare-bracket variants accepted | not measured | not measured | not measured | **0/45** |
| Juniper source-specific bare-bracket successes | not measured | unqualified | 0 | **5** |
| Juniper generic-only structural successes | not separately gated | 17 | 12 | **12** |
| Juniper free-text syslog safely left unstructured | not separately gated | 13 | 13 | **13** |
| Four-vendor corpus structurally parsed | 521/571 | 535/571 | 530/571 | **535/571 (93.7%)** |

`scripts/poc/createJunosBracketOracle.py` is an independent Python tokenizer:
69/105 records contain a qualified `[junos@` attribute sequence with a
complete, valid bracket and quote structure. For **69/69**, all attribute
names and values from the TypeScript source-specific extraction exactly match
the Python oracle, with **0** missing and **0** mismatched. A separate,
independent Python bare-bracket oracle verifies all attribute names and values
for the five original `test-flow.log#26/#27/#28/#29/#31` records: **5/5 exact**,
**0** missing, **0** mismatched. All **86/86** structurally successful Juniper
events preserve their original raw strings.

Of the 36/105 records outside the `junos@` source oracle, five now have
independent bare-bracket source-field evidence. The other 31 include regular
free text, malformed structure and other body dialects; the 12 generic-only
structural successes are **not** claimed to be source-field accurate. Neither
oracle verifies semantic normalization or native Stellar parser compatibility.

## Negative controls

The independent Python script generates six deterministic mutations per
69 source records: impossible calendar date, invalid PRI, duplicate attribute,
unsafe attribute, unclosed quotation, and missing closing bracket. All
**414/414** are rejected. The new bare-bracket oracle generates nine controlled
mutations of each of the five source records (invalid calendar/PRI/IP/port,
duplicate or unsafe attribute, truncated or unclosed bracket, and wrong
application identifier); **45/45** are rejected, with **0** accepted. Invalid
known-source records must not be reclassified as successful generic KV or
generic structured-data parsing.

This is a regression control on defined mutations, not comprehensive fuzzing
or proof of every possible Junos log shape.

## Reproduction

From the isolated PoC worktree:

```sh
python3 scripts/poc/fetchFreshVendorHoldout.py
python3 scripts/poc/createJunosBracketOracle.py
python3 scripts/poc/createJunosBareFlowOracle.py
npx vite-node scripts/poc/runJunosBracketOracle.ts
npx vite-node scripts/poc/runJunosBareFlowOracle.ts
npx vite-node scripts/poc/runFreshVendorHoldout.ts
npx vite-node scripts/poc/runSophosKvOracle.ts
npx vite-node scripts/poc/runPublicSecurityHoldout.ts
npx vitest run src/junosBracketFallback.poc.test.ts src/junosBareFlow.poc.test.ts
npm test
npm run typecheck
npm run build
```

Use `PARSER_STUDIO_FRESH_HOLDOUT_DIR` to run both Juniper and four-vendor
oracles offline against an already pinned, private corpus. Runners fail
nonzero if exact-value, negative-control or measured-count gates drift.

## Remaining research and acceptance boundary

The four-vendor test still contains **36** safe abstentions:
Juniper 19, Sophos 15, Check Point 2. Two Check Point samples use malformed
RFC5424 timezones and should remain rejected, rather than weakening the
common envelope. Further Juniper and Sophos repair requires independently
verifiable field-level oracles for new source dialects, not a universal regex
or arbitrary generic fallback. Field semantics, normalization, parser-file
generation, browser Full User E2E, and target runtime remain outside PoC
acceptance.

The 571-event dataset was used to tune this candidate. **93.7% is in-sample
qualification on these public fixtures**, not an unbiased future
generalization estimate. Structural success, exact source-field fidelity and
semantic normalization are distinct acceptance dimensions.

## Residual source-dialect review (2026-10-17)

Among the 19 remaining Juniper records, **13** are source-native free-text
system events with no certifiable structured body; **six** are `junos@`
bracket records containing typographic smart-quoted values (five flow
examples, one ATP example), which violate the current independent
ASCII-quote tokenizer. These six cannot be called source-exact by replacing
smart quotes or letting partial KV fields rescue the event. The synthetic
Junos smart-quote guard in `src/residualMalformedSafety.poc.test.ts` covers
this fail-closed policy without committing published raw fixture lines.

The certified Juniper counts remain **86/105 structurally successful**:
69 exact `junos_sd`, five exact bare `juniper_flow_kv`, and 12 generic-only
structural successes without independent exact-value evidence. A future
source-certifiable quoting dialect requires a separately reviewed oracle
and strict negative controls before updating any pass gate.
