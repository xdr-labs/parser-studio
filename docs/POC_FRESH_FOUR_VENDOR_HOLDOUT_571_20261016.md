# Fresh Four-Vendor Public Holdout — 571 Logical Security Events (2026-10-16)

## Research boundary

This is an independent Parser Studio engine PoC on
`poc/syslog-envelope-foundation-20261016`. It does not modify or deploy
the active product branch, credentials, Stellar DP, sensor, or any production target.

The source is 58 published Elastic Integrations pipeline fixture files, pinned
to upstream commit `ee918d03f4a90dacd32673546c64a633308796ef`.
Exact fixture paths, byte counts, physical line counts, and SHA-256 hashes are
in `scripts/poc/freshVendorHoldout.manifest.json`.
Raw records and derivatives are written only to a private local directory
(`~/.local/state/parserstudio-fresh-vendor-holdout-20261016/`, mode 0700;
files mode 0600). No customer data or raw fixture bytes are committed.

## Event framing and scope

- Juniper SRX: 7 files / 105 physical-line security events.
- Check Point: 8 files / 111 physical-line security events.
- Sophos XG: 17 files / 271 physical-line security events.
- CrowdStrike Falcon: 26 fixture files. Pretty-printed or adjacent JSON
  documents were decoded by a standard JSON decoder into 84 logical
  object/array records. A single scalar `400` fixture was classified as a
  **known-invalid control**, not a security event.
- Total: 58 source files, 571 logical security events, one intentionally
  invalid JSON scalar.

Do not interpret the 1,651 CrowdStrike physical source lines as 1,651 events.
Whitespace and pretty-printing do not change JSON document identity.
The independent JSON scalar check compares the source values as a multiset
against all emitted event fields; it does **not** certify field-path semantics,
exact original whitespace, or Stellar normalization.

## True baseline and candidate

| Source family | Initial baseline | After JSON fix | After Sophos validation | After Junos strictness | After certified Junos bare-bracket |
| --- | ---: | ---: | ---: | ---: | ---: |
| Juniper SRX | 72 / 105 | 72 / 105 | 72 / 105 | 81 / 105 | **86 / 105** |
| Check Point | 109 / 111 | 109 / 111 | 109 / 111 | 109 / 111 | 109 / 111 |
| Sophos XG | 232 / 271 | 232 / 271 | 256 / 271 | 256 / 271 | 256 / 271 |
| CrowdStrike Falcon | 38 / 84 | 84 / 84 | 84 / 84 | 84 / 84 | 84 / 84 |
| **Total** | **451 / 571 (79.0%)** | **497 / 571 (87.0%)** | **521 / 571 (91.2%)** | **530 / 571 (92.8%)** | **535 / 571 (93.7%)** |

These counts represent structural success only. They do not establish the
accuracy of semantic field naming, user-authored parser generation,
Stellar target artifacts, or runtime integration. The final 86 Juniper
structural successes comprise **69** independently source-exact `junos_sd`,
**5** independently source-exact `juniper_flow_kv` bare-bracket events, and
**12** remaining generic-only events without source-field fidelity evidence.
The new bare-bracket class retains original source raws **5/5** and rejects
**45/45** invalid mutations; the original `junos@` oracle remains **69/69**
source-exact and rejects **414/414** invalid mutations. The corpus was used
for parser tuning, so these are *in-sample* qualifications, not fresh unbiased
out-of-sample estimates.

At first evaluation the 571 logical events were new to this PoC. The input
layer was then corrected using the same corpus, so the after-result is
**a qualification result on a now-tuned corpus**, not an unbiased future
generalization estimate.

## Root cause and source-independent correction

The 46 previously unparsed CrowdStrike records were complete, well-formed
JSON objects spread across several physical lines. The event breaker
correctly did not claim an array, NDJSON stream, or RFC 7464 sequence,
but the fallback attempted to split each line into a separate security event.
The opening brace alone could never pass single-event parsing.

The correction in `src/securityInputPipeline.ts` attempts a complete bounded
single JSON object before heterogeneous line-event fallback, **only after**
stronger framing owners decline the input. It reuses the existing
`parseJsonObjectBatch` validation through the qualified single-event
extractor. No vendor-specific regex or relaxed JSON parser was introduced.

The new deterministic regression
`src/prettyJsonSingle.poc.test.ts` covers multiline LF and CRLF JSON,
exact source preservation, malformed JSON, unsafe keys, and invalid mixed
event boundaries.

## Value preservation and negative controls

- CrowdStrike: 84 / 84 structurally parsed after the correction.
- All 3,092 scalar value occurrences from the 84 source JSON documents
  were present in emitted structured event fields.
- 168 controlled corrupted JSON variants (truncated and unsafe-key
  injections): 0 accepted.
- One known-invalid scalar JSON fixture: rejected.
- Existing JSON batch, NDJSON, Syslog, and line-stream behaviors remain
  separate and retain their strict claims.

These malformed cases are bounded regression controls, not a comprehensive
security or fuzzing guarantee.

## Reproduction

Run from this PoC worktree:

```sh
python3 scripts/poc/fetchFreshVendorHoldout.py
python3 scripts/poc/createSophosKvOracle.py
python3 scripts/poc/createJunosBracketOracle.py
python3 scripts/poc/createJunosBareFlowOracle.py
npx vite-node scripts/poc/runFreshVendorHoldout.ts
npx vite-node scripts/poc/runSophosKvOracle.ts
npx vite-node scripts/poc/runJunosBracketOracle.ts
npx vite-node scripts/poc/runJunosBareFlowOracle.ts
npx vitest run src/prettyJsonSingle.poc.test.ts src/junosBracketFallback.poc.test.ts src/junosBareFlow.poc.test.ts src/securityInputPipeline.poc.test.ts
npm test
npm run typecheck
npm run build
```

An offline rerun can set `PARSER_STUDIO_FRESH_HOLDOUT_DIR` to an already
verified private fixture directory. The runner requires 535 / 571,
86 / 105 Juniper, 109 / 111 Check Point, 256 / 271 Sophos, 84 / 84 CrowdStrike,
3,092 / 3,092 CrowdStrike scalar occurrences, and zero accepted JSON negatives.
The separate source-fidelity oracles are documented in
`docs/POC_SOPHOS_XG_OPTIONAL_EMPTY_KV_20261016.md` and
`docs/POC_JUNIPER_SRX_JUNOS_BRACKET_20261017.md`.
Every runner exits nonzero on qualification drift.

## Residual classification and next research

There are 74 unresolved structural failures: **Juniper 33, Check Point 2,
Sophos 39**. A separate, read-only classification using the existing envelope
parser found:

- 24 / 74 had a recognizable outer Syslog envelope but an unsupported or
  intentionally unstructured residual body.
- 50 / 74 were not recognized as a Syslog envelope; many are source-native
  KV records, which are not necessarily supposed to have Syslog headers.
- 61 / 74 contain at least three textual `key=value` candidates, suggesting
  a possible bounded body-grammar path. This is not validation that their
  quoting, timestamps, or source identifiers are correct.
- The two Check Point failures show the malformed time-zone token
  `2023-01-13T10:10:16--5:00` (or the same shape with another clock);
  rejecting them is preferable to weakening the RFC 5424 timestamp boundary.
- Some Juniper failures include RFC 5424-like headers without a qualified
  time zone, whereas others have valid envelopes and free-text messages.
  Analyze these separately before proposing new source-body grammar.
- Sophos XG failures are predominantly standalone `device="SFW"`
  KV records whose optional fields or source identifiers differ from
  the reviewed leaf. Do not infer source correctness from the mere number
  of equals signs.

The initial 24/50/61 classification was measured before Sophos hardening.
After Sophos work there were 50 residuals. Strict `junos@` qualification
left **41** structural failures (Juniper 24, Check Point 2, Sophos 15):
24 recognized-envelope, 17 unrecognized-envelope, and 28 with at least
three textual KV candidates.

The independently qualified bare-bracket `RT_FLOW` grammar extracts five
additional source events and leaves **36** residual failures (Juniper 19,
Check Point 2, Sophos 15): **23** with a recognized Syslog envelope, **13**
without, and **23** containing at least three textual KV candidates.
The current qualification runner asserts 23/13/23, and independent Python
oracles verify the two Juniper source dialects separately instead of treating
loose generic extraction as exact.

Do not patch the residuals with a larger full-line vendor regex or permit
a known-source failure to downgrade to generic success. Additional unseen
holdout data and independently reviewed expected source values are required
before claiming a generalized improvement.

The product worktree remains untouched. Product adoption, actual parser
creation, normalization, browser user E2E, and native Stellar compatibility
are separate acceptance gates.

## Post-qualification audit of the 36 remaining source records (2026-10-17)

A read-only analysis of **all 36** unsuccessful input records at the
independently qualified bare-bracket HEAD `37b5ea8f40a676a427011513241f8ab13e3c460c`
found the following disjoint classes. The analysis consulted only the pinned
private source corpus; raw source lines were not added to Git.

| Family | Residual class | Records | Decision |
| --- | --- | ---: | --- |
| Juniper SRX | System free-text without a source-certified structured body | 13 | Leave unstructured; no invented attributes |
| Juniper SRX | `junos@` attribute segments with typographic smart quotes rather than strict ASCII quotation (5 flow, 1 ATP) | 6 | Leave unstructured until the source quoting dialect is independently certified |
| Sophos XG | Cannot tokenize a complete source KV sequence: non-KV segments/field-boundary ambiguity | 12 | Preserve raw; require source grammar evidence |
| Sophos XG | Unterminated quoted source value | 2 | Reject fail-closed |
| Sophos XG | Quote unexpectedly embedded in a bare token | 1 | Reject fail-closed |
| Check Point | RFC5424 timestamp containing the invalid timezone `--5:00` | 2 | Reject invalid timestamp |
| **Total** | | **36** | |

The **15 Sophos residual records** are not independently source-field
certifiable with the existing strict Python KV tokenizer. This does *not*
prove every record is inherently invalid; some could require an additional,
independently documented vendor dialect. The six Juniper smart-quoted records
likewise cannot be promoted by simply stripping Unicode punctuation.
An unsupported original is not an extracted-field correctness success.

`src/residualMalformedSafety.poc.test.ts` adds synthetic adversarial controls
for Junos smart-quoted values, malformed Sophos quotation, invalid Check Point
timezone and Juniper prose, alongside a valid ASCII-quoted Junos control.
These guards protect the qualified source parser against generic-downgrade
false positives. No extra accepted event is claimed from this audit.

**Next safe research gate:** obtain credible source-level expectations for a
currently unsupported but complete vendor dialect, define an independent
field/value oracle plus malformed controls, then evaluate it in the isolated
PoC before changing the structural acceptance counts. Keep all three
dimensions separate: structural extraction, exact source-field preservation
and semantic/target mapping.
