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

| Source family | Before this round | After this round |
| --- | ---: | ---: |
| Juniper SRX | 72 / 105 | 72 / 105 |
| Check Point | 109 / 111 | 109 / 111 |
| Sophos XG | 232 / 271 | 232 / 271 |
| CrowdStrike Falcon | 38 / 84 | 84 / 84 |
| **Total** | **451 / 571 (79.0%)** | **497 / 571 (87.0%)** |

These counts represent structural success only. They do not establish the
accuracy of semantic field naming, user-authored parser generation,
Stellar target artifacts, or runtime integration.

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
npx vite-node scripts/poc/runFreshVendorHoldout.ts
npx vitest run src/prettyJsonSingle.poc.test.ts src/securityInputPipeline.poc.test.ts src/lineEventStream.poc.test.ts src/jsonBatch.poc.test.ts src/ndjsonStream.poc.test.ts
npm test
npm run typecheck
npm run build
```

An offline rerun can set `PARSER_STUDIO_FRESH_HOLDOUT_DIR` to an already
verified private fixture directory. The runner requires 571 / 497,
84 / 84 CrowdStrike, 3,092 / 3,092 scalar occurrences, and zero accepted
negative controls. It exits nonzero on qualification drift.

## Residuals and next research

There are 74 unresolved structural failures: Juniper 33, Check Point 2,
and Sophos 39. They require classification by envelope, structured data,
source-body grammar, and intentional safe abstention **before** attempting
any narrower source-family rule. Do not patch them with a larger full-line
vendor regex or permit a known-source failure to downgrade to generic success.

The product worktree remains untouched. Product adoption, actual parser
creation, normalization, browser user E2E, and native Stellar compatibility
are separate acceptance gates.
