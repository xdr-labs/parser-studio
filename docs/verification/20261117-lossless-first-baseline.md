# LF-0 baseline census — 2026-11-17

This is an isolated experiment checkout at baseline `1b14cf0d70602788ac0cd73521eee696a45c0e51`.
The figures below describe repository behavior and the checked test corpus; they are not vendor-wide accuracy claims.

## Independent status dimensions

| Dimension | Existing evidence | Meaning |
|---|---|---|
| Original event retained | `SuiteResult.events` retains each framed event's `raw` string; raw-source copy is separately controlled by `omitSourceRaw` for Generic Structural output. | Source retention does not establish extraction completeness. |
| Structured extraction | `readEvent` grades FULL/PARTIAL/UNKNOWN/ERROR; the Generic Structural guard independently reconstructs JSON/CEF/LEEF/CSV body accounting. | FULL is an extraction verdict, not a mapping or native target verdict. |
| Mapping/output | `createCanonicalMappingPlan` tracks safe-path mapping decisions; generated normalized fields are checked separately by sample validation. | Source raw copies and merely extracted leaves are not mapped output. |

## Baseline corpus evidence

Before changing code, the focused baseline passed **53 tests across 5 files**:
`src/fieldPaths.test.ts`, `src/grammar/genericLossGuard.test.ts`,
`src/grammar/lossGuard.test.ts`, `src/guided/canonicalMappingPlan.test.ts`, and
`src/guided/NormalizationMappingReview.test.tsx`.
The generic structural corpus includes CEF, LEEF, JSON, positional CSV, and
syslog-enveloped variants. Mutating/removing or changing extracted body values
is classified PARTIAL; complete cases are FULL. This is deterministic repository
fixture evidence only.

The source path contract is bounded to depth 8 and 100 authoring leaf paths.
Literal dotted keys that collide with nested interpretations are rejected;
nulls, arrays, unsafe key segments, excess depth, and paths beyond the 100-path
authoring bound are not selectable as mapping paths. They remain in parsed
`fields`/raw samples, while `countUnaddressableSourceValues` reports the
non-addressable values. A 120-scalar adversarial object yields 100 selectable
paths and 20 unaddressable values.

## Confirmed accounting defect and correction

The baseline `countUnaddressableSourceValues` counted every array as one value,
regardless of its members. An independently asserted three-value array
(`['IOC-A', {indicator:'IOC-B'}, null]`) reproduced **1** where **3** values
were present. This did not prove extraction loss or false FULL: the values
remained in the JSON field tree and loss guard. It was a source-coverage
accounting undercount, not a reason to modify parser classification.

The corrected census counts scalar/null leaves recursively inside unaddressable
arrays and nested objects, while treating empty arrays/objects as one retained
unaddressable value. The focused rerun passed **54 tests across the same 5
files**. The UI's unmappable count for `actor@realm` plus a two-member evidence
array is now 3, distinct from its safe-path count.

## Boundaries not established

- This checkout does not contain the owner's real sample logs/parsers as an
  ingestable acceptance corpus; no synthetic data is described as real vendor
  evidence.
- The baseline did not establish exact raw-byte preservation through every
  parser/export path, or a family-wide FULL/PARTIAL/UNKNOWN census for every
  fixture. UTF-8/log-boundary regressions must be run as part of later
  qualification.
- 1,024-path candidate reconnaissance is a separate bounded scan; this report
  does not claim reviewability of source trees beyond current UI support.
- Browser output presence, Ruby runtime behavior, Stellar 7.0 import/indexing,
  and Ruby 2.4.9 are not qualified by these unit tests.

## Candidate increment at `b9f9d12` and local UI correction

The isolated experiment continued from the requested clean candidate branch. A
focused regression exercised `fieldPaths`, the generic structural loss guard,
the shared loss guard, canonical mapping planning, and the Map Fields UI. It
passed **57 tests across 5 files**. The UI regression checks a long UTF-8 value
through the source tree without shortening it and confirms that a retained JSON
null is visibly identified as a null extracted value and not a mappable field.
`displayValue` now renders complete values in those review surfaces; visual
clipping or scrolling does not alter the value displayed in the DOM.

This is synthetic/adversarial UI evidence, not a real vendor sample. The owner
sample logs and parsers are still absent, so vendor-derived field accounting,
per-event source hashes, exact UTF-8 residual byte spans, and the requested
full family/count census remain unverified. Existing `genericLossGuard` tests
independently damage extracted JSON, CSV, CEF and LEEF values and assert that
the verdict falls from FULL to PARTIAL. No raw-copy path is used as extraction
evidence by those guards.

Candidate checks on 2026-11-18:

- Focused extraction/mapping Vitest: **57 passed**.
- Full Vitest: **2,055 passed, 1 failed** (2,056 total). The failure is
  `src/guided/pythonTestSender.test.ts`, where `spawnSync('python3', ...)` was
  denied with `EPERM`; the 236 other files passed.
- Python unittest discovery: **188 passed, 3 errored** (191 total). Each error
  is a loopback-server test blocked while creating a socket with
  `PermissionError: Operation not permitted`.
- Frontend typecheck and production build: passed. Vite reported the existing
  large-chunk advisory; output was generated successfully.
- Backend TypeScript build: passed; semantic policy canonical-match check
  passed.
- Grammar generation and TS2Ruby `--verify`: passed; generated grammar and
  all three listed Ruby translation targets were in sync.
- Semantic-oracle TypeScript execution: not run. Its `tsx` launcher failed to
  create `/tmp/tsx-1000/3.pipe` (`listen EPERM`).
- Chromium novice mapping E2E: not run. Playwright could not start its configured
  local web server (exit code 1), consistent with the environment's denied
  loopback socket creation. The component-level mapping regression passed, but
  this is not a browser user-path result.
- Ruby runtime: unavailable (`ruby: command not found`). Docker daemon and
  image inventory could not be read because access to `/var/run/docker.sock`
  was denied. Ruby 2.4.9/native parity is UNVERIFIED; DP7 import/indexing is
  NOT TESTED.

The only source change in this increment removes the 80-character elision from
mapping review values and gives null values an explicit NOT MAPPABLE label.
This does not complete LF-0, LF-1, MAP-1, MAP-2, or QUAL-1 acceptance.
