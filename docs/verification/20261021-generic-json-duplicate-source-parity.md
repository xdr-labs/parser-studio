# Generic Structural wrapped JSON duplicate-member parity

**Owner scope:** A bounded, manufacturer-neutral JSON object grammar
correction stacked on the completed Stellar Cyber 7.0-only dictionary
accuracy candidate PR #126. No target-version schema selection,
mobile, DP, sensors, production or release operations.

## Actual root failure

The previous Generic Structural browser extractor accepted repeated
decoded object names in a JSON body preceded by a generic log token
or embedded in a short RFC5424 Syslog envelope. JSON.parse kept the
last value, silently discarding earlier values before field mapping.

Six authored invalid samples (root, nested, escaped-equivalent,
array-contained and short RFC5424) reproduced RED on the original
candidate. Three authored records with same-named keys in distinct
objects were correctly valid. This is a source/no-loss correctness
boundary, not a manufacturer-wide field-accuracy benchmark.

## Shared grammar correction

- Browser Generic Structural delegates to the existing strict JSON
  duplicate-key scanner for short RFC5424 JSON, prefixed JSON and
  bounded JSON envelope bodies. Checks run after syntactic JSON.parse,
  using the original unmodified source text.
- The native Generic Structural prefixed JSON helper now calls the
  same strict parserstudio_json_object routine provided by the
  generated Ruby fragment rather than a permissive parallel JSON.parse.
  The short RFC5424 helper already used the same strict native routine.
- The standalone helper test assembles the actual shared strict Ruby
  decoder from the compiler template; no separate permissive parser
  or vendor-specific regex is introduced.

## Evidence and limits

- RED: 6/9 newly authored Generic Structural source tests failed before
  the change; valid distinct-object controls passed.
- GREEN: focused browser Generic Structural tests 38/38.
- Native static code and compiled artifact contract PASS; actual Ruby
  execution is SKIP locally because dev-atlas has no Ruby executable.
  Exact-head GitHub Actions Ruby testing must be verified before native PASS.
- Real localhost Chromium without HTTP mocks: two novice UI paths
  (malformed record safely blocked, valid record explicitly recovered),
  plus one browser-loaded exact Generic Structural decoder matrix.
  Source bytes and input remain unchanged; no third-party network transfer.
- This source-frame scope does not claim original manufacturer/firmware
  correctness or native Stellar import. All generated outputs remain
  DRAFT; targetImportVerified:false.

The exact pushed candidate/CI results are recorded in GitHub Issue #1.
