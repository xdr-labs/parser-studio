# Native Executable Evidence v1 — CI-only synthetic oracle

Status: **H2 first implementation increment**, not a deployed Native Runner.

The GitHub `web-quality` job now has a REQUIRED step after canonical cross-engine
conformance: `Generated Ruby executable evidence (required CI-only oracle)`.
It compiles one trusted synthetic ParserProject into the actual extensionless
Ruby and `.conf` artifacts, verifies their byte hashes, executes the Ruby
fragment in a real Ruby interpreter, and compares each generated record with
independently authored expected values. The three fixed JSON source records
cover string leading zeros, numeric-to-string normalization and nonmatching
routing. The synthetic source/expected oracle is hardcoded in
`scripts/verification/native-executable-evidence.ts`, not inferred from the
browser or compiler outputs.

## Receipt and fail-closed status

Contract: `parser-studio.native-executable-evidence.v1`.

The CI artifact `parser-studio-native-evidence` contains only a JSON record
with event/field comparison counts, source/Ruby/.conf SHA-256 digests,
interpreter version and false target verification flags. No raw events,
normalized values, Ruby source, credentials, environment variables or
customer metadata are emitted. A missing Ruby executable, failed compile,
changed compiled byte hash, missing output or mismatched oracle **fails CI**;
there are no automatic skips or optimistic DRAFT-to-Native promotion.

The evidence is scoped to a **fixed synthetic Ruby parser callback only**.
It does NOT certify arbitrary user parsers, Fluentd runtime integration,
network listener behavior, deployment, Stellar Cyber DP 7.0 import, sensor
reception or vendor/firmware-wide accuracy.

## Remaining H2 work (not solved by this increment)

- A separately owned and authorized Native execution service, never the
  public authoring server, must isolate user-supplied source and generated
  parsers with verified Ruby/Fluentd dependency pins, read-only filesystem,
  uid/gid confinement, denied egress, process/CPU/memory/wall-clock quotas and
  bounded sanitized output.
- The existing `native-project-verification.ts` hash-anchored request/report
  protocol and `local-native-project-verifier.ts` must be assessed as
  *validation infrastructure*, not assumed sufficient isolation by themselves.
- Native evidence must link to the exact user project/recipe/source and
  generated pair and distinguish DRAFT_COMPILED, NATIVE_CONFORMANT and actual
  TARGET_VERIFIED without privilege escalation or automatic upload.
- Only a separate, permissioned Stellar Cyber DP 7.0 lab run can provide
  actual target import and receive evidence.

No public API endpoint, production runtime, DP, credentials or browser setting
was modified by the CI-only increment.
