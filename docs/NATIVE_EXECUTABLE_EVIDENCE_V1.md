# Native Executable Evidence v1 — CI-only synthetic oracle

Status: **H2 first implementation increment**, not a deployed Native Runner.

The GitHub `web-quality` job now has a REQUIRED step after canonical cross-engine
conformance: `Generated Ruby executable evidence (required CI-only oracle)`.
It compiles one trusted synthetic ParserProject into the actual extensionless
Ruby and `.conf` artifacts, verifies their byte hashes, executes the Ruby
fragment in a real Ruby interpreter, and compares each generated record with
independently authored expected values. The three fixed JSON source records
cover string leading zeros, rejection of a numeric original as an official
Stellar `action` field (with mapped-field error stage and unrelated IP retained),
and nonmatching routing. The synthetic source/expected oracle is hardcoded in
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

## H2 CI-only sealed Fluentd runner increment (Draft)

The H2 continuation introduces a **separate mandatory GitHub Actions job**
(`native-isolated-synthetic`) that builds the fixed Ruby 3.2 / Fluentd
1.17.1 Gemfile.lock environment and runs exactly one authored synthetic
ParserRecipe-derived parser+CONF pair. The source, expected normalized output
hashes and expected timestamp results are independent, fixed test inputs
compiled from the same repository HEAD. No arbitrary user parser, request
body, file upload or HTTP endpoint reaches this job.

Build-time access is limited to fetching the base Ruby image and Gemfile.lock
dependencies. Runtime execution uses Docker `--network none`,
`--read-only`, UID/GID 65532, `--cap-drop ALL`,
`--security-opt no-new-privileges`, PIDs/CPU/memory/file-handle limits,
a small non-executable tmpfs and a hard wall-time deadline. The image includes
the fixed repository-owned Native Fluentd runner, not a mounted host directory.
No Docker socket, credentials, source worktree or host path is mounted into
the container. The CI script first verifies that the sandbox cannot write to
the root filesystem, connect to an external IP or run as root.

The input payload is a transient private CI file containing **only fixed
synthetic logs and generated code**; it is not logged or uploaded. The output
must conform to the source-bound `parser-studio.native-project-verification.v0.1`
receipt and is checked again on the host. Only hashes, runtime version,
verified counts and explicit non-target/non-customer claims appear in console
output. In particular, `nativeUserParserVerified` describes the
*fixed synthetic* test request in this CI job, not customer parser support
or Stellar Cyber import verification.

**Evidence limitations:** Docker on the GitHub runner still shares its host
kernel, and the Ruby Docker base image is currently pinned to the `3.2`
minor track rather than an immutable OCI digest. Exact image ID is logged for
each run; strengthening image-digest governance and an independent hardened
runtime security review remain prerequisites for exposing a live service.
No public development-preview Native endpoint, DP import, traffic send,
Fluentd-in-DP claim, branch-protection mutation or deployment is performed.
