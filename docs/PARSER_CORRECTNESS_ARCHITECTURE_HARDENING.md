# Parser Correctness Architecture Hardening — Native-first qualification

Status: **ACTIVE**, owner requested 2026-11-07. Implementation Work Packet:
[GitHub #249](https://github.com/xdr-labs/parser-studio/issues/249).
Baseline: main `0f95c5818f4606ab006468432dd062382043ed7d`.

## Current bounded implementation and evidence (2026-11-08)

The former H0-H3 integration receipt did not establish complete operator semantics.
Audit #266 reproduced eight gaps. The executable v1 correction and required
coverage inventory are described in
[Executable contract completion](verification/20261108-executable-contract-completion.md).
Read that scope and the exact candidate receipts in #266 before using the older
incremental statuses below. H1/H3 qualification is tied to the shipping grammar,
operator, type and template matrix, not an aggregate historical PASS count.
H4 branch enforcement and H5 target qualification remain separately gated.

## Mapping Correctness v2 root-cause extension — 2026-11-09

[Work Packet #283](https://github.com/xdr-labs/parser-studio/issues/283) and [MCV2 plan](MAPPING_CORRECTNESS_V2.md) define the owner-approved mapping semantics, mutation/invariant tests and provenance protections. The new A→E sequence is an explicit hardening dependency **before** further PR #282 integration, not a substitute for H0–H5 or an assertion that current passing CI proves safety.

## Diagnosis

Existing `ParserProject` and `ParserRecipe v0.2` schemas, shared
`runtime/multipass/semantic-policy.v1.json` and same-source Ruby CI already
exist, but cannot by themselves prove every emitted parser's semantic correctness.
Browser TS is an approximate preview, Python Multi-Pass is a source-analysis
engine, and emitted Ruby is the execution authority for the exported parser.

Observed independent red cases:

- [#247](https://github.com/xdr-labs/parser-studio/issues/247): JS accepts
  engine-specific regex syntax with a different meaning from Ruby.
- [#245](https://github.com/xdr-labs/parser-studio/issues/245): accepted
  overlapping quantifiers exhaust browser preview execution budgets.
- [#246](https://github.com/xdr-labs/parser-studio/issues/246): choosing the
  first 100 union field paths makes official suggestions depend on event order.
- [#248](https://github.com/xdr-labs/parser-studio/issues/248): textual
  classification equals cannot match typed native integer/boolean outputs.

## Order of work and acceptance

### H0: Immediate correctness containment — started

1. Establish a pure, shared browser/backend portable regex policy. Block
   unsupported escapes, POSIX character classes and overlapping quantified
   atoms. Add independent negative and positive cases, and ensure direct
   ParserProject and ParserRecipe v0.2 generation both fail closed.
2. Review all distinct candidate field paths in deterministic order *after*
   cheap dictionary eligibility filtering. If the bounded evaluation budget is
   exceeded, fail closed and display the actual eligible-source count instead
   of silently claiming no suggestions or auto-promoting partial evidence.
3. For the current v0.1 string-only equality contract, refuse classifiers on
   non-string normalized values. Compare the actual normalized preview string,
   never `String(raw)`; expand to typed predicates only in a versioned schema.
4. Run focused TypeScript/backend regression and full exact-HEAD suites; native
   Ruby and public Chromium must pass for all changed behavior before merging.

### H1: Canonical rule/operator contract v1 — in progress

The first increment defines the versioned strict classification operator
contract (string-only `equals`, typed `exists`, post-normalization comparison),
shares its evaluator and type eligibility checks across browser/backend, and
marks both generated Ruby templates. Independent authored examples check that
`0006` differs from `6`; same-head CI must execute generated Ruby to verify
actual native agreement. Further extraction/field-path/error contracts remain
open until their own executable goldens exist.

Define a versioned supported grammar and explicit types/paths, predicate
semantics, error-stage behavior and original-byte accounting. Consolidate
existing Ruby template helpers by generated/common validated implementation.
Unsupported grammar is `REVIEW_REQUIRED`, not a best-effort promoted DRAFT.
Preserve the independent Grammar-first / Multi-Pass source engine.

### H2: Native-first verification — CI evidence increment in progress

The first increment adds a required exact-HEAD synthetic Ruby executable
oracle and sanitized artifact hashes, described in
[Native Executable Evidence v1](NATIVE_EXECUTABLE_EVIDENCE_V1.md).
**This is not a production sandbox or certification of arbitrary user parsers.**
The isolated runner/security hardening and live deployment remain pending.

Reuse the source-hash-bound `native-project-verification.ts` contract and
`local-native-project-verifier.ts` behind an authorization-checked isolated
runner. Fix Ruby/Fluentd version and record exact generated artifact hashes.
Disable outbound network; isolate files and processes; bound CPU/memory/time.
Run in CI first. Separate design and safety authorization are mandatory before
any live public development preview runtime endpoint is enabled.

Evidence levels: `SOURCE_PARSED` → `DRAFT_COMPILED` → `NATIVE_CONFORMANT` →
`TARGET_VERIFIED`. Browser preview/HTTP 200/zip hash do not imply native
conformance; even native Ruby cannot prove Stellar Cyber DP 7.0 import.

### H3: Differential + independent-oracle QA — metamorphic increment in progress

The first increment adds 100 deterministic multi-event source-order permutations
with independently authored official field truth and exact vendor value
preservation. Evidence and remaining scope:
[Independent Oracle H3](INDEPENDENT_ORACLE_H3.md).

For each explicitly supported grammar: independent original source truth,
positive/negative fixtures, validated Stellar 7.0 target values, predictable
partial/unmatched spans, Unicode/numeric/NULL/type boundaries, event reordering
and bounded property-based mutations. Generate and run the exact Ruby pair,
compare typed results, error stages and original source accounting. No tests
may use implementation-produced outputs as their only goldens.

### H4: Exact-HEAD release gate — operator-side verification implemented

Require same-HEAD native differential, compiler, all browser UX paths and
sanctioned regression suites, with no unexpected skips or P0/P1 issues.
Require verified CI statuses and strict review of the current advisory
`merge_gate_status` / actual repository protections before requesting the
separately authorized branch-protection or release-policy change. The
[H4 exact-HEAD operator release gate](H4_EXACT_HEAD_RELEASE_GATE_20261108.md)
implements the approved verification in a fail-closed CLI. GitHub returned 403
for private repository protection/rulesets on the current plan, so GitHub
branch enforcement remains unavailable; do not mark H4 fully complete.

### H5: Stellar Cyber DP 7.0 qualification — separate approval and lab

Perform real parser import, execution and receive only in a designated
permissioned DP lab. Do not infer target verification from native unit tests.
Current state: **NOT VERIFIED**.

## H0 implementation boundaries

- Preserve raw log bytes, vendor namespace and partial source accounting.
- Do not change the supported syslog receiver defaults, normalization catalog
  revision, public services, production endpoints or authentication.
- Regression tests must demonstrate both original failures and safe positives.
- When a conservative grammar gate rejects a previously accepted user regex,
  provide review guidance; never claim this is universal regex safety proof.
- Code/PR work can proceed under owner instruction. Actual public preview
  rollout and deployment-policy changes require separate authorization.
