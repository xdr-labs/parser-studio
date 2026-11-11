# Parser Studio — Executable Contract and Runtime-Fidelity Hardening

Status: ACTIVE. Approved by owner 2026-11-10. Tracked under GitHub
[Issue #249](https://github.com/xdr-labs/parser-studio/issues/249);
regressions [#285](https://github.com/xdr-labs/parser-studio/issues/285)
and [#286](https://github.com/xdr-labs/parser-studio/issues/286).
This plan supersedes treating test counts or static SSoT documents as native
deployment proof. Do not claim a formal bug-free guarantee.

## Defects that escaped the previous H0–H4 gates

- The sealed native CI profile uses Ruby 3.2.11 and Fluentd 1.17.1, while the
  authorized Stellar 7.0 lab reports Ruby 2.4.9 and Fluentd 1.7.4. Ruby 2.4
  interprets `Regexp.new(pattern, timeout: 0.05)` as case-insensitive flags,
  not as a deadline; the native CI had no negative oracle for this behavior.
- The frontend canonical mapping provider and Python consume the shared
  semantic policy, but the advisory backend mapping endpoint retains its own
  alias table and checks only exact destination collisions.
- The six evergreen Chromium shards use a historical pinned backend commit;
  same-head Chromium coverage exists elsewhere, but it does not cover the
  complete evergreen catalogue.
- A required job rejects every PR while an unrelated P0/P1 is open, including
  the PR trying to fix it.

## Acceptance stages

| Stage | Implementation | Independent acceptance |
| --- | --- | --- |
| R0 | Defer *release eligibility* on ordinary fixing PRs, keep the exact required status context, evaluate open P0/P1 on main or release. | Static gate test checks branch-event behavior, and open P1 still fails main release eligibility. No closure of issues just to obtain green CI. |
| R1 | Declare executable feature × consumer × runtime ownership: format, mapping API, compiler, preview, transport, exact native profile. Reject undeclared or unsupported claims; no duplicate independently edited alias maps. | Machine-validated coverage manifest linked to actual suite/source; a mutation deleting a required consumer/oracle fails closed. |
| R2 | Read approved name aliases from a single versioned semantic contract across UI and backend; no alternate destination tables. Preserve manual-review and original source identities; block dotted ancestor/descendant collisions, NAT false friends and invalid values. | #286 reproduction, adversarial collisions, cross-consumer positive and negative cases and invariant test. |
| R3 | Declare Ruby 2.4.9/Fluentd 1.7.4 profile separate from the Ruby 3.2/Fluentd 1.17 CI synthetic profile. Unsafe Regex native execution must fail closed; do not confuse Ruby 2.4 Regexp option flags with a 50ms deadline. | Actual generated Ruby, target-profile negative and positive oracles on an isolated equivalent runtime or authorized read-only lab; no skipped or fabricated runtime evidence. |
| R4 | Evergreen Chromium E2E uses same HEAD backend as frontend; leave pinned compatibility runs separately identified. Compare raw UTF-8 events, ordered field identities, reviewed mapping, errors, and generated native output against independent tuples. | Negative/mutated/holdout logs including multi-event, source/destination ports, NAT and regex casing; 0 mismatches for declared supported capabilities. |
| R5 | Freeze final hashes and evidence; scoped CI PR-fast vs periodic wide and pre-release full; H5 separate actual DP indexed-event acceptance or NOT VERIFIED. | Release blocked by open P0/P1; exact artifact lineage, reproducible CI, review and user-approved rollout only. |

## Architectural constraints

- A policy *document* is not a behavioral single source of truth: runtime
  consumers must import it, with architectural tests to reject shadow copies.
- Canonical ParserSpec/MappingPlan remains value/evidence aware; an advisory
  name-only endpoint is never allowed to automatically assign a target field.
- Always distinguish source candidates, browser previews, synthetic Ruby/Fluentd
  evidence and actual DP import/index events. These are separate states.
- Do not run arbitrary user Regex on the production Fluentd host; preserve
  raw records, precise error state and bounded resource limits.
- The full supported-feature universe cannot be proven by isolated successful
  examples; unverified paths remain DRAFT or UNSUPPORTED.
- No production/service changes, managed DP parser installation or public
  preview release are authorized by this engineering roadmap.

## Execution record

- Baseline main: `f202934650c48099890805dc5b0da1904ebc5a8e`.
- Branch: `feat/parser-executable-contract-20261110`.
- Confirm individual completions against exact-commit tests, CI and the
  runtime-compatibility evidence before changing this section.


## Runtime compatibility policy

The explicit profiles are in
[`contracts/target-runtime-profiles.v1.json`](../contracts/target-runtime-profiles.v1.json).
Ruby 3.2 CI success does not imply Stellar 7.0 Ruby 2.4 support.
Regex-generated Ruby on Ruby 2.4 must reject before constructing or matching
a Regexp, and manifest warnings must expose this unsupported target. This is
a **safety containment**, not restoration of Regex functionality on Ruby 2.4.
R3 is not complete until an independently verified target-compatible bounded
Regex path is implemented or the authoring UI explicitly blocks target export.

## 2026-11-10 implementation checkpoint (unmerged candidate)

- R0 gate separation: synthetic Github-event execution proves P1 blocks
  `push` and `workflow_dispatch` but not repair `pull_request` (3/3).
- R1 canonical consumer gate: 100 original frontend normalization aliases
  migrated to the shared policy; 33 explicit review-only advisory source
  names use the same policy; emitted backend policy snapshot is hash-identical,
  with an invariant blocking manual drift. Mandatory CI invariant checks
  known policy consumers, oracle paths, the declared 11 formats, actual
  native profile claims and deliberate policy mutations. This is a **bounded
  ownership inventory**, not evidence that every unknown path was examined.
- R2 alias/collision regression: backend mapping-hints 7/7 PASS, including
  Juniper Structured Data port leaves, translated/NAT guards, and dotted
  ancestor/descendant destination collisions. Compiled backend runtime
  import and prefix collision check PASS. Name-only API never auto-applies.
- R3: generated Ruby Regex code explicitly fails closed on Ruby without
  `Regexp.timeout`, and every Regex-pair manifest warns that Ruby 2.4.9
  cannot deploy this behavior. Actual authorized Stellar 7.0 Ruby 2.4.9
  read-only run loaded the generated fragment and refused both upper/lower
  samples. Mandatory synthetic Ruby 2.4.9 + 3.2.11 isolated CI gate added;
  **its GitHub execution is still pending in this candidate**.
  Ruby 2.4-compatible Regex support is not restored.
- R4: six evergreen Chromium shards configured to compile and run the
  same exact HEAD backend, with no historical pin or ignored test selection.
  Targeted local actual same-HEAD Chromium: 22 PASS, 7 legacy/unsupported
  SKIP, 0 FAIL. Full same-HEAD CI shards remain to be verified.
- Existing broad local regressions: frontend 1,720/1,720, backend targeted
  Regex/advisory 10/10, Python 154/154 plus new release-gate 3/3,
  backend TS build and typecheck PASS, MCV2 mutation and source score
  PASS (91.84% non-equivalent candidate score). These are
  evidence-scoped results, not a claim of exhaustive absence of defects.
- R5/DP indexed events remain NOT VERIFIED. No deployment or production
  parser/transport mutation was performed for this checkpoint.


## Critical source-reachability correction (2026-11-10)

`backend/src/http.ts` owns a legacy optional mapping-suggestions endpoint,
but **the shipping entrypoint is `backend/src/mainline-authoring-server.ts`**.
It explicitly disables the name-only HTTP feature and responds with 404.
Thus #286 is a latent shared-policy divergence, **not a demonstrated
customer-facing mapping-hints endpoint defect**. The canonical policy is
still applied to that dormant module to prevent reactivation of stale
semantics. Full current-product browser E2E must assert the optional
endpoint remains unavailable; it must NOT add a public API to make a
legacy code audit pass. Only the actual Guided mapping path is user-facing.
The new cross-consumer parity runner tests those separate active/dormant
paths with explicit evidence strengths. This distinction is mandatory for
future audits: inventory shipped entrypoints and reachable call paths first.


## Independent semantic truth acceptance (R4 added)

The golden targets in
[`contracts/semantic-identity-independent-goldens.v1.json`](../contracts/semantic-identity-independent-goldens.v1.json)
are authored independently of both executable engines and the shared
semantic-policy JSON. They carry **26 literal expected outcomes** across
reviewed IP/port/action/source identity, nested RFC5424 source paths,
dangerous NAT prefix variants, invalid values, occupied destinations and
both orders of competing source fields. The CI runner
`scripts/verification/independent-semantic-identity-oracle.ts` checks both
browser decisions and the dormant review-only advisory logic against these
independent results and refuses any divergent value, skipped case or reduced
fixture inventory. This is a small explicit truth set; it does NOT claim
independent proof for every undocumented vendor log or DP index event.


## Explicit shipping-surface graph (R1 improvement)

`contracts/shipping-surface.v1.json` identifies the actually shipped
backend entrypoint, its required compiler path, and legacy-only modules.
`scripts/verification/shipping-entrypoint-reachability.mjs` checks a
transitive source-import graph, asserts that `backend/src/http.ts` remains
unreachable from the shipping server, and kills an injected-import
mutation. The shipped backend's actual HTTP/404 behavior remains a
separate browser and runtime test; source graph reachability is
not a formal replacement for dynamic coverage. This prevents false
release readiness claims based on tests of dormant helper endpoints.


## Same-source artifact lineage (R5 partial)

The fixed-synthetic CI receipt
`scripts/verification/executable-artifact-lineage.ts` calculates the exact
Git source HEAD/tree, canonical semantic policy hash, runtime profile hash,
compiler/template source hash, generated Ruby and CONF SHA256, deterministic
ZIP SHA256 and artifact revision ID. It reruns the same source compilation
and packaging and refuses changed outputs, tampered file bytes, dirty tracked
source, wrong GitHub SHA, or forged target verification status. Both Native
and Web jobs independently produce sanitized receipts on the same head.
The H4 operator-release gate requires all four evidence artifacts: two
existing Native proofs plus these two lineage receipts. The per-job receipts
are not yet a cross-job cryptographic identity comparison or an actual
build-once distribution mechanism; those remain R5 hardening, and full DP
indexed-event confirmation remains NOT VERIFIED.


## PR source-vs-merge SHA fidelity (R4 corrective)

Original CI log from PR #287 showed checkout at the GitHub-generated
`refs/remotes/pull/287/merge` commit `52e91e6e4beed09026b4c9de70c237a46ed2201f`
rather than the review source HEAD `f300e64605d7b4091ab7fb32f2fc8a2b0399a92c`.
The original workflow did compare frontend/backend **to the same temporary
merge commit**, but those tests must not be called exact PR source HEAD.
All checkout jobs now explicitly select
`github.event.pull_request.head.sha` for pull requests, fall back to
`github.sha` for push/manual events, and assert the actual checked-out Git
commit. The lineage receipts verify that same expected source SHA.
Integration against a merge candidate remains a distinct concern and is
enforced by protected main's strict up-to-date requirement and post-merge CI.


## Cross-job artifact evidence reconciliation (R5 follow-on)

The nine-job required CI suite retains its existing status check names.
`release-eligibility` now waits for both `native-isolated-synthetic`
and `web-quality` jobs; it downloads their redacted lineage receipts
from the same workflow run, checks the exact PR source SHA (not the
temporary merge SHA), and requires every source tree, policy, target
runtime profile, compiler/template, generated Ruby/CONF, artifact
revision and deterministic ZIP hash to match. It refuses extra fields,
missing evidence, forged target-proof booleans, missing/modified files,
and the previous version of stale-head evidence. New independent
negative tests verify all fail-closed paths.

**Separation of concerns:** This detects cross-job drift, not a genuine
single-build distribution pipeline, independent correctness of every
vendor parser, or actual downstream Stellar indexed events. The
release-eligibility step continues to reject open P0/P1 issues after
checking evidence. Thus release remains blocked until #285 is
qualified without suppressing the issue.


## R3 final target-runtime export exclusion (2026-11-10)

Observed Stellar Cyber 7.0 uses embedded Ruby 2.4.9 / Fluentd 1.7.4.

**Exact cause of the earlier fail-closed behavior.** Two things combined, and
only the first is a Ruby constraint:

1. *Ruby.* `Regexp.timeout=` and `Regexp::TimeoutError` first appear in Ruby 3.2.
   Ruby 2.4.9 (Onigmo, no memoization) cannot bound a backtracking match at run
   time, and `Regexp.new(pattern, timeout: 0.05)` is not a timeout there: the
   Hash is a positional options argument and silently becomes IGNORECASE.
   `Timeout.timeout` cannot interrupt a running regex match either.
2. *Compiler design.* The generated helper delegated ALL regex safety to that
   missing runtime timeout. The generation-time gate (`portable-regex.ts`) is
   documented as a heuristic rejection list, not a bound, so nothing could
   justify running a pattern without the timeout.

**Fix (this contract).** `backend/src/ruby24-regex-cost.ts` bounds the cost at
generation time instead. It builds the pattern's Glushkov position automaton and
accepts only patterns whose number of simultaneously viable backtracking paths is
bounded by a constant: no exponential or infinite degree of ambiguity (EDA/IDA,
Weber and Seidl), deterministic alternations and optional elements, at most two
loops that disagree with what follows them, and an anchored scan (an unanchored
pattern gets a virtual leading `.*` loop and is refused if any repeat overlaps
it). Accepted patterns run NATIVELY on Ruby 2.4.9 through the generated helper,
which additionally refuses input that is longer than 4096 bytes or contains a
line break (the analysis assumes one short line). Everything else stays refused
with HTTP 422 `TARGET_RUNTIME_REGEX_UNSUPPORTED` and a precise reason, for
ParserProject generation, ParserRecipe v0.2 validate/generate and ZIP packaging
of a client-supplied pair (the proof is re-derived from the embedded project; a
forged marker does not export an unbounded pair).

The target adapter capability is
`regexPreviewSupported=true, regexExportSupported=true, regexExportMode=ruby24-static-cost-proof`;
`/validate` reports per project whether the pattern is exportable through
`targetExportSupported`. The Ruby 2.4.9 CI gate executes a bounded pattern on
real operator-style logs (field values compared with hand-authored expectations,
two events through the plugin callback), adversarial 4096-byte inputs under a
1 second wall-clock limit, and verifies that an unbounded pattern fails closed.
**This is a static classification backed by execution, not a general regex
engine or a claim about Stellar target import/indexing (still NOT VERIFIED).**
