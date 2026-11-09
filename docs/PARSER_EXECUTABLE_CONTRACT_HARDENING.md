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
