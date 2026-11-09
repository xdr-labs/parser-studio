# Mapping Correctness v2 — invariant-first normalization

Status: **ACTIVE** · 2026-11-09 · [Work Packet #283](https://github.com/xdr-labs/parser-studio/issues/283) · umbrella [H0–H5 #249](https://github.com/xdr-labs/parser-studio/issues/249) · implementation PR [#282](https://github.com/xdr-labs/parser-studio/pull/282).

## Root-cause evidence

Passing 8/8 GitHub Actions jobs did not establish general correctness. The previous implementation lost valid source paths in a name allocator, overwrote an explicitly edited destination via a name heuristic, and promoted translated/NAT port keys through a shared-but-under-specified policy. All three reproduced on exact HEAD `608144c`. The previous review's lack of invariant-driven negative cases was the release gap; counting more ordinary test fixtures does not close it.

## Decision authority

One versioned MappingPlan carries **source identity, target, type, provenance, semantic evidence, collision status, review decision and explicit unresolved entries**. Browser, Python source analyzer and native Ruby must interpret the *same contract*, not derive independent assumptions. The approved Stellar 7.0 target dictionary remains the source of valid official fields. Unreviewed vendor semantics are never silently promoted.

A target's generated/manual identity **must never be inferred from an automatic-looking ID, destination spelling, or vendor label**. Legacy drafts without trusted provenance are held unchanged. On user edit, persist `USER_EDITED`; explicit official-field approval persists `APPROVED`. Auto-generated destinations have `AUTO` provenance only at the actual generation boundary. ParserRecipe/review-only suggestions cannot forge approval. Keep provenance as authoring metadata and do not emit it as a Stellar normalized field.

## Ordered implementation and acceptance

| Phase | Implementation | Hard acceptance |
| --- | --- | --- |
| MCV2-A | Versioned MappingPlan + per-mapping provenance and idempotent legacy migration | Manual override survives rerender, reanalysis and save/restore; unmarked legacy state never rewritten |
| MCV2-B | Source-path allocation and unified semantic policy | No silent omissions, no unapproved collision, NAT/translated aliases blocked across TS/Python/JSONata, Juniper explicit source/destination port aliases remain valid |
| MCV2-C | Independent executable invariants + property/stateful/mutation tests | No Silent Loss / No Collision / Manual Override / Determinism / Semantic Safety / Cross-engine Parity / Fail Closed, deterministic shrunk counterexamples stored as fixtures |
| MCV2-D | Exact-head mandatory CI & H4 operator gate | No skipped required oracle; no open P0/P1; native semantic comparison on changed source and matching backend/Ruby SHA; advisory branch protection stated accurately |
| MCV2-E | Multi-vendor source holdouts, novice Chromium, native pair/receiver evidence | Same samples from UI to source IR to emitted Ruby; remain `DRAFT` unless exact target runtime tested |

A target mapping is **APPROVED** only if the field is in the vetted dictionary, all relevant observed values satisfy type/range constraints, no ambiguous competing source or destination exists, user changes are not overwritten and the exact generated parser can execute the same plan. Unknown paths, impossible allocations and unsupported source semantics become `REVIEW_REQUIRED`, never success.

The MCV2-A/B fixes are the initial implementation slice. The H0–H3 compiler hardening, H4 advisory operator CLI and H5 Stellar 7.0 DP target qualification remain existing work; do not silently redefine them as passed by this document.

## Quality metrics

- Zero unreported lost valid source paths; zero collisions declared successful.
- Zero user-edited destinations rewritten by automatic reconciliation.
- Zero unreviewed NAT-derived port promotions; preserve original values and event bytes.
- Zero deterministic mapping-plan disagreement between browser and generated native Ruby for verified operator subsets.
- Record seed, source hash, expected/oracle result and minimal counterexample for each failed property test.
- Mutation score target **>=90%** on the mapping decision core, after an independently measured baseline; a target, not a claimed current result.
- GitHub CI pass is necessary but not sufficient. The issue/PR gate must also have no unresolved P0/P1 counterexamples and a reviewed native evidence receipt.

## Initial implementation evidence (2026-11-09, PR #282)

The first MCV2-A/B/C/D slice adds explicit v1 authoring provenance, a
collision-aware original/leaf source-name allocator, bounded 256-source
feasibility with explicit unresolved diagnostics, a shared TS/Python NAT
semantic guard, 512 seeded independently checked allocation cases and a
mandatory MCV2 job step in the existing `web-quality` gate. Existing legacy
mappings without provenance are held unchanged rather than guessed to be
unmodified. Browser Auto Parser and manual edits now explicitly retain origin.

Local evidence before exact-head CI: full frontend 1,679 tests PASS; targeted
UI user-edit state test PASS; both TypeScript/build PASS; independent Python
semantic negatives 2/2 PASS; two complete Juniper tutorial Chromium paths PASS.
The target CI HEAD, exact-generated-Ruby comparisons and full property/mutation
coverage are still separate acceptance requirements. Do not mark MCV2-A–E
complete merely because this initial slice is green.

## Second implementation slice — canonical IR and executable release evidence

`src/guided/canonicalMappingPlan.ts` is the versioned
`parser-studio.mapping-plan.v1` local decision census. It records each safe
original source path, typed target, field group, explicit origin, observed
catalog evidence, review reasons, conflicts, and unresolved source identities.
It does **not** embed original values or runtime secrets. Auto Parser,
normalization review, generated mapping reconciliation, JSONata proposal
review and scoped event-family candidates consume the same catalog decision
plan. The existing backend adapter/compiled Ruby executes the reviewed mapping
rules; DP 7.0 import remains separately unverified.

The MCV2 type and source identity guards now require trusted `AUTO` origin;
auto-looking IDs or original path-shaped targets no longer authorize silent
replacement. `createDraft` initializes genuine generated defaults with AUTO,
whereas legacy unmarked drafts remain untouched. Explicit editing persists
`USER_EDITED` and user-approved JSONata/scoped family mappings persist
`APPROVED`. Exact source paths, non-transport semantics and the NAT/translated
family deny-list are preserved.

Regression additions: 512 independent seeded 2-choice allocation cases; 11
actual in-memory mutations of production mapping/port-policy code, all
rejected by an independent oracle (**11/11 selected mutants**, not a broad
mutation score); 5 documentation-fixture source holdouts (3 authorable,
2 correctly review-only); selected browser tests of Juniper, FortiGate
multi-event, JSONata and 7.0 scoped mapping. The exact-head GitHub quality
workflow now requires both the negative/positive mutation probes and
original-source Ruby differential assertions on the Juniper and two FortiGate
fixtures. There is no optional skip if Ruby is unavailable on the runner.

The H4 operator-side gate now requires an explicitly identified closed Work
Packet with all acceptance boxes checked; open P0/P1 issues, stale CI and
incomplete GitHub search responses refuse release even when CI is green.
This does not change GitHub branch protection and does not authorize any
release. Independent full-repository mutation sampling, every Stellar field
family, and actual customer DP 7.0 import/runtime qualification remain
separate unverified gates.

### Exact-head integration regression correction

Initial MCV2 CI revealed that treating every non-addressable source value as a
fatal authoring error broke legitimate AWS WAF array-bearing and empty CSV
cell inputs. The revised contract distinguishes **unresolved safe source
paths** (block automatically generated DRAFT) from **unaddressable source
values** (retain exactly in raw source, count explicitly in UI/plan, and do
not falsely emit as scalar mappings). Independent unit and Chromium CSV/AWS
WAF recovery checks are mandatory; the source parser's error ledger remains
authoritative. The Ruby differential harness selects the actual generated
non-`.conf` parser file from `compilePair` instead of assuming a `.rb` file
suffix. These corrections are part of the acceptance gate, not a relaxation
of no-silent-loss requirements.

### Third implementation slice — Canonical MappingPlan source-level mutation oracle

The MCV2-C gate now executes `scripts/verification/mcv2-canonical-mutants.mjs`
in GitHub CI. It bundles the **real** `canonicalMappingPlan.ts` and its
production dependencies with esbuild, injects 24 independently selected
semantic mutations in memory (never modifies the working tree) and compares
all of them against expected manual override, path census, official-vendor
semantics, collisions, unresolved counts, type validation, retained array
accounting and value-free evidence. The initial baseline exposed a real
missing collision diagnostic: the official candidate provider safely excluded
an occupied target but the IR did not explain that conflict. The v1 plan now
retains `EXISTING_TARGET_CONFLICT` using a catalog-only diagnostic scan while
keeping the occupied destination ineligible for auto-approval.

**Measured subset:** 24/24 Canonical MappingPlan mutation probes and 11/11
source-allocation/port-policy probes rejected. These are source-executed
meaningful error injections, but not an exhaustive mutation census of every
mapping-decision statement. The >=90% full mapping decision-core target is
still unverified until a comprehensive measured baseline is available. The
new gate fails on any surviving selected mutant or missing source anchor.

### Independent AST-wide Canonical MappingPlan mutation baseline

The `mcv2-canonical-ast-score.mjs` CI gate visits **every binary operator
and `if` condition** in `canonicalMappingPlan.ts` using TypeScript AST source
positions, bundles and runs the actual mutated module with its production
dependencies, and evaluates independently declared source, destination,
catalog, collision, manual override, type/range, budget, unknown-value and
cross-event oracle expectations. A mutation that does not compile is recorded
as invalid, never counted as a kill. Invalid count is currently zero.

Observed on this source version: **32 total**, **26 killed**, **zero
non-equivalent survivors** and **six explicitly justified equivalent**
`??` → `||` variants. The raw kill fraction is **26/32 = 81.25%**; excluding
only the six proven equivalent expressions under well-typed input contracts,
the measured **Canonical MappingPlan orchestrator score is 26/26 = 100%**.
Those six original operands are typed Array, object, non-empty FieldGroup or
null/undefined, so `||` produces exactly the same value as `??` for valid
inputs. Their literal source expressions and reasons appear in the CI output.
The gate fails closed on a surviving non-equivalent mutation, a baseline
oracle failure or an effective score below 90%. It also runs the 24/24
independently selected semantic orchestrator mutants, complementing the
11/11 source-name allocator and translated-port semantic mutants.

**Scope limitation:** This AST census covers the Canonical MappingPlan
orchestrator, not all statements in the separate allocator, candidate
provider, Python structural analyzer or generated Ruby backend. The broad
multi-module 90%-coverage target remains open; neither a successful AST
orchestrator gate nor selected mutant results proves that target.

### Bounded source-allocator and semantic-policy mutation census

`mcv2-bounded-allocation-ast-score.mjs` runs each AST-mutated source in a
**separate bounded process**, including deliberately corrupted loop/SCC exit
conditions. This prevents an accidental infinite loop in a mutant from
hanging the development machine or GitHub CI. The oracle enumerates all
source/leaf assignments for small source sets, checks deterministic
lexicographic preference and fail-closed collisions, then verifies
128/129/256-path boundary behavior, duplicate leaf identity, manual edit
provenance, NAT/translation aliases and nested source paths. It also checks
that a duplicate auto-generated source rule cannot silently produce the
same target twice. Mutation syntax errors are tracked separately and do
not count as killed mutants; every source position has a receipt.

Current measured baseline: **field allocator 68/72 (94.44% raw)** and
**source-port policy 4/4 (100% raw)**. Four allocator survivors are low-risk
observationally equivalent guards/boolean expressions under the tested domain
contracts (the same zero defaults, no-op already-chosen leaf, and early
empty-array return), and are **retained in the raw denominator**. The gate
fails below 90% raw AST mutation detection on either measured module.
This is a real bounded sampled mutation baseline, not a claim that every
branch of `normalizationCandidates.ts` or Stellar DP 7.0 is mutation-tested.

### Source-to-official-field candidate semantic oracle

The `mcv2CandidateSemanticOracle.test.ts` independent expectations cover
22 positive/negative cases: literal `source-port -> srcport` and
`destination-port -> dstport` including ICMP numeric values, correct IP and
protocol values, invalid IP/port/proto ranges, NAT/post-NAT path variants,
false-friend vendor action/duration/event-type labels, ambiguous aliases,
mixed-event sparse evidence, unknown names, and manual owner edits. The
CI also runs `mcv2-semantic-candidate-mutants.mjs`: **12/12 selected
source-level semantic decision mutants detected**, with real production
module bundling. Two equivalent/no-op mutations were discarded from the
selected probe set rather than counted as successful detections. This is
NOT an AST-wide mutation score for `normalizationCandidates.ts`.

### Bounded AST-wide official-candidate mutation census (2026-11-09)

The independent production-provider oracle now exercises
`src/guided/normalizationCandidates.ts` through **all 155 AST-level binary,
`if`, and ternary condition mutations**. Each mutant is separately bundled
with the real production dependencies, then executed in a distinct Node
process with a **3.5-second timeout and a 192 MiB V8 heap cap**. The
baseline must pass before mutation; any compile-invalid mutant is recorded
separately, never counted as killed. Tests use entirely synthetic log values.
The mandatory CI command is
`node scripts/verification/mcv2-bounded-candidate-ast-score.mjs --require-90`.

**Measured local result:** 135 killed / 155 compile-valid mutations (87.10%
raw); eight documented equivalent `??` to `||` substitutions; **135/147
non-equivalent (91.84%)**, with 12 unwaived survivors, zero invalid and zero
timeouts. Equivalence proofs are executable-expression-specific:
`source.split('.').at(-1)??source` (three locations: valid paths have a
nonempty last segment); alias-table values (nonempty official-name strings);
FieldGroup values (nonempty enum strings); event arrays (always truthy);
event length (nonnegative integer, including zero); and accumulated
candidate arrays (always truthy). An unknown survivor is **not** classified
as equivalent by default. The gate requires exactly eight reviewed
equivalences, a full-module census, zero compile-invalid mutations, and a
non-equivalent score of at least 90%.

Combining this candidate-provider scope with the previously measured
Canonical MappingPlan (26/26 non-equivalent), source allocator (68/72 raw),
and source-port policy (4/4 raw) gives **233/249 = 93.57%** across the
explicitly scoped core AST operators. Four allocator survivors remain in
the denominator, so this aggregate is conservative relative to that
module's equivalence notes. This **does not** measure every expression,
every external module, all Python branches, or the proprietary DP runtime;
the 12 candidate-provider survivors remain documented sensitivity gaps.
The existing shared TS/Python/compiled-Ruby golden oracle is a separate
cross-engine contract, not an AST score.

**New real correctness defect discovered by the oracle:** a single event
with more than 100 addressable fields previously had only its first 100
fields inspected for official suggestions; a competing official alias
later in a CSV record could be missed. A first fail-closed correction
unintentionally suppressed legitimate PAN-OS mappings because the 100-field
authoring budget is not the official-candidate scan budget. The corrected
implementation enumerates **up to 1,024 safe source leaves per event** and
uses the 1,025th as a fail-closed sentinel. An event with 101 source
leaves is fully inspected, so competing aliases remain REVIEW; an event
with 1,025 safe leaves is blocked with a visible incomplete-scan warning.
The separate authoring budget remains 100 and the mapping-plan UI already
reports values beyond that authoring limit as unaddressable. The aggregate
official-candidate budget remains 1,024 *eligible* distinct paths across
events. The independent PAN-OS positional CSV regression must remain green.

## Scope and release safety

Maintain source parser Grammar-first / Multi-Pass and do not invent per-vendor case patches. No main merge, public preview rollout, production/sensor restart, permissions/branch-protection change or Stellar DP import/receive is authorized by this roadmap alone. Such changes remain separately gated by the existing repository rules.
