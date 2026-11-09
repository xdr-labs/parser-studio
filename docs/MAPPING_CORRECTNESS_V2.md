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

## Scope and release safety

Maintain source parser Grammar-first / Multi-Pass and do not invent per-vendor case patches. No main merge, public preview rollout, production/sensor restart, permissions/branch-protection change or Stellar DP import/receive is authorized by this roadmap alone. Such changes remain separately gated by the existing repository rules.
