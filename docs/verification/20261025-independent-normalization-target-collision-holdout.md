# Independent QA holdout — hierarchical normalization target collisions

Date: 2026-10-25. Repository: `xdr-labs/parser-studio`.

## Requirement and source identity

The product must block two normalization mappings whose destination paths are identical **or** have a parent/child relationship, such as `custom.actor` and `custom.actor.id`. The reverse declaration order must be equally safe. Two sibling leaves (`custom.actor.id` and `custom.actor.name`) and unrelated lexical prefixes (`custom.actorId`) are not collisions. All source event values must remain unchanged during validation.

- Target development source before the test-only change: `4ca65ebafcde67f02bd296357d4340e216feecbc` (PR #159 integrated, already published on development Web).
- The implementation in `src/guided/normalizationValidation.ts` is **unchanged** from `567e0c255312028337898114cac452567bc585cc`; the existing implementation already satisfies the requirement.
- The independent requirement originated in the bounded Engineering System AI QA source-mutation pilot (Issue #317; Draft PR #318). It is a previously untested regression guard, **not** a newly discovered product defect.
- The only executable source diff is three additional Vitest cases in `src/guided/normalizationValidation.test.ts`: parent-first, child-first, and non-colliding sibling/prefix controls.

## Actual native Vitest and isolated source mutation

- Before adding these assertions, original product tests **3/3 PASS**.
- After adding the assertions, all current, unmodified product tests **6/6 PASS**.
- A separate `git archive` of the exact original product commit was modified **only inside a disposable private sandbox**, replacing the path-overlap predicate with `return a===b;`. This intentionally removes parent/child detection while leaving identical-field collision detection.
- Against the same deliberate mutant, the original 3/3 tests **still PASS**, but the extended six-case suite returns **2 FAIL, 4 PASS**: both independent parent/child counterexamples catch the injected defect. The false-positive controls still pass.
- Source-mutation logs (not model or hosted CI evidence):
  - Existing suite: `/home/aella/.local/state/parserstudio-independent-collision-qa-20261025/mutant-with-existing-tests.log`, SHA-256 `2e715402e7bcd913840aec5a3763658c8d12ab0999574017471576f05562763f`.
  - Extended suite: `/home/aella/.local/state/parserstudio-independent-collision-qa-20261025/mutant-with-independent-holdout.log`, SHA-256 `14115e65168216c65394b661d5c07dd824fbb330d18136fe7e41064ac0e7aa54`.

## Evidence boundaries

This is one selected, syntax-valid, intentional TS mutation with real Vitest execution, **not** a StrykerJS/global mutation score, vendor semantic validation, independent ChatGPT provider inference, full user E2E or Stellar Cyber runtime qualification. It does not change parser behavior, source values, any runtime bundle or the public development server. PR #159 remains untouched and unmerged; no production release or main merge was authorized.
