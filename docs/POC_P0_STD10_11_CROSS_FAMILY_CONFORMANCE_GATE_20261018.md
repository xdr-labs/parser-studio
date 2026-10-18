# P0-STD-10/11 — Isolated cross-family conformance gate

**Scope:** Parser Studio Issue #1 standards-first source grammar PoC, not
product/main/native integration, deployment, or merge. Base is PR #52
exact 492964acf36594be02a6c10f14f43dfa1c90614a.

## Source-only combined candidate

The qualified isolated changes from Draft PRs #56 through #67 were
cherry-picked onto a NEW independent worktree/branch only, in dependency
order. Original Draft PRs and both pre-existing dirty worktrees are intact.
Only import adjacencies were resolved (CEF/LEEF/JSON/KV in the common
structured family and JSON/CSV in the browser preview). No vendor regex
or blind union of candidate fields was introduced.

The machine-readable coverage ledger
scripts/poc/standardCrossFamilyEvidenceLedger.v1.json maps 11 precise
standards/source subsets to their real implementation paths, tests and
immutable pre-frozen expected-answer SHA256 digests. Its generator and
test are buildStd10CrossFamilyEvidenceLedger.py and
src/poc/standardCrossFamilyEvidenceLedger.test.ts.

The frozen cases include **143 standards-derived synthetics** across
RFC6587/5424, CEF, LEEF, JSON, CSV, KV, Zeek, W3C and multi-pass
ambiguity. These are NOT newly independently certified manufacturer
wire accuracy. A separate W3C publisher-authored illustrative example
(4 physical events, 12 explicit original field name/value/UTF-8 span
claims) was verified with TP=12, FP=0, FN=0 and zero byte drift against
its privately stored 172-byte publisher original. This is NOT native or
real device production traffic. Copyright-sensitive original bytes
remain in mode 0700/0600 private dev-atlas storage; Git retains hashes
and expected claim digests only.

## Exact local evidence

On the source-composed candidate, the original 11 focused standards
test files and 155 tests PASS. A new dedicated cross-format regression
suite checks ten integrated source safety routes plus the existing
SHA/traceability ledger test: 11/11 PASS. Updated full Vitest:
**199 files / 1,409 tests PASS**, TypeScript + Vite build PASS.
Original safety replay: 1,361 historical originals + 2,892 mutated
invalid records (197 REVIEW_ONLY unchanged), plus 50 previously
independent source examples: zero changed results, original byte drift
or unverified auto-promotion. Historical samples are safety only,
not a newly scored holdout.

The new Draft PR still requires exact-HEAD GitHub quality CI, including
Chromium scenarios and independent loopback HTTP integration. Do not
claim CI success before it is observed.

## Cross-family false-complete and source boundary convergence

A separate source-stage test,
src/poc/standardCrossFamilyConvergence.test.ts, guards shared behavior
after all standalone grammar patches are composed. Ten direct invariants
use independent source text and check RFC6587 original byte framing,
RFC5424 legal repeated SD-PARAM/unknown escapes, CEF required header
and severity, LEEF declared delimiters, RFC8259 duplicate/overflow/
surrogate rejection, RFC4180 source field-edge spaces, KV complete
consumption/unknown escaping, Zeek terminal #close, declared W3C
quoted source fields, and ambiguous KV-vs-positional CSV nonpromotion.
Those are **compatibility regression assertions**, not ten new
manufacturer accuracy goldens. The immutable SHA ledger is checked
separately and its evidence categories are never upgraded by these
synthetic cases.

The exact full-suite test count and GitHub Actions status for the
updated HEAD must be recorded after these extra regression assertions
are committed and verified. The earlier 197-file/1,398-test count
describes the prior source-composed HEAD only.

## Remaining qualification

Real publisher/manufacturer wire originals and independent field goldens
remain needed for mixed forwarder/relay host/time, RFC5425 secure
transport, CEF extensions, LEEF duplicates/empty values, custom
producer CSV columns and multi-line records, JSON complete nested
source spans, KV producer escape semantics, Zeek/W3C schema rotation,
bounded Funnel native arbitration, and actual Stellar/Fluentd target.
Unproven results remain PARTIAL/REVIEW_ONLY/UNSCORABLE.

Product HEAD da94aa9, roadmap PR #51, Draft PRs #52..67,
frontend 11 and backend 10 dirty entries remain untouched.
No product, main, actual native targets, DP, sensors, credentials,
production, deployment, release or merge authorization exists.

## Reproduction

    python3 scripts/poc/buildStd10CrossFamilyEvidenceLedger.py
    npx --no-install vitest run src/poc/standardCrossFamilyEvidenceLedger.test.ts
    npm test
    npm run build
    npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
    npx --no-install tsx scripts/poc/scoreStd9PublisherW3cExample.ts
    git diff --check

The last scorer requires the protected original and fails UNSCORABLE
rather than fabricating publisher source when absent.
