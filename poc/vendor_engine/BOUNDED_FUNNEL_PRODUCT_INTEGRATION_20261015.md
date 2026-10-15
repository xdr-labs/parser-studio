# Bounded Funnel Auto Parser Product Integration — 2026-10-15

## Decision implemented

Parser Studio keeps the qualified Multi-Pass / Generic Structural source engine
as the baseline and adds a bounded multi-pass Funnel orchestration layer above
it. This is additive product integration, not a replacement parser.

Integration base:

- product base: 4596f4629a4cb7b900eb459cadffb0d2813c7957
- source Draft PR: #21
- research evidence branch: poc/funnel-beam-autoparser-20261015
- research evidence HEAD: f0e5aedbb38327c2adc291fa0232698ea3e7dfcc

The existing dirty novice E2E, UI, backend and PR #21 worktrees were preserved.
This implementation was developed in an isolated worktree and branch.

## Product path

Internal flow:

qualified Multi-Pass -> parser fan-out -> residual candidates -> bounded batch structural learning -> replay -> deterministic no-loss selection -> converge/bound

Product modules:

- multipass_adjudicator.py: unchanged qualified baseline engine.
- structural_funnel.py: bounded cross-event structural hypothesis primitives.
- bounded_funnel.py: product orchestration, replay, safety gates and beam abstraction.
- multipass_preview_api.py: Auto Parser preview now invokes the Funnel product
  entry point; batch preview performs bounded local batch learning and replay.

## Initial product policy

- Default beam width is 1.
- Maximum pass count is 6.
- Observed real maximum depth is 3.
- Existing SOURCE_PARSED results are immutable and return immediately.
- Existing accepted source spans cannot be removed or reinterpreted.
- Partial recovery can only add source-backed spans and remains incomplete.
- Learned complete promotion requires raw preservation, no-loss and adversarial
  mutation/anchor safety.
- Direct Generic Structural admission on arbitrary residuals remains disabled.
- Runtime is not used for ranking or acceptance.
- Batch size is bounded to 500 events at the Funnel product boundary.

## Product qualification

The product-integrated implementation was rerun against the exact research
evidence sources using the product default beam_width=1.

### Independent positive reference

- 158 / 158 added source spans exact.
- 0 unvalidated extra ranges.
- Cisco Secure Email: 44 / 44.
- Snort IDS/IPS: 60 / 60.
- Sophos UTM: 54 / 54.

### Fresh negative holdouts

- holdout #2: 49 / 49 baseline-incomplete events abstained.
- holdout #3: 1 / 1 baseline-incomplete event abstained.
- complete divergence: 0.
- raw mismatch: 0.
- baseline span loss: 0.

### Real chained replay

WatchGuard development replay:

- 48 / 48 added spans independently validated.
- 6 chained events.
- extended-BSD -> typed-label stacking preserved.
- maximum observed depth: 3.

### Broad security stress

Three deterministic splits:

- eval events: 3,621.
- improved events: 855.
- added source-span occurrences: 5,844.
- prior complete exact preserved: 2,167 / 2,167.
- complete promotions: 8.
- mutation attempts: 32.
- mutation false-complete: 0.
- raw mismatch: 0.
- baseline span loss: 0.
- prior complete divergence: 0.

### Pass / beam ablation

- one pass, beam 1: 5,794 spans.
- up to six passes, beam 1: 5,844 spans.
- multi-pass gain: +50 spans.
- beam 4 additional gain over beam 1: 0.
- maximum observed pass: 3.

This confirms the initial product policy: repeated bounded passes provide a
measured accuracy gain; widening the beam currently does not.

## Regression evidence

Local exact implementation worktree:

- focused Funnel + Structural + preview product tests: 50 PASS.
- full vendor_engine: 447 PASS / 4 optional skips / 0 failures / 0 errors.
- web unit tests: 556 / 556 PASS.
- TypeScript/Vite production build: PASS.
- same-candidate local Chromium tests that do not require the pinned live
  backend: 12 PASS / 26 conditional skips / 0 failures.

One unrelated local browser scenario hard-codes origin port 5180. That port is
owned by the preserved novice-E2E worktree on dev-atlas, so it was not killed or
reused. The complete browser matrix is therefore delegated to exact-HEAD GitHub
CI on an isolated runner after push.

## Non-claims / gates retained

This integration does not merge a PR, release, deploy production, modify
credentials/auth, touch a target loader, DP/sensor, native target state, or
claim native target verification. Browser / Full User E2E and exact-HEAD CI
remain release-readiness gates.
