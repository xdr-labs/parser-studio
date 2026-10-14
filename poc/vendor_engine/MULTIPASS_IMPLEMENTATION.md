# Accuracy-First Multi-Pass Parser Integration

## Owner decision

Keep the current PR #16 security-source engine as the base. Integrate only independently verified additive extraction primitives from PR #15. Accuracy of native source identity, typed value and exact UTF-8 span is the primary gate. Runtime is observational only; bounded CPU/memory/input/depth and regex safety remain mandatory.

## Frozen MP-0 baseline

- PR #16 HEAD: `9d3f1ff57f53aba8268b2ad216eecc67421dfa2a`.
- Python PoC: 233/233 PASS, zero skips/errors/failures.
- Commercial source oracle: 27,968 TP / 0 FP / 0 FN on 391 scored records; one malformed source remains excluded from correctness and retained raw/PARTIAL.
- Security framing v2: 6,048 TP / 0 FP / 0 FN; 216/216 exact record trees and boundaries.
- Independent evidence HEAD: PR #15 `872e3a583844bbbc0aa56f9d185936273c5baa33`, evidence only, not merged.

## Ordered implementation

MP-0 baseline freeze -> MP-1 candidate/evidence contract -> MP-2 CEF additive pass -> MP-3 LEEF xHH pass -> MP-4 declared-schema state isolation -> MP-5 deterministic adjudicator -> MP-6 bounded residual recursion -> MP-7 security regression gate -> MP-8 engine decision.

No broad prose/template-mining work, Dictionary mapping, masking optimization, UI, native target writes, production, merge or release is part of these MP stages.
