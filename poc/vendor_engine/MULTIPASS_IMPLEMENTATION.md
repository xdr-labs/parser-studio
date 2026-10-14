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

### MP-2 CEF additive pass

`security_cef.py` is a qualified CEF-standard candidate, not a global replacement. Local exact-source evidence: commercial CEF 22/482 remains 482 TP / 0 FP / 0 FN in base and candidate; authored CEF 96/900 improves 840/36/60 to 900/0/0, exact records 48→96 and false-complete 36→0. Malformed controls remain raw/incomplete and never become complete. Private source files remain ignored.

### MP-3 LEEF xHH additive pass

`security_leef.py` runs only when the base explicitly reports an unsupported LEEF delimiter. It adds exact `xHH` recognition while existing literal and `0xHH` paths remain unchanged. Authored xHH conformance is 192 records / 3,552 exact fields at 3,552 TP / 0 FP / 0 FN; the frozen documentation `xa6` example improves 0/19 to 19/19. Malformed/incomplete xHH remains non-complete.

### MP-4 declared schema/document state isolation

`security_document.py` scopes explicit `#separator/#fields/#types` state to declared table rows. `#close`, separator rotation and field rotation destroy stale state; new fields require new types. Unknown `#...` records remain ordinary visible records. Active table state never captures JSON/WAF, CEF, LEEF, CEE/Syslog or native KV records. A deterministic 240-physical-record ledger has zero loss/duplication, 32/32 declared rows with exact trees/spans, 16/16 stale-type rows fail closed, and 96/96 interleaved security records remain byte/output-identical to the current parser.

### MP-5 deterministic candidate adjudication

`multipass_adjudicator.py` runs the qualified base, CEF-standard and LEEF-xHH candidates and compares exact source claims. Extraction-identical candidates preserve the base. Overlapping field/span or container ownership conflicts require a strictly higher independently-qualified evidence tier; equal-tier conflicts become explicit `MULTIPASS_AMBIGUOUS_CONFLICT`. Non-overlapping tree-compatible candidates may merge; incompatible tree ownership raises instead of unioning. Current commercial 27,968 fields remain exact, all 77 WAF/Suricata records are base-identical, while CEF900 and LEEF3,552/xa6-19 use their qualified candidates exactly.

### MP-6 bounded residual recursive parsing

`multipass_residual.py` runs only after MP-5 whole-record adjudication. It never
re-parses accepted spans. Residual recovery is restricted to explicit structured
sub-records owned by an already-recognized security envelope `body`; small
opaque wrapper labels remain residual and therefore keep the event PARTIAL.
Compatible child trees/spans are merged under the existing body container.
Conflicting ownership or overlap is rejected with an explicit residual conflict.

Recursion is bounded to depth 4 and 64 residual windows with cycle identity based
on absolute source range plus raw digest. Direct CEF/LEEF field limits cannot be
bypassed by later passes. Complete JSON/CEF/LEEF records are byte-for-byte result
identical with residual parsing enabled or disabled.

Self-authored security residual differential: 72 wrapped/nested WAF/IPS-shaped
records / 2,160 independently encoded target fields. MP-5 whole-record baseline
0 TP / 0 FP / 2,160 FN; MP-6 candidate 2,160 TP / 0 FP / 0 FN, 72/72 exact target
ledgers, raw 72/72, false-complete 0 in both. This is structural residual evidence,
not new vendor traffic or open-world accuracy. Full regression after MP-6:
279/279 PASS, zero skips/errors/failures.
