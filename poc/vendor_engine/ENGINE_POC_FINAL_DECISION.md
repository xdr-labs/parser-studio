# Accuracy-First Parser Engine PoC — Final Decision

Status: **ENGINE POC IMPLEMENTATION COMPLETE; INDEPENDENT GENERALIZATION GATE NOT QUALIFIED**.

Selected engine: `multipass_adjudicator.parse_security_multipass` with `security_source.parse_security_source` preserved as the base. No wholesale replacement, semantic Dictionary inference, hidden-mask reconstruction, native target writes, production deployment, merge or release is authorized by this decision.

## Completed engine milestones

MP-0 through MP-8 are implemented and committed. Qualified CEF and LEEF candidates, declared-schema isolation, deterministic conflict adjudication, bounded residual recovery, source-field and framing gates, and the source-engine selection test are included. Follow-up corrections prevent newline and indented-newline Syslog event headers from being absorbed as fields of a preceding event.

## Measured acceptance evidence

- Original WAF/Suricata security JSON: 2,110 TP, 0 FP, 0 FN on 77 records.
- Derived CEE security records: 5,127 TP, 0 FP, 0 FN on 198 records.
- Commercial NGFW fixture reference: 27,968 TP, 0 FP, 0 FN on 391 scored records; one malformed FortiGate record is excluded and preserved PARTIAL.
- Commercial CEF: 482 TP, 0 FP, 0 FN; authored CEF: 900 TP, 0 FP, 0 FN.
- Authored LEEF xHH: 3,552 TP, 0 FP, 0 FN; pinned documentation xa6 example: 19 TP, 0 FP, 0 FN.
- Stream framing: 6,048 TP, 0 FP, 0 FN; 216/216 exact record boundaries/trees.
- Authored residual security bodies: 2,160 TP, 0 FP, 0 FN; 72/72 exact.
- Derived 500-case JSON lexical mutation stress: 13,764 TP, 0 FP, 0 FN, 500/500 exact records, raw preserved, false-complete 0. These are derived from 77 known source events, NOT 500 unseen vendor/version records.
- Source engine full local suite: 291/291 PASS. Exact-head GitHub quality CI #177 SUCCESS on `657b50664edd2f0854940ef308af6a3ae0cdf144`.

## Scope limits and handoff

The 500-case mutation stress does not meet the proposed independent unseen vendor/version corpus gate (500 genuinely independent events, exact field/value/type/span F1 >=99%, complete event rate >=95%, false complete 0). This gate is **NOT VERIFIED**; do not label it PASS, or describe source PoC evidence as native Ruby/CONF/DP/sensor E2E. Existing samples do not establish production/generalized accuracy. New unseen fixtures must have independent, source-backed reference fields and version provenance, and remain private until licensing is reviewed.

**Decision:** stop unbounded algorithm exploration and accept the verified multi-pass source engine as the selected Auto Parser source-extraction candidate for product integration. Treat the missing independent vendor/version generalization and native target qualification as separate explicit downstream acceptance gates, not hidden engine-PoC completion claims. Preserve the pinned benchmark and regression suites; new failures require RED -> minimal correction -> GREEN -> full regression -> exact-head CI.
