# Third-party Syslog-ng independent source-field evaluation — negative result

Date: 2026-10-17. This evidence-only isolated PoC is stacked on the unchanged Draft PR #45 SHA 7b05891ab30406b241d046d179fb48f11001db9b. No product/main parser edits, DP/sensors/credentials/deployment, release or merge.

## Independent provenance and qualification

A third distinct public GitHub repository, syslog-ng/syslog-ng, source revision fddad8aaad25f008d49e8fb30d018946941c2414, file modules/syslogformat/tests/test_syslog_format.c, was obtained and SHA-pinned **before comparing any parser behavior**. Original bytes: 21,230. Original file SHA: bf392e459cf0dbedbf99222c744cea69f9523610b1c3223ad45f8dd398044a66. This upstream repository reports ambiguous license metadata; original test content is **private only**, never republished into Git. Public metadata: scripts/poc/syslogngIndependentSource.pinned.json. Prior standalone projects Influx, OpenTelemetry and Elastic are not credited as new samples here.

A separate Python-only reference extracts a static original C input string and upstream C unit-test *assertions* for HOST, PROGRAM, PID, and MSG, then verifies unambiguous independent exact-value source byte locations. It does not inspect TypeScript/parser output when generating ground truth. Original raw events, expected source names and values, and per-field byte evidence remain private under ~/.local/state/parserstudio-syslogng-independent-20261017, directory mode 0700 and files mode 0600. Private reference SHA-256 3d39c8fecb9a89fef56eacb5f42319771be342fa59ade90453661a73b2e4e7fd.

36 independent upstream C test cases identified; **7 source-partially-scorable cases with 19 independently asserted field/value/byte triples**; remaining **29 UNSCORABLE** due to missing literal original, insufficient explicit assertions, or source-location ambiguity. Full source-field tree expected outputs are not available, so **do not compute or claim complete-event exactness, total field recall, or FP on unasserted fields**. No manufacturer original-device packet/semantic certification.

## First blind outcome — the regression must not be concealed

Both parsers were evaluated **on the exact same previously frozen partial field assertions**. The candidate is the previously sealed, unchanged generic Syslog observer source SHA 823ed184a49ea60ef77e5e85d0e27ebbd15eb677158aacbfaaffb9a975c502cb in src/poc/generalSyslogEnvelopeSpans.ts. There is no candidate code change or replay-as-fresh.

| Honest scoped metric | Unchanged baseline parseSyslogEnvelope | Isolated generic PoC #45 |
| --- | ---: | ---: |
| Independently asserted positive original fields | 19 | 19 |
| Upstream asserted names + values that matched | **10/19** | **3/19** |
| Exact original source value + UTF-8 byte triples | Not exposed | **3/19** |
| Unmatched/upstream-asserted fields | 9 | **16** |
| Source-partial cases with candidate abstention | N/A | **5/7** |
| Full original event exactness | UNSCORABLE | UNSCORABLE |
| FP on unasserted source fields | UNSCORABLE | UNSCORABLE |
| Original raw bytes retained | 18/18 available | 18/18 |
| Automatic promotions and unauthorized native qualification | None | 0 |

This is an **adverse generalization result**: the new isolated RFC3164/RFC5424 grammar is significantly narrower than the existing general Syslog envelope path for some independent BSD and noncanonical source layouts. Earlier PR #45 development and limited OpenTelemetry tests are genuine but insufficient to establish broad improved unknown-format success. The 3/19 matched triples here are scoped only to explicit upstream assertions. The negative result is evidence **against automatic product integration**, not a reason to cherry-pick matching fields or patch a single manufacturer's regex.

The new stage remains isolated and REVIEW_ONLY or ABSTAIN_UNSAFE; a lexical/envelope match is not full source success. No shipping parser was altered; there is no regression to an actual product branch.

## Safe next structural experiment

1. Treat broader RFC3164 whitespace/tag/message ownership and safe body residual adjudication as common grammar dimensions. Never make one-off syslog-ng vendor/source-specific branches.
2. Use these 7 upstream asserted cases only as a **development error-analysis set** for a NEW structurally different candidate; they cannot be reclassified as a fresh blind result after tuning.
3. Before any next cross-project accuracy claim, obtain a NEW, separately pinned and withheld independent source holdout (e.g. another upstream C/Go/Rust parser's explicit expected-value cases) and freeze it before candidate inspection. Check byte triples, field FP/FN only where independently complete expected truth exists, malformed controls, raw retention and abstention.
4. Preserve the candidate SHA, private oracle, and negative outputs; a future qualified replacement remains isolated unless specifically authorized for product integration.

## Reproduction

Run in the isolated PoC worktree:

1. python3 scripts/poc/pinIndependentSyslogngHoldout.py
2. python3 scripts/poc/freezeIndependentSyslogngOracle.py
3. python3 -m unittest discover -s scripts/poc -p testIndependentSyslogngOracle.py -v
4. node_modules/.bin/vite-node scripts/poc/runIndependentSyslogngFieldHoldout.ts
5. npm run typecheck && npm test && npm run build

All first-comparison original outputs are immutable and private. Git stores only evidence infrastructure and source SHA/summary, never source original contents or expected values.

## Product and governance boundary

Prior Draft PR #43 (44e6063), #44 (25e0c8c), #45 (7b05891), product HEAD da94aa9, older PoC worktrees, main, DP, sensors, deployment, credentials and all releases are unchanged. The product roadmap R1 Juniper/Defender/Umbrella, R2 beginner feedback, R3 mapping UI visual acceptance, R4 same-HEAD owner approval remains handoff-only, with NO integration permission.
