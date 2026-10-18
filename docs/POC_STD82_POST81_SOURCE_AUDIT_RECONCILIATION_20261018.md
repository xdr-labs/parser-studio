# P0-STD-82 — Post-PR81 Standards Source Evidence and Risk Reconciliation

## Decision boundary

This document reconciles Parser Studio's source-only P0-STD audit after independently isolated Draft PRs #69–#81. No claim is made that the entire parser engine is compliant with every supported standard, that source-level synthetic lexical cases establish real manufacturer accuracy, or that any Stellar/Fluentd native artifact has passed execution.

Canonical authority: Issue #1 P0-STD roadmap and ACTIVE Work Packet. Exact code baseline for this isolated addendum is Draft PR #81 HEAD 309189334fcfd3328c4dc15be11a30c3645de34c. Preserve previous Draft PRs, product/main, existing frontend/backend dirty worktrees, native adapters and live environments.

## What is now tracked and machine-verified

- The original **11** source-code/test/oracle rows remain immutable in scripts/poc/standardCrossFamilyEvidenceLedger.v1.json (SHA256 5de2502812b4e8b8f587a91af825c4e526736f179d26e8b9f28da2016075325e).
- The initial **19** risk observations remain immutable in scripts/poc/standardCoverageLedger.v1.json (SHA256 33d3ea9be0d98b77119bd199c2deabffd51afdb59f8a6fc57f3d1cbefb5ecc4c); each gets an explicit new current interpretation, linked to a specific source PR or marked unresolved. A previously observed defect is not silently erased from a historical audit.
- **11** authoritative source reference records remain immutable in scripts/poc/normativeGrammarSources.pinned.json (SHA256 401ea5dd49f89e9ef96abf894d50237b054a0ae4f54b8a548476ddde03355b12). They distinguish Standards Track RFCs, Informational RFCs, vendor CEF/LEEF definitions, W3C draft and Zeek pinned source.
- New scripts/poc/standardPost81Traceability.v1.json provides **13** additional PR #69–#81 rows. Together with the prior 11 source evidence rows, there are **24 traceable code/test/oracle entries**, NOT 24 certified formats.
- Every new row records PR exact HEAD and observed GitHub quality-check status, normative section/revision, actual implementation file, function symbol and line, test path, pinned oracle SHA and count, remaining risk and explicit nonpromotion flags. These fields are machine checked against the actual current source checkout.
- These entries contain **177 standards-authored synthetic cases**, **6 publisher-documentation illustrations** and **0 new oracle cases** for PR #75 integration composition. Cases may overlap earlier oracles; counts do not represent distinct production events or generalization rates.
- Previously frozen **1,361** original source events, **2,892** historically mutated-invalid cases (197 still REVIEW_ONLY), and 50 earlier independent source examples are strictly *historical safety replay*. They cannot be scored as fresh manufacturer oracle truth.

## Narrow source evidence versus unresolved risk

| P0 slice | Relevant PRs | Narrowly demonstrated | Still unverified |
| --- | --- | --- | --- |
| RFC3164/5424/6587 framing / RFC5425 provenance | #71/#72/#78/#80/#81 | Context-aware counted messages, opaque original octets, independent source/relay host-time labels | Paired actual upstream/collector captures, independently verified TLS peer identity, device clocks, native |
| CEF source extension | #69/#70 and earlier CEF qualification | Exact escaped lexemes and decoded values on bounded examples, no blind key-looking split | Actual producer firmware/wire decode semantics and native parsing |
| LEEF source | #79 and earlier LEEF tests | Preserve zero-byte present values and ordered duplicate occurrences | Producer/null and QRadar/Stellar repeated-key policy |
| RFC8259/7464 JSON | #76 and earlier JSON preflight | Nested JSON Pointer original UTF-8 intervals and representation guards | Full independently scored device nested fields/types and native |
| RFC4180 CSV | #77 and earlier CSV lexing | Multiline logical rows, quoted CRLF, source intervals and empty cells | Manufacturer column definitions, native stream and forwarded event |
| Zeek and W3C | #73/#74 plus earlier format guards | Bounded schema lifetimes, close/rotation and required directives | Real publisher version and native outcomes |
| Cross-family adjudication | #75 plus older Funnel gates | Composition regression with no new unproven success claim | Independent unknown multi-family holdouts and one native parser artifact |

## Highest remaining audit and product risks

**High — original producer and relay provenance.** No general matched source-device/collector raw capture pairs with producer-frozen expected values and independently authenticated transport/clock context. A Syslog HOSTNAME is not TLS peer authentication and a documented format option does not prove actual vendor wire mode.

**High — native parser and product integration.** None of these source-only improvements authorizes native Fluentd/Stellar certification, exported multi-event parser, DP/sensor writes, production, release or merge. The qualified Multi-Pass + Generic Structural + bounded Funnel architecture remains the product base. The actual product reference da94aa9 has not been changed by the isolated audit.

**High — manufacturer semantics.** Repeated LEEF fields, KV unquoted empty assignments, producer positional CSV, vendor escapes, device version-specific timestamps and masked tokens must remain lexical observations, not guessed null/default, source identity or native mapping.

**High — 197 historical review cases.** The 197 of 2,892 malformed mutation set consists of 171 Sophos-shaped KV lexical REVIEW_ONLY and 26 RFC3164 header-only REVIEW_ONLY proposals. They lack independently certified actual vendor negative truth. Do not incorrectly score all 197 as true positives/false positives or coerce automatic rejection. Prior source VETO, byte accounting and no-auto-promotion controls remain mandatory.

## Next acceptance gates

1. Exact-head GitHub quality CI must succeed on this standalone Draft PR: deterministic Vitest, English-only, TS/Vite build, Chromium scenarios, pinned localhost HTTP backend. Historical source safety replays must separately pass. Source tests never prove native or manufacturer compliance.
2. A real manufacturer evaluation requires privately sealed upstream and receiver raw captures, device/relay firmware, forwarding configuration, transport identity, and independently expected source field names/values/types/UTF-8 spans. Only then compute precise TP/FP/FN, complete-event correctness, abstention and false-complete on eligible denominators.
3. Product integration and native validation require separate owner acceptance. Preserve a single final Stellar parser for multiple event families, the explicitly user-defined CSV field schema, prefix/postfix selections, conditional normalization, and novice Web UI Full User E2E. Do not merge all evidence PRs into product without this gate.

No target devices, DP, sensor, credentials, native loader, deployment, production, release or Git merge were accessed.

## Reproduction

~~~sh
python3 scripts/poc/buildStd11Post81Traceability.py
npx --no-install vitest run src/poc/standardPost81Traceability.test.ts \
  src/poc/standardCrossFamilyEvidenceLedger.test.ts \
  src/poc/standardCrossFamilyConvergence.test.ts
npx --no-install tsx scripts/poc/auditStandardsCoverage.ts
npm test
npm run build
npx --no-install tsx scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
npx --no-install tsx scripts/poc/auditHistoricalMalformedReviewBounds.ts
npx --no-install tsx scripts/poc/runIndependentNonJsonSafetyReplay.ts
git diff --check
~~~

Every count is scoped historical/synthetic source evidence, NOT blanket standard, manufacturer or native certification.
