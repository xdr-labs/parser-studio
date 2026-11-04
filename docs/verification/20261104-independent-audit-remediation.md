# 2026-11-04 Parser Studio independent audit remediation

Baseline: xdr-labs/parser-studio main `2ab6027b03bdbf356e97a7f4b5dae2abcacd188e`. The approved change is implemented and verified in an isolated branch. Real Stellar Cyber DP 7.0 runtime compatibility remains an independent launch gate; no actual DP upload or ingestion is claimed.

## Fixes

| Finding | Corrective control |
| --- | --- |
| AUD-01 P1 · short regex can hang the browser preview | Reject quantified nested groups (including counted repeats) in the frontend and backend validators; route AI correction candidate previews and final rechecks through the 15-second-terminated browser Web Worker for custom regex. |
| AUD-02 P1 · competing literal dotted and nested source keys | Detect multiple JSON path interpretations. Browser normalization rejects ambiguity with `AMBIGUOUS_SOURCE_PATH`; generated Ruby single and multi-family parsers raise a normalization error instead of choosing a potentially incorrect official IP. JSONata review rejects ambiguous/mixed source shapes and distinguishes literal ``source.ip`` from nested `source.ip`. |
| AUD-03 P1 · invalid official IP protocol | Enforce `proto` as integer 0–255 and `proto_name` as TCP/UDP/ICMP/IGMP in the browser scalar validator and both native Ruby templates. Manual ChatGPT mapping review cannot waive those value constraints. |
| AUD-04 P2 · mapping prompt silently omits 101st field | Reject a mapping prompt containing over 100 distinct safe field paths with a clear explanation. Split samples by coherent event types rather than claiming partial prompts cover every source field. |
| AUD-05 · dependency advisory | Lock backend transitive `fast-uri` to patched `3.1.9`. Production npm dependency audit must report zero vulnerabilities. |

## Native POC safety

Changing the generated Ruby template invalidates the previously pinned disposable POC SHA. The new audited template SHA is `d0f276cdff8708a2d8a7b4d120963d96e08bd521679b542e104b43ef1e4b8eb7`. The change is appended to the exact closed template allowlist; all original owner approval, loopback-only, null-sink, synthetic project identity, tenant, port, recompile byte-comparison and audit requirements remain intact. No general parser upload has been enabled.

## Acceptance and evidence

- New browser unit tests: source shape collision and literal dot selector semantics, multi-sample inconsistencies, official protocol constraints, 115-field prompt rejection, regex nested-count rejection and worker timeout/termination.
- New native Ruby tests on single and event-family templates: ambiguous JSON field and incorrect transport protocol rejection, good nested/flat formats preserved.
- Legacy API POC upload guard regression verifies current audited template and gate invariants.
- Full frontend Vitest, TypeScript production build, backend Node native/Ruby/Drain3 suite, production lockfile vulnerability audit, and Chromium documentation-corpus E2E must all pass on the exact candidate HEAD before public preview deployment.
- Release remains limited to the development preview. Generated parser manifests remain DRAFT, without target import or runtime-ingestion claims.

Security advisory: https://github.com/fastify/fast-uri/security/advisories/GHSA-wjr9-j795-jxcr

The source-path schema cannot predict unseen future log-shape changes. Real production logs must be representative, and mappings must stay reviewable.
