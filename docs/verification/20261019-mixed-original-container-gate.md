# Mixed named log types: no original-container compiler bypass

Date: 2026-10-19. Isolated Draft candidate based on exact source SHA
0ae241fd2c7ad05453156d15dd53bdb9e9839534 (CI SUCCESS, Draft PR #106).

## Root cause

When original input started with ordinary independently supported JSON, a
later event containing a Docker JSON-file wrapper, Kubernetes CRI source,
Linux audit record, Zeek/W3C declared header or RFC framing could be masked
by the first event's ordinary browser JSON result. The earlier strong
original-container compiler gate inspected the beginning of the *entire*
sample, not all physical record starts. Even with individually named
Threat/User/Container input groups, the original Docker wrapper could remain
unblocked when a different JSON type came first.

### Frozen identical authored source regression

- 8 strong synthetic second-row/original-CRLF cases were RED with the old
  exact SHA source gate, despite its standalone original-container tests
  passing. Ordinary JSON + Docker, CRI, Linux audit, octet-counted JSON,
  W3C/Zeek headers, RFC7464 and CRLF-before-Docker were missed.
- Generic fix scans every physical record start in the bounded original UTF-8
  input and preserves the same first-party, negative-only protocol signatures.
  No original byte or user-defined sample is modified. The gate can *only*
  prevent claiming unsupported downloadable compiler status.
- Strong same-source FRAMING/SCHEMA evidence from Python remains
  authoritative when present. Source user names are never used as
  compiler predicates.
- Existing ordinary JSON multiple events, CEF, LEEF, KV, and supported
  mixed sources remain unaffected by original-container signatures.
  A value merely containing the textual word "log" is not a source
  container signature.

## Reproducible evidence

- Deterministic before/after new source gate: **8 RED / 9 GREEN** new
  bounded cases, with prior 3/3 core gate cases remaining green.
- Real local Playwright CLI Chromium with actual Python Multi-Pass and
  pinned offline HTTP backend: **2/2 PASS** for (1) ordinary JSON followed
  by Docker source and (2) separately named Threat/User/Container groups,
  both in Advanced Tools. No false Review Fields/DRAFT promotion, no
  raw-source mutation, no API mocking or auto-LLM transfer.
- Exact-HEAD GitHub CI is updated to require **27 executed, zero skipped**
  named/mixed original-container/routing/physical-boundary user cases
  plus the established web, parser, sender, backend/HTTP and compatibility
  regressions. This is a development-only change; CI must pass on committed
  SHA before any deployment claim.

## Limitations

This is source/parser compiler-readiness evidence only. It is not a
manufacturer/firmware semantic accuracy oracle, Ruby original transport
loader verification, Stellar DP installation or event-ingestion receipt.
The public owner-authorized https://app.parser.xdr.ooo/ stays on the
existing pinned development build until the exact deployed frontend AND
source engine qualify together. Do not merge Draft PRs, change Nginx/TLS,
or send to sensors under this scoped PoC.
