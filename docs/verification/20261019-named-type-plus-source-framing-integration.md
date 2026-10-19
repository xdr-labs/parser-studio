# Development-only integration: individually named log types + lossless stream framing

2026-10-19 — merged candidate only, not main or public deployment.

## Source contracts retained

- Base owner-approved public development feature: f789736ff625220182300976949997e354d11670
  (Draft #102; deployed on app.parser.xdr.ooo, 15/15 public Chromium previously PASS).
- Parallel PoC source-only improvements: 98ef0ec89adf459b3452e23c0221fd3ed26b1a2c
  (Draft #103 stacked on #101; original source-container and compiler-readiness fixes).
- Integration branch merges both isolated development revisions. No protected dirty worktree
  or existing published binary was edited; no GitHub PRs were merged.
- Both NamedLogTypesPanel and the original-source CRLF file-upload advisory remain on
  Add Logs. Source byte span accounting and the new compatibility warning are retained.
- The single AutoParser conflict was resolved conservatively: navigation to Review Fields
  requires both named-group validation and no compiler-readiness block. Downloads continue
  to require all source events accounted for, explicit backend authorization and verified
  current mappings. A group label never becomes an invented runtime event discriminator.
- Original Audit/CRI/Docker, header-dependent W3C/Zeek and RFC framing have source
  recognition but no qualified native original-stream compiler and remain PARTIAL/RAW_ONLY
  with actionable beginner guidance. No false support for target import or sensor ingest.

## Actual integration qualification

- Compiler/TypeScript npm run typecheck PASS.
- Full frontend TypeScript + Vite production build PASS.
- All date-scoped offline Python regressions 37/37 PASS.
- Actual Playwright CLI Chromium and real isolated parser services:
  4/4 named-log-type user journeys + 4/4 Audit/CRI/Docker source-only journeys = **8/8 PASS**.
- Three original PR #101 CI novice-corpus failures (duplicate KV, pfSense and OPNsense
  source-only block/recovery) separately re-exercised: **3/3 PASS**.
- The previous full baseline suites are not rebranded as new independent manufacturer
  benchmarks. Cross-source containment must continue to fail closed on unqualified
  compound transport/record combinations.

## Release boundary

This combined source is a Draft review candidate, NOT installed on
app.parser.xdr.ooo, not merged to main, no DP/sensor operations and no change
to the running authoring backend, Nginx or TLS. Before any future deployment,
verify exact-head CI, owner-authorized review of the combined product, and
record rollback and unchanged Exporter separately.
