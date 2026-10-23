# Parser Studio — real-browser novice journey and contextual-tool cleanup (2026-10-23)

## Owner request / evidence boundary

Use real Web UI controls as a first-time user with diverse security logs, not a
source-code-only audit. Inspect all principal Auto Parser and ChatGPT Assisted
steps, identify confusing tools, fix demonstrated issues, and preserve supported
source/byte/compiler behavior. **Production, Stellar DP/sensor, target import
and mobile are not in scope.** All authored tests use noncustomer synthetic or
previously approved documentation fixtures; TEST-NET IP addresses are examples.

The public app was read and exercised **without modification**. The new source
was implemented and qualified in an isolated dev-atlas worktree, based on
`main=acf4ff7eba76613dee9c47135acb314847c34815`.
A passing local Vite/Chromium test does **not** mean this proposed UI has been
released to the public development app. Preserve the earlier deployed version
until a separate owner-authorized release decision and public exact-byte E2E.

## First-hand public HTTPS browser baseline — 12 different sample families

A new automated Chromium browser context was opened per sample on the actual
`https://app.parser.xdr.ooo/` URL, with a real text paste, Analyze Logs,
Review Fields, Map Fields and Create Parser Files where safe. Observed source
status and requested downstream parser authoring remain separate acceptance
categories.

| Source example | Observed result | Source/data boundary |
| --- | --- | --- |
| Two Suricata EVE-style JSON types | Reviewed DRAFT created | The controlled event corpus was structurally complete; no manufacturer-wide precision claim |
| RFC 3164 Syslog | Reviewed DRAFT created | Original two records retained |
| RFC 5424 Syslog with SD | Reviewed DRAFT created | Original SD and message inspected |
| Two CEF security records | Reviewed DRAFT created | Publisher/vendor dialects beyond input not certified |
| Two LEEF security records | Reviewed DRAFT created | Exact reviewed sample only |
| Two KV firewall records | Reviewed DRAFT created | Source original retained |
| Two quoted positional CSV records | DRAFT created after explicit column-name confirmation | Before confirmation 0/2 needed review; after confirmation 2/2 parsed, no bug |
| Mixed JSON + CEF + KV | Reviewed DRAFT created | Three records accounted, unsupported target claims not made |
| W3C with declared header | Review-only, no DRAFT | Two data events and two original schema/header lines; compiler not verified |
| Zeek with declared metadata | Review-only, no DRAFT | Two data events and seven metadata/header lines; compiler not verified |
| Snort/IDS free-form alerts | Review-only, no DRAFT | Structural residuals shown, no false complete |
| JSON with duplicate decoded key | Review-only, no DRAFT | Repeated key did not overwrite original evidence |

**Result: 8/12 sample families reached supported DRAFT generation; 4/12
correctly remained review-only.** No browser page exceptions were observed.
These are finite actual-user examples, **not** a global vendor field-F1 claim.
Read-only evidence is at
`/home/aella/.local/state/parserstudio-public-rollouts/parserstudio-full-browser-audit-20261023/results.json`;
the matching execution and screenshots live alongside that report. Private
source logs were not uploaded to GitHub.

## Three verified novice UX improvements

1. **Input visibility:** Actual baseline public screenshots at desktop widths
   1440 and 1280 placed the raw-log textbox approximately 1,168 and 1,188 px
   down the page — beneath 900/800 px first viewports. A new RED Chromium
   geometry test reproduced both. The proposed source moves the optional
   manufacturer/product/version/listener-port identity panel **after the source
   input and Analyze Logs**, compresses repetitive introductory copy, and
   makes the optional multi-type entry one compact line. Both 1440×900 and
   1280×800 Playwright initial-viewport assertions now PASS, with original
   keyboard focus, source content and final DRAFT identity intact.
2. **Confusing internal tools:** Remove the duplicate, research-oriented
   **Group similar text logs** (private Drain3) and **Find a similar known
   log shape** controls from the beginner Add Logs screen. They expose
   availability checks, manual source transfer and exploratory hints that
   do not independently produce a reviewed parser, duplicating the main
   Analyze Logs action. The runtime code path and raw-source request launchers
   were removed from this UI. A negative browser test verifies no private
   grouping HTTP request can be started by the retired controls. Retain
   contextual, automatic **local** repeated-unknown-shape grouping, including
   reversible Parser Set subgroups. Retain user-requested prefix/postfix
   marking, explicitly declared Syslog forwarders, existing-parser import,
   local versions and the opt-in offline Python test sender.
3. **Schema/header accounting:** An explicit note next to the beginner
   summary separates W3C/Zeek **two logical data events** from preserved
   two/seven source metadata lines. Explain that header lines are not events,
   and that original header-dependent stream-native DRAFT compatibility is
   still NOT VERIFIED. Both real Chromium flows remain review-only; original
   metadata is preserved, not removed or falsely promoted.

### Explicit non-defect

The initial quoted CSV source summary displayed 0/2 events before human column
review. A separate focused real public-browser sequence confirmed that after
the user approved column names it changed to 2/2 and enabled Review Fields.
That behavior is correct and was not patched.

## Local exact-source user action matrix

Real Playwright Chromium against the changed Vite UI and built, pinned
same-checkout offline authoring/Multi-Pass backend:

- **53/53** affected beginner/browser journeys PASS: multi-format AWS WAF,
  Suricata, CrowdStrike, Defender, PAN-OS, FortiGate, CEF/LEEF, Juniper,
  WatchGuard, Check Point, W3C/Zeek, quoted multiline CSV, unsupported XML;
  contextual field errors, AI repair, CSV approval, header accounting, user
  file upload, visible tools, original UTF-8 prefix marking, declared-source
  guidance, browser-local save/compare/restore and independent local history,
  imported Project/CONF/Ruby review, Python sender download and bounded
  loopback-only test sender.
- **22/22** further Auto/ChatGPT and compiler browser cases PASS; this run
  also discovered 24 integration tests marked SKIP because its runner lacked
  the explicit `PARSER_STUDIO_LIVE_BACKEND=1` flag. Do not count SKIP as PASS.
- A separate pinned `PARSER_STUDIO_LIVE_BACKEND=1` run executed those
  integration scenarios: **18/18 in-scope PASS**, including real generated
  DRAFT Ruby/CONF/ZIP, SHA checks, different/combined event-family and relay
  samples, listener ports 6801/6819, original-source ChatGPT recovery,
  namespace collision rejections and fail-closed tests. **Six** retired
  historical owner-scoped target session/Interflow cases were intentionally
  SKIP and remain excluded; they are not current product functionality.
- A new **one continuous complete-first-user test PASS 1/1** at 1280×800:
  directly enter sample + manufacturer/product/version/6819 port, save local
  version, analyze, inspect field and mapping, generate actual Ruby+CONF+ZIP,
  verify listener and final `invert true`, begin a new empty parser and
  restore the original browser-local version with identity. No page errors.

**Unique final local Chromium results: 94 PASS, six intentionally excluded
legacy SKIP, zero unexpected failures among qualified final runs.** A first
iteration of the new complete-user E2E failed due to selector strictness
(ambiguous `New Parser` help and repeated saved-version labels); it was
corrected in test selectors, without product code changes. Record historical
RED iterations separately from the final green result.

Full frontend Vitest: **146 files / 1,135 tests PASS**. TypeScript/typecheck,
production Vite Web build, offline backend build and `git diff --check` PASS.
No privileged external target activity or live customer packet transmissions
were performed.

## Adoption and deployment

The resulting functional changes are restricted to novice UI affordances,
English contextual explanations and associated browser/unit tests. The parser
engine, field extraction, authorized mappings and Stellar Cyber 7.0 dictionary
remain unchanged. The original development app and rollback receipts remain
available; merge/public development deployment is a separate accepted gate.

Do not regenerate the earlier MDL accuracy research or overwrite other
protected worktrees. Do not claim native target/DP/sensor certification based
on these browser-generated DRAFT files.
