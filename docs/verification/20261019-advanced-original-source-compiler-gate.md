# Advanced mode source-stream compiler-readiness bypass

Date: 2026-10-19. Candidate based on Draft PR #105 exact committed
c22b5a32bb70d8b4023b6be8a4ca3c74eb8caae9.

## Failure and trusted source boundary

In the main two-path Auto Parser, the ordinary beginner workflow correctly
distinguished useful source parsing from executable parser-file support.
Opening Advanced Tools bypassed the beginner readiness prerequisite. In a
real localhost Playwright Chromium session, the original Docker JSON-file
stream returned two PARTIAL source records, each carrying
FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER, but the Advanced Review
action incorrectly navigated to Review Fields. This was a genuine
source-compiler readiness bypass (RED), not a missing manufacturer regex.

## Generic fail-closed correction

- A bounded, **negative-only** original source-container gate checks for
  exact same-source Multi-Pass FRAMING/SCHEMA issue evidence, or strong,
  finite transport-container signatures at the original source boundary.
  It never promotes unsupported sources to a qualified DRAFT.
- Recognized original-only transport families include Docker JSON-file,
  Kubernetes CRI, Linux audit, header-dependent W3C/Zeek, RFC6587 octet
  frames with Syslog/JSON payload, RFC7464 JSON text sequences, NUL-delimited
  GELF or Syslog sources, and systemd journal exported entries.
- The same gate blocks both the review transition and file generation in
  beginner and Advanced Tools modes; Review attempted on unsupported
  original source now shows a concrete explanation and actionable ChatGPT
  Assisted recovery, preserving all original event bytes.
- Ordinary JSON/CEF/LEEF/KV/Syslog sources are not presumed unsupported.
  Regular JSON still reaches Review Fields and Map Fields in Advanced mode.
  Absence of a marker is not native compatibility proof, and original
  transport DRAFT/compiler support remains NOT VERIFIED.
- This changes neither backend compiler schema nor native Stellar/DP
  acceptability; no vendor-specific regex, sensor send, credential change,
  main merge, or public app deployment.

## Evidence and exact-head CI

- Real Chromium RED: Docker two PARTIAL events incorrectly reached Review
  Fields when Advanced Tools was selected.
- Real Chromium GREEN: same source is blocked, and direct Advanced Review
  without running Analyze Logs cannot bypass the gate.
- All **10/10** real isolated Chromium regression scenarios pass:
  Docker with and without Analyze, ordinary JSON non-regression, and seven
  protocol/container families all blocked for original unsupported DRAFT.
- Deterministic negative source marker unit checks cover strong signatures,
  mismatched stale preview identity and otherwise eligible ordinary formats.
- Exact-HEAD quality workflow now includes this ten-case suite alongside
  the existing fifteen previously qualified named-type/conditional-routing
  and physical boundary scenarios; it requires **25 executed / 0 skipped**.

No source reaches a real sensor or DP under this PoC and no confidential
customer/device logs were used. Tests use authored synthetic strings; native
target field correctness requires separately authorized evidence.
