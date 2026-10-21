# Parser Studio — strict Syslog JSON source / logical-boundary parity

2026-10-21 fixed public Stellar Cyber **7.0** Dictionary authoring scope.
This is a distinct, isolated, manufacturer-neutral parser/UX accuracy repair
stacked on Draft PR #127
(https://github.com/xdr-labs/parser-studio/pull/127)
HEAD 89c429559c9a3c46c5c3e5f15ce018397050725c.

## Root cause and bounded source evidence

- The reviewed RFC5424/RFC3164 explicit JSON body adapter previously used
  permissive JSON.parse; it retained the last of repeated decoded object
  members, silently discarding earlier values in the local browser.
  The pinned Ruby native DRAFT counterpart already rejects such duplicates.
- The browser's separate multiline logical boundary adapter could certify
  a JSON event as REVIEWABLE_MULTILINE when the JSON.parse path dropped an
  earlier same-key value. Boundary review is not native parsing proof.
- Authored independent negative examples include top-level, nested,
  Unicode-escaped equivalent and array child member-name collisions. Valid
  JSON with identically named fields in different objects remains valid.
- RED: **11 negative tests** failed on the original source, with two
  positive distinct-object controls PASS.
- No manufacturer/firmware originals or arbitrary Regex recovery evidence
  was invented.

## Change scope

- Reuse the fixed generic decoded-key source scanner only after the
  JSON grammar parser accepts syntax. One-line RFC5424 and bounded
  tagged RFC3164 source paths now return no extracted fields and an
  explicit duplicate-key review message.
- Multiline logical boundary candidates with repeated decoded keys are
  marked REVIEW_REQUIRED / AMBIGUOUS while preserving physical line
  accounting. No source text or customer field values enter this report.
- Do not change compiled Ruby/CONF templates, target syntax or source
  transport. This closes a browser-vs-qualified-native mismatch.
- Preserve valid JSON in separate objects and multilingual nested fields.
  No version selection or 6.5/6.6 schema compatibility.

## Exact qualification

- Focused Vitest: 30/30 PASS across original RFC3164/RFC5424 and logical
  boundary tests, including 13 newly authored positive/negative cases.
- Real isolated Playwright CLI desktop Chromium: two user-facing and direct
  browser-source scenarios 2/2 PASS using localhost Vite, Python Multi-Pass
  and built offline authoring Backend. No HTTP mocks or target connection.
- Full frontend regression, Web build and exact-head GitHub CI must be
  recorded from actual execution before claiming complete acceptance.
- Generated files remain DRAFT; engineVerified and targetImportVerified
  remain false. Public development SHA and previous PRs stay unchanged.

## Deferred evidence

Original multi-line transport compiler contracts for Linux Audit grouping,
CRI partial/final and Docker JSON-file remain unsupported by native DRAFT
without separate independent source goldens. No mobile, DP, sensors,
external AI, production or proprietary target parser import.
