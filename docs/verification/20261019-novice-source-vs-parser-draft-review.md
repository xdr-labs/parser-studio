# 2026-10-19 — Beginner Auto Parser: source extraction vs. parser-file readiness

## Baseline and objective

The previously verified 781e36feef357588b5a2f8da62a4298fcdb33ee6
Draft PR #108 completed exact-HEAD CI #39262152890 successfully.
The public development beta still runs the independently verified
b777d743be66ebcc98c967529366742f01b687b3 candidate. Its
134/134 real public Chromium acceptance has not been rerun or changed.

The existing synthetic security-log review inventory found cases where the
Python source decoder returned SOURCE_PARSED, including a standard
RFC 5424 free-form MSG and an ordinary LEEF event, but no downloadable
parser rule had been independently validated. The beginner screen
incorrectly instructed users to create a rule for "remaining message
text" even though the original source text and field bytes were complete.

## Root cause and behavior change

BeginnerAnalysisPanel already distinguishes parserRuleReviewRequired from
a partially decoded event. Its generic recommendation function did not
account for that distinction. When the preview syntax contained SYSLOG,
the fallback incorrectly treated complete source fields as residual data.

Now a **source-complete, compiler-unverified** event explicitly says:
- "Fields extracted — parser rule needs review".
- Original values were kept; no missing source text is implied.
- "Review parser-file support for these fields" tells the user to test
  a supported rule against more events before creating parser files.
- Native Fluentd or proprietary Stellar compatibility is **not verified**.
- ChatGPT Assisted remains a manual, redact-before-copy process; no
  automatic external customer-data transfer was added.

New advice applies only when a review is required, the source status is
SOURCE_PARSED, and there are no residual byte regions. Existing
format-specific guidance for RAW_ONLY, PARTIAL, invalid CSV/CEF/LEEF,
Windows XML, and W3C/Zeek sources remains intact. No third authoring
method, native compiler fallback, or vendor-specific regex was added.

## RED to GREEN and actual user actions

1. Two independently authored component scenarios—RFC 5424 UTF-8
   MSG and a fully extracted LEEF—failed against the prior user guidance.
2. The two new checks and three existing novice-recovery cases passed
   (BeginnerAnalysisPanel.recovery20261019.test.tsx: 5/5).
3. Preview client regressions passed (6/6), targeted total **11/11**.
4. Real Playwright CLI Chromium on isolated 127.0.0.1 Vite, exact
   candidate Python Multi-Pass and offline authoring backend passed
   **3/3**, with no HTTP mocks. The two source-complete cases displayed
   revised guidance; malformed quoted KV remained non-PARSED.
5. TypeScript/Vite and private authoring backend builds passed.
6. Updated tests are picked up by the existing same-HEAD GitHub
   quality workflow; final exact-HEAD CI remains a separate gate.

These are authored synthetic fixtures, NOT firmware, manufacturer field
semantic F1, native Stellar parser import, or sensor/DP validation.
The isolated local test services were stopped after verification.
Public development deployment, Exporter, rollbacks, intentionally dirty
worktrees and previous Draft PRs were untouched.

## Remaining

- Keep unverified security text and field meanings reviewable until an
  independent oracle or common standards grammar warrants more.
- Native compiler and proprietary target qualification remain separate
  from source extraction. Unsupported transports and malformed inputs
  cannot be promoted merely to improve a structural success rate.
- Any merge, public re-deployment, production release, or DP/sensor
  operation requires its separately authorized owner gate.
