# RFC 3164/BSD source CONTENT — standalone, no-loss qualification (2026-10-20)

## Target and provenance

This change continues the prior Draft PR #109 exact
00d2c0977886e3e738a214020050baac3323e477, CI #39268282984
COMPLETED SUCCESS. Public development remains the previously approved
b777d743 beta; this candidate does not alter or redeploy the public site.

The relevant standard is RFC 3164 section 4.1.3. After a recognizable
BSD Syslog header and TAG, CONTENT may be free-form text. An arbitrary
source-body sentence is not a regular-expression semantic grammar.
RFC 5424 section 6.4 already received a similarly bounded fix in #108.

- RFC 3164: https://datatracker.ietf.org/doc/html/rfc3164#section-4.1.3
- RFC 5424: https://datatracker.ietf.org/doc/html/rfc5424#section-6.4

## Source-to-user problem

The supported bounded PRI + BSD timestamp + HOST + TAG header grammar
and unprefixed BSD header grammar identified fields correctly.
An ordinary subsequent free-form CONTENT without KV/JSON/CEF/LEEF
structure was then reported as NO_SUPPORTED_GRAMMAR and left residual,
although its exact body source is a valid text field.

The change represents the independently observed original CONTENT as
body.message with an exact, original UTF-8 byte span, using
SYSLOG_RFC3164+RFC3164_CONTENT and BSD_SYSLOG+BSD_CONTENT.

No source/destination/action semantics are inferred from prose. No year
or timezone is filled in for RFC 3164. Nonprinting controls, invalid
calendar/PRI, malformed quoted KV, malformed JSON candidates, and
physical multiline content remain reviewable rather than falsely
certified.

### A critical regression caught by the frozen replay

An initial naive free-form capture made two existing Juniper examples
appear SOURCE_PARSED, but dropped their independently identified
generic_atoms.network IP and port spans. This was REJECTED.
Merely capturing an entire body in one catch-all field is not an
improvement when finer-grained validated values disappear.

The integrated product now checks its existing generic, qualified
candidate-only atom and label detectors before granting a complete
free-form-content result. If the text includes independently recoverable
IP/MAC/URL/UUID/hash or source-labeled value spans, it stays on the
normal PARTIAL review path, retaining those original fields. No vendor
regex or new runtime/network/parser-code execution was added.

## RED to GREEN and controlled scope

The first independent 16-case Python qualification was RED on 6 positive
new standards cases. After the first implementation, two new no-loss
regressions for previously recoverable network and label spans failed
(RED), and the source-completeness shortcut was hardened.

Final isolated result:

- 18/18 new focused Python tests PASS: PRI/no-PRI, free-form,
  Unicode/emoji UTF-8 source byte offsets, bracketed non-JSON text,
  pre-existing label and IP span retention, KV/CEF precedence,
  malformed KV/JSON, invalid PRI/calendar, multiline, non-printing
  controls and two-event exact accounting.
- 47/47 affected Python tests PASS, comprising 18 new, 10
  RFC 5424, 7 transport framing, 6 declared schema, and 8 Linux
  Audit/CRI/Docker original-container tests.
- 6/6 real Playwright CLI Chromium on actual isolated
  127.0.0.1 Vite + Python Multi-Pass + offline authoring endpoints,
  no API mocks: the three new RFC 3164/source no-loss scenarios plus
  the three already qualified RFC 5424/native-readiness scenarios.
- TypeScript/Vite frontend and offline authoring backend builds PASS.
- UI source preview is never allowed to certify native Fluentd,
  proprietary Stellar target import, physical sensor or DP operation.

## Frozen original 100-case outcome — do not re-label a corpus

| Authored synthetic replay | Prior #109 | Candidate |
| --- | ---: | ---: |
| Same SHA-256 synthetic inputs | 100 | 100 |
| Original framed events | 114 | 114 |
| All events SOURCE_PARSED per input | 71 | 71 |
| REVIEW/partial/unsupported per input | 29 | 29 |
| Changes to source classification | — | 0 |
| Lost or changed original accepted fields | — | 0 |
| Lost/changed accepted source byte spans | — | 0 |
| Manufacturer-semantic independent F1 | Not measured | Not measured |
| Native Fluentd/Stellar target verification | Not claimed | Not claimed |

This is the same developer-authored fixture set; no claim of unseen
manufacturer performance or improved existing-corpus success count is
made. The targeted new RFC 3164/BSD cases support the standards
capability without weakening the 100-case no-loss baseline. The public
b777 browser 69/31 result is older and includes downstream parser-file
readiness, so it must not be confused with the offline 71/29 figure.

## Operational guardrails

- Scope is only draft code and immutable synthetic test evidence.
- Main/older stacked Draft PRs, public b777 beta, Exporter, rollback and
  deliberately dirty worktrees remain untouched.
- Source completeness is separate from downloadable native/parser-file
  readiness, which still needs reviewed compiler evidence.
- No automatic AI upload, external event forwarding, Nginx/auth/TLS,
  production, DP or sensor change is permitted.
- Final exact-head CI, PR/head identity and owner-controlled future
  deployment/release gates must be checked independently.
