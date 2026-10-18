# P0-AP1 — Bounded local logical event boundary review

## Implemented

The optional **Review multiline log boundaries (browser only)** disclosure appears within the beginner **Add Logs** step. It is purely local and user-triggered: no browser upload, backend mutation, raw-sample persistence, generated parser, network request or third-party AI call is performed.

The analyzer inspects at most 64 KiB of source and 2,000 physical lines, with a maximum of 500 groups and 8 KiB per reviewed candidate. It detects two deterministic review candidates:

- **Pretty-printed JSON objects:** brace/string/escape-aware logical grouping with bounded nesting. A completed group must parse as a safe, bounded JSON object; incomplete, trailing or malformed JSON is **AMBIGUOUS**, never a parsing success.
- **Java stack traces:** a dated ERROR/WARN/FATAL/SEVERE header or qualified Exception/Error header followed by a bounded sequence of Java frames, causes, suppressed exceptions and elided-frame markers. Unmatched frame continuations or unrelated text are **UNRECOGNIZED**, not silently folded into a convenient log event.

It displays only the candidate kind, source start/end line numbers, counts, and fixed status codes. Every nonempty physical input line is accounted for, including unknown/orphan lines. Up to 12 group summaries are shown; the report counts all groups and preserves their original source line positions. Raw stack frames, JSON properties, IP addresses, usernames and observed customer log values are never placed into the report.

## Native and backend boundary

This does not convert the user's original sample, rewrite accepted parsing rules, install a Fluentd multiline aggregator, configure a TCP framing delimiter, generate a Ruby parser, or claim native/target compatibility. Only browser-boundary hypotheses are reviewed. User-defined multiline framing and real receiver semantics must first be designed and qualified independently with a precise source transport contract and pinned native Fluentd fixtures.

For ambiguous JSON or stack traces, the display recommends Edit Details and labels native/DP verification as NOT VERIFIED. Existing single-line JSON/KV/CEF/LEEF and strict RFC3164/RFC5424 parsers remain unchanged. Mixed-family compilation is limited to explicitly allowlisted single-line JSON/KV/CEF/LEEF, not multiline or arbitrary Syslog.

## Tests

- src/guided/logicalBoundaryReview.test.ts: two consecutive multiline JSON objects with nested braces in string values, bounded Java stack traces, malformed/truncated JSON, orphan frame/unrecognized data, regular JSON Lines, empty input, oversized datasets, excess events and excessive nesting. It requires full physical-line accounting and no raw event values in report JSON.
- The UI binds this explicit review to current source/draft identity so changes invalidate previous reports.
- This is browser-only evidence. No full user E2E, proprietary Stellar import, actual sensor or DP tests are claimed.

## Relationship to later explicitly framed TCP JSON

The optional browser review in this document remains non-mutating and unverified. Separately, the Edit Details path can now author an explicit TCP-only JSON blank-line framing contract when a real log sender is known to delimit whole JSON objects with LF LF. This is not a result of the browser guessing multiline boundaries. The Native Parser Plugin and CONF AST synthetic evidence and limits are described in docs/19_EXPLICIT_TCP_JSON_FRAMING.md.
