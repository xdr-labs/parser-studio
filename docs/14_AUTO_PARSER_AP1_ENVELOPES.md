# P0-AP1 — Local Envelope/Body Candidate Ledger

**Current deliverable:** browser-only, explicit user-triggered envelope/body recognition
and an authenticated same-origin backend compiler-capability check. It is not
a new native parser engine, real Stellar import or an automatic DP deployment.

## Reviewed synthetic detection matrix

| Source input | Envelope | Body | Current backend v0.1 compilation | Timestamp policy |
| --- | --- | --- | --- | --- |
| Valid single-line JSON object | Standalone | JSON | DRAFT candidate | No header |
| Strict key/value record | Standalone | KV | DRAFT candidate | No header |
| Valid CEF 0 | Standalone | CEF | DRAFT candidate | No header |
| Valid LEEF 1.0/2.0 | Standalone | LEEF | DRAFT candidate | No header |
| Valid CSV row | Standalone | CSV | Explicit columns required | No header |
| Bounded RFC5424 v1 header + JSON | RFC5424 | JSON | DRAFT when advertised | Explicit timestamp or NILVALUE |
| Bounded RFC5424 v1 header + KV | RFC5424 | KV | DRAFT when advertised | Explicit timestamp or NILVALUE |
| Bounded RFC5424 v1 header + CEF/LEEF | RFC5424 | CEF/LEEF | DRAFT only with matching capability | Explicit timestamp or NILVALUE |
| RFC3164 timestamp + quoted KV | RFC3164 | KV | **UNSUPPORTED** by v0.1 backend | **Year and timezone unknown** |
| Mixed, malformed, unrecognized | As classified | As classified | **No universal single parser** | Unverified |
| Multiline group / stack trace | Ambiguous | Candidate only | **No native multiline compiler** | Unverified |

The browser receives only session-private pasted sample bytes. Clicking
**Analyze Logs** runs a bounded synchronous *local* classifier and then
makes one explicit, same-origin **GET capabilities** request. The request
contains no source data, field values or credentials. Results retain:
original physical line number, bounded logical event count, enveloped
family, body kind, fixed status and ambiguity codes. Output and reports
contain no raw or normalized event values.

All nonempty bounded logical events are accounted for, including unsupported
and unknown records. Over 64 KiB, over 500 events or individual records over
4096 characters are never treated as ready. Blank-line grouped multiline
samples are explicitly **BOUNDARY_REVIEW**, not native Fluentd validated.
No parser/port/output config changes unless the user explicitly accepts a
single-family **DRAFT** candidate; this updates only the reviewed extraction
and RFC5424 body mode, retaining the complete source, existing mappings and
the original six-step editor.

## Evidence and remaining P0-AP1 work

- Deterministic value-free scenario tests:
  `src/guided/autoParserEnvelope.test.ts`.
- Real user interaction, consent, default-deny, sample privacy and
  mixed-family Chromium tests:
  `tests/auto-parser-envelope.spec.ts`.
- Existing UI/backend integrated synthetic pair proof and native pinned
  baseline remain separately verified at
  `docs/13_UI_BACKEND_LOOPBACK_INTEGRATION.md`.
- The current backend **does not implement RFC3164+KV Ruby/CONF compilation**,
  universal mixed-family routing or native multiline; this UI cannot mark
  them supported. Backend PR #4 must independently add reviewed typed codec
  contracts and native golden fixtures before those combinations become
  compiler-supported. In the meantime users may inspect them without
  losing source data.
- Browser structural recognition is only a *candidate*. Current backend
  capability metadata does not mean a user parser's Ruby was executed
  or that any customer Stellar loader accepted it. Actual target/DP,
  sensor port and Interflow E2E remain independently gated.
