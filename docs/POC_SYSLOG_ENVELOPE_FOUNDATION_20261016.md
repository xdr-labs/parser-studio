# Syslog Envelope Foundation PoC — 2026-10-16

## Purpose

This PoC tests whether Parser Studio should stop treating common Syslog wrappers as vendor-specific full-line grammars and instead introduce a reusable Syslog envelope stage before body parsing.

The owner-requested constraints are preserved:

- The active development worktree is read-only for this PoC.
- The PoC runs from an independent clone and branch.
- Existing successful Generic Structural behavior must not regress.
- Malformed or unsafe inputs must remain fail-closed.
- Source values are preserved before semantic naming is attempted.
- The goal is extraction correctness, not parsing speed.

## Isolation evidence

Active development source:

- path: `/home/aella/parser-studio-beginner-parser-set-e2e-20261016`
- source HEAD at snapshot: `19ea6fba6bb5e81f6a2cba7e6cba8fcea2d63313`
- the source worktree was already dirty and was not modified by this PoC

Independent PoC:

- path: `/home/aella/parser-studio-syslog-foundation-poc-20261016`
- branch: `poc/syslog-envelope-foundation-20261016`
- baseline snapshot commit: `aa457e8`
- fixed corpus commit: `75f0820`
- source and PoC `src/genericStructural.ts` SHA-256 matched at the snapshot boundary:
  `b42a4212f3b120f277c06322c952ddce9e4c61ab4e4e778af1d2570385384c26`

## Initial problem found

The active engine had already gained a narrow recovery rule for a common PAN-OS Traffic log:

`RFC3164 header -> PAN-like positional CSV`

That hotfix is useful, but it demonstrates the architectural problem. A different timestamp wrapper, a different RFC variant, or another security product body requires another full-line grammar even though the outer Syslog fields are conceptually the same.

The engine therefore mixes two separate questions:

1. Can the Syslog transport/envelope be recognized?
2. Can the remaining vendor message body be structurally extracted?

The PoC separates those questions.

## Research convergence

The reviewed standards, open-source implementations, competitors, data-pipeline products, and log-parsing research converge on the same design.

### Standards

RFC 3164 defines an outer header containing priority, timestamp, and hostname before free-form content.

RFC 5424 formalizes the outer message as:

`PRI VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`

The outer envelope is therefore a reusable grammar and should not be rediscovered independently inside every firewall, EDR, NDR, WAF, or proxy parser.

### Collector and data-pipeline implementations

- `syslog_loose` attempts RFC 5424 first and then falls back to looser RFC 3164 parsing.
- rsyslog exposes compatibility controls for real-world deviations such as a year after the RFC 3164 timestamp and headerless input.
- Vector describes Syslog handling as best-effort parsing of RFC 6587, RFC 5424, RFC 3164, and common deviations.
- OpenTelemetry Collector has a dedicated Syslog parser stage and explicitly supports a mode where framing is accepted while the body remains unparsed.
- Cribl separates RFC-compliant Syslog fields from the remaining message and retains raw data when a message cannot be structurally decoded.
- Wazuh pre-decodes the Syslog-like header before decoder `prematch` and child extraction.
- Elastic recommends delimiter-based Dissect for consistently structured bodies rather than forcing every format through regex.
- Splunk Connect for Syslog routes PAN-OS into product/log-family parsers after Syslog ingestion instead of treating every complete wire line as one universal grammar.

### Security-vendor evidence

PAN-OS documentation shows the message payload itself is ordered positional CSV. Traffic, System, Config, GlobalProtect, User-ID, Authentication, GTP, IP-Tag, SCTP, and other families share the leading body concept of receive time, serial, and a log type, while their later fields differ by family.

This supports two independent layers:

- Syslog envelope extraction.
- PAN-OS body-family extraction and later semantic mapping.

### Research

Drain and Drain3 reinforce the same boundary from the unstructured-log side: template mining is more accurate when timestamp, hostname, severity, and other structured header fields are removed first.

Template mining is therefore a potential later fallback for residual free text, not a replacement for deterministic Syslog parsing.

## PoC architecture

The recommended parser path is:

`event framing -> Syslog envelope -> body dialect -> vendor/log-family -> semantic mapping -> normalization`

The PoC implements the first two extraction boundaries without changing target-specific export behavior.

### Stage 1 — Syslog envelope

`src/syslogEnvelope.ts` recognizes and validates bounded forms for:

- RFC 5424
- RFC 3164/BSD
- RFC 3164 with year before the time
- RFC 3164 with year after the time
- RFC3339-style loose timestamp wrappers
- ISO date + separated time + optional numeric timezone
- slash-date security-device wrappers
- colon-date device wrappers
- PRI-only structured-body candidates

It preserves:

- PRI
- derived facility and severity
- protocol version
- timestamp/date/time/timezone
- hostname
- app name
- process ID
- message ID
- RFC 5424 structured data
- residual message

### Stage 2 — body dialect

The candidate Generic Structural integration attempts structured body parsing only after a validated envelope:

1. CEF
2. LEEF
3. JSON object
4. PAN-OS positional CSV signature
5. source-preserving security positional CSV
6. comma-delimited KV
7. space-delimited KV

The candidate deliberately does not invent semantic names for an unknown positional CSV. Values are retained as `column_N`.

Free-form bodies remain residual message data rather than being falsely declared structured.

## Corpus

The fixed evaluation corpus contains 49 positive events and 12 malformed negative events.

Security families include:

- PAN-OS firewall Traffic
- Fortinet
- SonicWall
- Suricata JSON
- CEF-style endpoint telemetry
- LEEF-style proxy/NDR telemetry
- Snort-style IDS messages
- pfSense/filterlog
- RFC 5424 AWS-WAF-like JSON
- generic RFC 5424 text
- Sophos-style KV

The same security bodies are wrapped in multiple timestamp/envelope families to prevent a vendor-specific success from being mistaken for a Syslog improvement.

Negative cases cover:

- invalid PRI
- invalid calendar values
- invalid clock values
- invalid timezone
- invalid RFC 5424 version/timestamp shapes
- malformed PRI token
- arbitrary prose

## Fair before/after benchmark

The baseline was re-run from detached commit `75f0820` using the exact current corpus and metric definitions.

| Metric | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| Positive events | 49 | 49 | same |
| Generic Structural parsed | 15 / 49 (30.6%) | 43 / 49 (87.8%) | +28 events / +57.2 pp |
| Structured body extracted | 13 / 49 (26.5%) | 43 / 49 (87.8%) | +30 events / +61.3 pp |
| Syslog envelope recognized by the dedicated stage | 14 / 49 in the old engine | 49 / 49 (100%) | +35 events / +71.4 pp |
| Malformed negatives accepted | 0 / 12 | 0 / 12 | no regression |
| Existing Generic Structural regression tests | 29 / 29 | 29 / 29 | no regression |

The six events not promoted to structured Generic Structural output are five Snort free-form variants and one ordinary RFC 5424 text message.

This is intentional. Their Syslog envelopes are successfully extracted by Stage 1, but the residual text does not have a deterministic structured body grammar in this PoC.

## Important failed experiment

An early integration allowed any valid outer Syslog envelope to become a Generic Structural success.

That raised positive coverage to 48/49 immediately, but nine existing fail-closed regression tests failed because malformed known vendor records could fall through and be accepted as generic Syslog.

That design was rejected.

The corrected integration only promotes a fallback into Generic Structural when the residual body is deterministically structured. General envelope recognition remains a separate parser stage.

This distinction is essential to avoid trading recall for false positives.

## PAN-OS conclusion

The original PAN-OS failure is not fundamentally a PAN-OS CSV problem.

The body is already highly structured and the official field order is stable enough to recognize a source-preserving positional layout. The larger failure was that the parser expected too much of one complete-line grammar.

With the new boundary:

1. `<PRI>` is parsed independently.
2. the outer timestamp and hostname are parsed independently across common timestamp variants;
3. the residual PAN-OS CSV is recognized from receive-time + serial + log-type anchors;
4. every column is preserved before semantic mapping;
5. a later PAN-OS family mapper can assign official field names by log type.

This prevents each timestamp variation from requiring another PAN-specific parser.

## Safety properties retained

The PoC keeps bounded parsing:

- 8 KiB single-record envelope limit
- NUL/newline rejection at the envelope boundary
- PRI range validation
- calendar/clock/timezone validation
- bounded JSON nesting and node counts
- prototype-bearing source-key rejection
- bounded CSV/KV token counts
- no semantic field invention for unknown CSV
- malformed known structures do not silently downgrade into success

## Recommended product direction

Adopt the Syslog envelope layer, but do not merge the PoC as one monolithic patch.

Recommended integration order:

1. Add a first-class `syslog_envelope` stage to the parser IR/pipeline.
2. Make format detection operate on the residual `message`, not the complete wire line.
3. Route the residual message through JSON, CEF, LEEF, KV, CSV, and existing bounded vendor grammars.
4. Represent outcomes separately:
   - envelope matched
   - body structured
   - semantic mapping complete
   - normalization complete
5. Treat free-form residual text as a valid partial extraction, not as a total parser failure.
6. Apply PAN-OS official field dictionaries only after structural CSV extraction and select the dictionary by PAN log type.
7. Consider Drain-style template mining only for residual free text after deterministic structure is removed.
8. Add RFC 6587 framing/event-breaking as a separate transport concern rather than embedding it in the envelope regexes.

## Rejected directions

Do not:

- build a larger universal full-line regex;
- add a complete vendor parser for every timestamp variation;
- let a valid header mask a malformed known body;
- infer semantic field names from positional values before the log family is known;
- use template mining before deterministic headers and delimiters have been removed;
- treat an unstructured residual message as equivalent to a failed Syslog envelope.

## PoC acceptance recommendation

The hypothesis is validated.

The measured gain is large enough to justify product integration, and the successful design preserves the existing fail-closed regression behavior.

The next product task should be a small, reviewable integration of the envelope stage into the existing multi-pass Funnel pipeline, followed by the existing broad Full User E2E corpus. The active development worktree should not be replaced by this PoC branch.
