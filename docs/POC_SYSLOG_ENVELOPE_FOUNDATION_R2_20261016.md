# Syslog Envelope Foundation PoC R2 — 2026-10-16

## Executive conclusion

The PoC validates a structural change to Parser Studio's parsing architecture.

The parser should not treat a complete security log line as one vendor-specific grammar.
It should first parse the reusable Syslog envelope, then parse the residual message body,
then apply vendor/log-family semantics, and only after that normalize fields.

Recommended pipeline:

```text
event framing
  -> syslog envelope
  -> body dialect extraction
  -> vendor/log-family semantic profile
  -> normalized field mapping
  -> validation/export
```

This direction materially improves extraction while retaining fail-closed behavior.

## Isolation and safety

The owner's active development worktree was not used as a write target.

Active development worktree observed at the start of the PoC:

- path: `/home/aella/parser-studio-beginner-parser-set-e2e-20261016`
- branch: `fix/beginner-parser-set-e2e-20261016`
- snapshot HEAD: `19ea6fba6bb5e81f6a2cba7e6cba8fcea2d63313`
- the worktree was already dirty before this PoC

Initial isolated PoC:

- path: `/home/aella/parser-studio-syslog-foundation-poc-20261016`
- branch: `poc/syslog-envelope-foundation-20261016`
- current-engine snapshot commit: `aa457e8`
- fixed corpus commit: `75f0820`
- first envelope candidate commit: `43c110e`

A second isolated clone was created because the first PoC directory was observed being
modified concurrently by another task. R2 is the stable qualification target:

- path: `/home/aella/parser-studio-syslog-foundation-poc-r2-20261016`
- branch: `poc/syslog-envelope-foundation-r2-20261016`
- base: `43c110e38d66c3da1cd60f5dc6ab456c13ee5f43`

No production target, credential, release state, or active development branch was modified.

## Root cause

The original PAN-OS failure exposed a general architectural problem rather than only a
Palo Alto CSV problem.

The engine already contained many useful bounded grammars, but several grammars parsed
the Syslog header and vendor payload as one inseparable full-line expression. That causes
combinatorial growth:

```text
vendor body A x RFC3164
vendor body A x RFC3164 + year
vendor body A x RFC3339 wrapper
vendor body A x ISO date/time/zone
vendor body B x the same wrappers
...
```

The correct invariant is:

```text
one validated envelope parser
  x
many independently reusable body parsers
```

## Research convergence

### Syslog standards

RFC 3164 defines a reusable outer header containing PRI, timestamp, and hostname before
the remaining message content.

RFC 5424 formalizes the message as:

```text
PRI VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
```

Therefore the envelope is a protocol-level structure, not vendor semantics.

References:

- RFC 3164: https://www.rfc-editor.org/rfc/rfc3164
- RFC 5424: https://www.rfc-editor.org/rfc/rfc5424

### Collectors and data pipelines

OpenTelemetry Collector has an explicit Syslog parser operator with RFC3164, RFC5424,
and a `none` protocol mode. The `none` mode preserves non-conforming message content
while still allowing Syslog transport/framing and PRI handling.

- https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/pkg/stanza/docs/operators/syslog_parser.md

rsyslog includes compatibility controls for real-world RFC3164 deviations such as a year
after the timestamp and headerless input.

- https://docs.rsyslog.com/doc/configuration/modules/pmrfc3164.html

Splunk Connect for Syslog treats PAN-OS Syslog transport separately from PAN log-family
routing and documents both legacy BSD and IETF-framed inputs.

- https://splunk.github.io/splunk-connect-for-syslog/develop/sources/vendor/PaloaltoNetworks/panos/

Elastic recommends delimiter-based Dissect for repeatable structure and Grok only where
regular-expression flexibility is actually required.

- https://www.elastic.co/docs/reference/query-languages/esql/esql-process-data-with-dissect-grok

### Security normalization products

Microsoft Sentinel ASIM uses source-specific parsers behind unifying normalized-schema
parsers. Its parser-development guidance explicitly separates filtering, parsing, field
preparation, mapping, and testing.

- https://learn.microsoft.com/en-us/azure/sentinel/normalization-about-parsers
- https://learn.microsoft.com/en-us/azure/sentinel/normalization-develop-parsers

Google Security Operations similarly recommends a phased parser:

1. identify the source format,
2. extract with the most appropriate JSON/KV/CSV/Grok/XML mechanism,
3. transform,
4. map to UDM,
5. validate the normalized record.

Google specifically recommends using the format-native extractor rather than applying
heavy Grok to everything.

- https://docs.cloud.google.com/chronicle/docs/event-processing/parsing-overview
- https://docs.cloud.google.com/chronicle/docs/reference/parser-syntax

### Open-source parser implementations and research

The Go Syslog implementations reviewed support RFC3164/RFC5424 parsing as independent
protocol grammars instead of embedding one vendor grammar into the wire header.

Examples:

- https://github.com/leodido/go-syslog
- https://github.com/influxdata/go-syslog

Drain3 states that template-mining accuracy improves when structured fields such as
timestamp, hostname, and severity are removed before mining the unstructured message.

- https://github.com/logpai/Drain3

This supports using template mining only after deterministic envelope/body extraction,
not as a replacement for known Syslog structure.

## PAN-OS finding

PAN-OS can emit BSD or IETF Syslog and also supports custom Syslog formats. The parser
therefore must not couple one timestamp wrapper to one PAN payload shape.

Palo Alto documentation also describes the default exported log payloads as ordered CSV
fields. Common leading concepts include:

- FUTURE_USE
- Receive Time
- Serial Number
- Type
- Subtype
- Generated Time

Traffic, Threat, System, Config, GlobalProtect, User-ID, and other families then diverge.

References:

- https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring/configure-syslog-monitoring-pan-os
- Palo Alto Syslog field documentation / administrator guides

Recommended handling:

1. parse the outer BSD/IETF Syslog independently;
2. fingerprint the residual positional CSV;
3. preserve every value as `column_N` before assigning semantics;
4. validate the PAN log type and expected anchors;
5. only then apply the appropriate PAN log-family field dictionary;
6. if the structure is recoverable but PAN semantics are not verified, retain it as
   generic positional CSV instead of falsely labeling it PAN;
7. treat configured PAN custom-log-format output as a separate profile.

## R2 implementation

### Stage 1 — Syslog envelope

`src/syslogEnvelope.ts` provides bounded parsing for:

- RFC5424
- RFC3164/BSD
- RFC3164 with year before time
- RFC3164 with year after time
- RFC3339-style wrappers
- ISO date + separated time + optional numeric timezone
- slash-date security-device wrappers
- colon-date device wrappers
- PRI-only partial envelopes

It preserves:

- raw PRI plus derived facility/severity
- protocol version
- timestamp/date/time/timezone components
- hostname
- app name
- process ID
- message ID
- RFC5424 structured data
- residual message

RFC3164 year/timezone absence is not silently converted into an exact UTC event time.

### Stage 2 — body dialect

After envelope extraction the residual message is passed to deterministic body parsers:

- CEF
- LEEF
- JSON object
- PAN-style positional CSV
- generic security positional CSV
- comma-delimited KV
- space-delimited KV
- existing bounded vendor body grammars

Unknown positional CSV values remain source-preserving `column_N` fields.

### Stage 3 — header-independent vendor bodies

The PoC demonstrates that existing vendor grammars can be decoupled from the outer
header.

The R2 body layer reuses or introduces bounded body-only parsing for:

- Cisco ASA/FTD
- Juniper RT_FLOW
- Check Point bracket/colon KV
- Cisco ISE comma KV
- WatchGuard
- Sophos KV

This removes the need to duplicate the same vendor body grammar for every timestamp
wrapper.

## Fixed-corpus benchmark

A detached baseline at `aa457e8` was executed against the same 49-positive-event corpus.

| Metric | Baseline | Candidate | Improvement |
| --- | ---: | ---: | ---: |
| Positive events | 49 | 49 | same |
| Full Generic Structural parse | 15/49 (30.6%) | 43/49 (87.8%) | +28 events / +57.2 pp |
| Structured body extraction | 13/49 (26.5%) | 43/49 (87.8%) | +30 events / +61.3 pp |
| Dedicated Syslog envelope recognition | 14/49 in old engine | 49/49 (100%) | +35 events / +71.4 pp |
| Malformed fixed-corpus inputs accepted | 0/12 | 0/12 | no regression |
| Original Generic Structural tests | 29/29 | 29/29 | no regression |

The six events intentionally not promoted to a structured Generic Structural success are
five Snort-style free-text variants and one ordinary RFC5424 text event. Their Syslog
envelopes are recognized, but the residual bodies do not have a deterministic structured
grammar in this PoC.

## Cross-product generalization test

A deterministic matrix crossed:

- five PRI values,
- six security body families,
- seven Syslog timestamp/header wrappers.

Result:

```text
210 / 210 envelope recognized
210 / 210 structured body parsed
16 / 16 invalid header boundary cases rejected
```

This test is important because it prevents success on one PAN sample from being mistaken
for a general Syslog improvement.

## Vendor-wrapper decoupling result

Before body decoupling, all 30 test lines had a recognized envelope but only 16/30 reached
structured vendor/body extraction.

| Body family | Before | R2 |
| --- | ---: | ---: |
| Cisco ASA/FTD | 3/5 | 5/5 |
| Juniper RT_FLOW | 1/5 | 5/5 |
| Check Point bracket KV | 0/5 | 5/5 |
| Cisco ISE comma KV | 5/5 | 5/5 |
| WatchGuard | 2/5 | 5/5 |
| Sophos KV | 5/5 | 5/5 |
| **Total** | **16/30** | **30/30** |

Nine deliberately malformed vendor-body cases were also tested and none were accepted as
the corresponding verified vendor structure.

## Failure semantics

One Boolean `parsed=true/false` is not sufficient.

The product should represent independent stage results:

- `envelope_matched`
- `body_structured`
- `vendor_profile_matched`
- `semantic_mapping_complete`
- `normalized`
- `target_runtime_verified`

A useful downgrade is not the same thing as a false success.

Examples validated in R2:

- PAN-shaped CSV with an invalid PAN receive date or unknown PAN type can be retained as
  generic positional CSV, but must not be labeled as verified PAN semantics.
- Unsupported Juniper `RT_FLOW_SESSION_*` variants can preserve the tagged message
  without emitting verified `juniper` semantic fields.
- Incomplete WatchGuard traffic can preserve the message without claiming verified
  WatchGuard traffic fields.
- Unclosed quotes, unsafe keys, impossible ports, malformed RFC5424 headers, embedded
  NUL/newline, and similar syntax/safety violations remain hard failures.

## Safety properties

The PoC retains bounded behavior:

- 8 KiB record bound for the envelope path
- NUL/newline rejection
- PRI 0..191 validation
- calendar/clock/timezone validation
- bounded RFC5424 structured-data scanning
- bounded JSON nesting/node count
- prototype-key rejection
- bounded CSV/KV token counts
- no semantic naming of unknown positional values
- malformed structured input cannot be silently treated as a verified vendor profile

## Full R2 repository verification

Stable R2 verification completed successfully:

```text
Test Files: 94 passed / 94
Tests:      771 passed / 771
TypeScript: tsc --noEmit PASS
Build:      tsc -b && vite build PASS
```

Vite emitted only the existing chunk-size warning; the production build completed
successfully.

## Product integration recommendation

Adopt the architecture, but integrate it into the active product as small reviewable
changes rather than replacing the development worktree with this PoC.

Recommended order:

1. Add `syslog_envelope` as a first-class parser stage in the portable IR.
2. Keep TCP/RFC6587 framing in the event-framing layer, separate from envelope parsing.
3. Run body-format detection on the residual `message`, not the entire wire line.
4. Convert existing full-line vendor grammars into reusable body parsers where possible.
5. Preserve source values before semantic naming.
6. Add explicit stage-level status/evidence to the UI and test report.
7. Add PAN default-format family dictionaries only after structural extraction, with
   separate handling for custom PAN Syslog formats.
8. Use Drain/template mining only for residual free text after deterministic parsing.
9. Re-run the existing broad Full User E2E corpus on the integrated product candidate.

## Rejected directions

Do not:

- create one larger universal full-line regex;
- duplicate every vendor parser for every timestamp variant;
- treat envelope recognition as proof that the body was parsed;
- treat a vendor-like fingerprint as proof of vendor semantics;
- invent field names for unknown positional CSV;
- run template mining before deterministic header/delimiter extraction;
- infer an exact UTC timestamp from RFC3164 when year/timezone evidence is absent.

## Decision

The PoC hypothesis is validated.

The primary improvement is not another Palo Alto-specific regex. It is a reusable
Syslog envelope boundary plus reusable body parsing and an explicit semantic-validation
stage.

That architecture gives Parser Studio materially better coverage while preserving source
data and avoiding unsupported semantic claims.
