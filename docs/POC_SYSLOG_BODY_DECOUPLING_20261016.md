# Syslog Envelope + Vendor Body Decoupling PoC — 2026-10-16

## Executive conclusion

The parser-engine problem is architectural, not a Palo Alto Networks special case.

The original engine frequently bound all of these concerns into one full-line grammar:

1. Syslog transport/header recognition.
2. Timestamp variant recognition.
3. Host/application metadata extraction.
4. Body-dialect recognition.
5. Vendor/log-family parsing.
6. Semantic field naming.

That design makes a valid vendor payload fail whenever the outer timestamp or Syslog wrapper changes.

This PoC validates a layered design:

```text
transport/framing
  -> syslog envelope
  -> body dialect
  -> vendor/log family
  -> semantic field mapping
  -> normalization
```

The result is materially better on the fixed security-log corpus while preserving fail-closed behavior.

## Isolation and provenance

The active development worktree was not used as the implementation target for this PoC.

Phase 1 source snapshot:

- active source path at snapshot:
  `/home/aella/parser-studio-beginner-parser-set-e2e-20261016`
- source HEAD at snapshot:
  `19ea6fba6bb5e81f6a2cba7e6cba8fcea2d63313`
- source `src/genericStructural.ts` SHA-256 at the snapshot boundary:
  `b42a4212f3b120f277c06322c952ddce9e4c61ab4e4e778af1d2570385384c26`

Phase 1 independent PoC:

- path:
  `/home/aella/parser-studio-syslog-foundation-poc-20261016`
- branch:
  `poc/syslog-envelope-foundation-20261016`
- baseline snapshot:
  `aa457e8`
- fixed corpus:
  `75f0820`
- validated/pushed envelope candidate:
  `43c110e38d66c3da1cd60f5dc6ab456c13ee5f43`

Phase 2 is another independent clone so that ongoing Phase 1 work cannot contaminate the evidence:

- path:
  `/home/aella/parser-studio-syslog-body-decoupling-poc-20261016`
- branch:
  `poc/syslog-body-decoupling-20261016`
- exact base:
  `43c110e38d66c3da1cd60f5dc6ab456c13ee5f43`

No product merge, release, deployment, credential change, or production mutation is part of this PoC.

## Research survey

The survey covered standards, security analytics products, collectors/pipelines, open-source parsers, data-lake structure discovery, and log-parsing research.

### 1. Standards

RFC 5424 defines the Syslog message as an outer reusable envelope:

```text
PRI VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
```

PRI has a bounded 0..191 value and the header fields are independently defined from the residual message.

Reference:

- RFC 5424 — The Syslog Protocol
  - https://www.rfc-editor.org/rfc/rfc5424

Product implication:

- PRI, timestamp, hostname and application metadata should be parsed once.
- The remaining `MSG` should be handed to a body parser.
- Vendor parsers should not repeatedly rediscover the same Syslog header.

### 2. OpenTelemetry Collector

The OpenTelemetry Syslog receiver explicitly separates transport framing from message parsing.

Its supported protocols include `rfc3164`, `rfc5424`, and experimental `none`.
With `none`, transport framing still applies, the body remains unparsed, and a leading PRI can still be decoded.

References:

- https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/receiver/syslogreceiver
- https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator/parser/syslog

Product implication:

- RFC 6587/TCP framing belongs before the Syslog envelope parser.
- A structurally valid envelope can be useful even when the residual body is not yet decoded.
- `ENVELOPE_PARSED` and `BODY_STRUCTURED` must be separate states.

### 3. Vector

Vector's Syslog source and `parse_syslog` function use best-effort handling for RFC 6587, RFC 5424, RFC 3164, and common deviations.

References:

- https://vector.dev/docs/reference/configuration/sources/syslog/
- https://vector.dev/docs/reference/vrl/functions/

Product implication:

- Real devices deviate from one exact RFC shape.
- A bounded compatibility layer is preferable to proliferating vendor-specific full-line regexes.
- Deviations still need explicit error handling; "loose" must not mean "accept anything."

### 4. Wazuh

Wazuh uses a pre-decoding stage before source-specific decoding.
The pre-decoder extracts general Syslog-like timestamp, hostname and program information.
The subsequent decoder consumes the remaining message.

References:

- https://documentation.wazuh.com/current/user-manual/ruleset/decoders/index.html
- https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html

Product implication:

- This is the same architectural boundary validated by the PoC:
  `header -> residual message -> decoder`.

### 5. Google Security Operations

Google SecOps explicitly models hybrid formats such as:

- `SYSLOG + JSON`
- `SYSLOG + XML`
- `SYSLOG + CSV`
- `SYSLOG + KV`

Its parser-extension workflow separates a Syslog extractor from the target structured part before field mapping.

References:

- https://docs.cloud.google.com/chronicle/docs/event-processing/using-parser-extensions
- https://docs.cloud.google.com/chronicle/docs/ingestion/parser-list/supported-default-parsers

Product implication:

- "Syslog" and "body format" are orthogonal dimensions.
- Parser Studio should detect and expose both dimensions instead of assigning one monolithic format label.

### 6. Splunk Connect for Syslog

Splunk Connect for Syslog has PAN-OS product/log-family routes and message-content parsing after Syslog ingestion.
It distinguishes PAN traffic, threat, system, config, HIP match, correlation and User-ID streams.

Reference:

- https://splunk.github.io/splunk-connect-for-syslog/develop/sources/vendor/PaloaltoNetworks/panos/

Product implication:

- PAN-OS should be routed by log family after the transport/header stage.
- The correct family dictionary should be selected only after structural extraction.

### 7. Microsoft Sentinel ASIM

ASIM separates unifying parsers from source-specific parsers.
Its parser-development guidance explicitly calls out differing device versions, non-standard source formats, and intermediary modifications as reasons to maintain source-specific logic.

References:

- https://learn.microsoft.com/azure/sentinel/normalization-parsers-overview
- https://learn.microsoft.com/en-us/azure/sentinel/normalization-develop-parsers

Product implication:

- Parsing and normalization should remain separate.
- A common normalized schema does not justify a universal source parser.
- Variant handling should remain inspectable and source-specific where semantics differ.

### 8. Elastic Dissect and Grok

Elastic recommends delimiter-oriented Dissect for reliably repeated structured messages and Grok/regex when variable text really requires regex power.

References:

- https://www.elastic.co/docs/solutions/observability/streams/processors/dissect
- https://www.elastic.co/docs/reference/query-languages/esql/esql-process-data-with-dissect-grok

Product implication:

- CSV/KV/delimited security logs should not be forced through increasingly large regular expressions.
- Prefer deterministic delimiter/token parsers first, regex only where structure requires it.

### 9. Palo Alto Networks documentation

The official PAN-OS Traffic log format is ordered positional data beginning with fields such as future-use, receive time, serial number, type, subtype and generated time.
The field list is long and evolves as PAN-OS adds capabilities.

References:

- https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields
- https://docs.paloaltonetworks.com/ngfw/help/12-2/config-log-fields

Product implication:

- The PAN body is fundamentally positional CSV.
- First preserve every source column.
- Only then select a vetted field dictionary by log family and evidence.
- Do not infer semantic column names from values.

### 10. Drain / Drain3

Drain uses a fixed-depth parsing tree for online template extraction.
Drain3 specifically recommends removing structured fields such as timestamp, hostname and severity before template mining because this improves mining accuracy.

References:

- https://ieeexplore.ieee.org/document/8029742
- https://github.com/logpai/Drain3

Product implication:

- Template mining belongs after deterministic envelope/delimiter parsing.
- Drain-style mining is appropriate for residual free text, not for replacing Syslog/CSV/KV parsing.

### 11. Loghub-2.0 benchmark

Loghub-2.0 provides large annotated datasets across 14 software systems with an average of about 3.6 million log lines per dataset.

Reference:

- https://github.com/logpai/loghub-2.0

Product implication:

- Our security-product corpus should eventually be complemented by a large-scale structural benchmark.
- However, generic software-log benchmark success is not a substitute for security-vendor correctness.

### 12. Logram

Logram uses n-gram dictionaries and reports comparable parsing accuracy with materially higher efficiency on 16 public datasets.

Reference:

- https://arxiv.org/abs/2001.03038

Product implication:

- N-gram/template approaches can be considered as an optional residual-text candidate generator.
- They should not supersede deterministic parsing for well-defined Syslog, JSON, CEF, LEEF, KV or CSV bodies.

### 13. LogParser-LLM

LogParser-LLM combines LLM semantics and statistical parsing.
Its large-scale LogPub evaluation reports an average 3.6 million logs per dataset across 14 datasets, with 90.6% grouping F1 and 81.1% parsing accuracy.

Reference:

- https://arxiv.org/abs/2408.13727

Product implication:

- LLM assistance can be useful for residual unknown templates or human-reviewed repair.
- It must remain downstream of deterministic extraction and the existing privacy/review gates.
- LLM output must not be treated as native/runtime verification.

### 14. Datamaran and data-lake structure discovery

Datamaran discovers record/field boundaries, separates structure from noise and supports multiple structures without requiring known record boundaries.
Its paper reports 95% extraction accuracy on automatically collected GitHub log datasets.

Reference:

- https://arxiv.org/abs/1708.08905

Product implication:

- Data-lake structure discovery is valuable for offline corpus discovery and unknown-family candidate generation.
- It is not a replacement for bounded deterministic production parsing.

## Phase 1 measured result

The fixed 49-positive / 12-malformed corpus produced:

| Metric | Snapshot baseline | Layered envelope candidate |
| --- | ---: | ---: |
| Positive events | 49 | 49 |
| Generic Structural parsed | 15 / 49 (30.6%) | 43 / 49 (87.8%) |
| Structured body extracted | 13 / 49 (26.5%) | 43 / 49 (87.8%) |
| Dedicated Syslog envelope | 14 / 49 (28.6%) | 49 / 49 (100%) |
| Malformed negatives accepted | 0 / 12 | 0 / 12 |
| Existing Generic Structural regression | 29 / 29 | 29 / 29 |

The six records not promoted to Generic Structural are five Snort-style free-text records and one generic RFC 5424 free-text record.

Their outer envelopes are parsed successfully.
Their residual bodies intentionally remain unstructured.

That is a valid partial result, not a total parse failure.

## Phase 2 problem: vendor bodies were still header-coupled

After Phase 1, a residual test rewrote only the outer timestamp/wrapper while keeping the vendor body constant.

Families:

- Cisco ASA
- Juniper RT_FLOW
- Check Point bracket key/value
- Cisco ISE comma key/value
- WatchGuard
- Sophos key/value

Five wrapper variants per body produced 30 events.

Before body decoupling:

| Metric | Result |
| --- | ---: |
| Envelope recognized | 30 / 30 |
| Vendor/body structured | 16 / 30 |

Per-family structured coverage was:

| Family | Before |
| --- | ---: |
| Cisco ASA | 3 / 5 |
| Juniper RT_FLOW | 1 / 5 |
| Check Point bracket KV | 0 / 5 |
| Cisco ISE comma KV | 5 / 5 |
| WatchGuard | 2 / 5 |
| Sophos KV | 5 / 5 |

This proves that a common envelope alone is insufficient if the downstream vendor parser reparses the complete original wire line.

## Phase 2 implementation

The PoC decouples residual-body parsing while preserving existing strict parsers and output contracts.

Added body-only paths for:

- Cisco ASA/FTD message body
- Juniper RT_FLOW message body
- Check Point bracket colon-KV
- WatchGuard traffic message body

The shared flow is now conceptually:

```text
raw
 -> parseSyslogEnvelope(raw)
 -> envelope.message
 -> deterministic body parser
 -> vendor/log-family parser
 -> source-preserving fields
```

Existing strict full-line parsers remain first in the chain so currently verified outputs are preserved.

## Known-family fail-closed rule

A critical lesson from adversarial testing is that generic fallback must not erase evidence that a known parser failed.

Examples:

- A PAN-like CSV with invalid PAN receive-time/log-type anchors must not silently become a successful PAN event.
- An `RT_FLOW_SESSION_*` message with an unsupported/malformed RT_FLOW event must not fall through to a generic BSD tagged-message success.
- An ASA message with invalid ports/context must not be accepted by a weaker generic parser.
- A malformed Check Point bracket structure must not become generic key/value success.

The product rule should be:

> Once a high-confidence known-family signature is present, failure of that family's structural validation is a typed failure/partial result, not permission to retry with a weaker semantic grammar.

Generic fallback is valid only when it does not make a stronger unsupported semantic claim.

## Phase 2 measured result

After body decoupling:

| Metric | Before | After |
| --- | ---: | ---: |
| Cross-wrapper vendor events | 30 | 30 |
| Envelope recognized | 30 / 30 | 30 / 30 |
| Vendor/body structured | 16 / 30 (53.3%) | 30 / 30 (100%) |
| Malformed known-vendor bodies accepted | n/a | 0 / 9 |

Per-family result:

| Family | Before | After |
| --- | ---: | ---: |
| Cisco ASA | 3 / 5 | 5 / 5 |
| Juniper RT_FLOW | 1 / 5 | 5 / 5 |
| Check Point bracket KV | 0 / 5 | 5 / 5 |
| Cisco ISE comma KV | 5 / 5 | 5 / 5 |
| WatchGuard | 2 / 5 | 5 / 5 |
| Sophos KV | 5 / 5 | 5 / 5 |

## Deterministic combinatorial test

The matrix test uses:

- five PRI values: 0, 14, 34, 134, 191;
- six structured security-body families;
- seven timestamp/envelope wrappers.

Total:

- 210 valid combinations.

Result:

- envelope parsed: 210 / 210;
- structured body parsed: 210 / 210;
- failures: 0.

The invalid-header matrix contains 16 boundary-invalid records.

Result:

- accepted: 0 / 16.

## Adversarial test

The Phase 2 adversarial suite covers malformed:

- PRI;
- RFC 3164 dates/clocks;
- RFC3339 dates;
- numeric time zones;
- RFC 5424 version;
- PAN-like positional CSV;
- ASA ports/context/message IDs;
- Juniper RT_FLOW;
- Check Point bracket KV;
- WatchGuard metadata;
- JSON;
- CEF;
- LEEF;
- space KV;
- embedded newline/NUL.

It also checks that a valid free-text Syslog record can be recognized as an envelope while not being promoted to deterministic structured-body success.

Result:

- 31 / 31 tests pass.

## Whole-product regression evidence

Phase 2 was validated against the complete current test suite, not only PoC tests.

Final validation:

- `npm test`: **94 test files / 772 tests PASS**
- `npm run typecheck`: **PASS**
- `npm run build`: **PASS**
- `git diff --check`: **PASS**

Production build:

- Vite 6.4.4
- 1,644 modules transformed
- build completed successfully
- the existing large-chunk warning remains unrelated to this parser PoC

## Recommended product architecture

Adopt the following explicit stages in the parser IR and Funnel:

### Stage A — transport framing

Responsibilities:

- RFC 6587 octet counting/non-transparent framing
- line/multiline event boundaries
- input size limits

Do not mix transport framing into vendor regexes.

### Stage B — Syslog envelope

Output should include:

- PRI
- facility
- severity
- protocol/version
- timestamp/date/time/timezone
- hostname
- app name
- process ID
- message ID
- structured data
- residual message
- envelope variant
- confidence/evidence

### Stage C — body dialect

Run bounded candidates against only the residual message:

- JSON
- CEF
- LEEF
- KV
- CSV/delimited
- bracket KV
- positional token stream
- free text

### Stage D — vendor/log family

Use strong source evidence to choose:

- PAN-OS Traffic/Threat/System/Config/GlobalProtect/etc.
- ASA/FTD message family
- Juniper RT_FLOW event family
- WatchGuard family
- Check Point family
- other supported security families

A vendor body parser must not depend on one particular outer Syslog timestamp shape.

### Stage E — semantic mapping

Only after structural extraction:

- assign official vendor field names;
- select field dictionaries by evidence-backed log family;
- preserve all unknown/unmapped fields;
- record dictionary/profile revision.

### Stage F — normalization

Map source semantics into the Stellar/Interflow destination schema with independent evidence and review.

## Required result states

Do not collapse all outcomes to PASS/FAIL.

Use at least:

- `ENVELOPE_PARSED`
- `BODY_STRUCTURED`
- `BODY_UNPARSED`
- `KNOWN_FAMILY_INVALID`
- `SEMANTIC_MAPPED`
- `NORMALIZED`
- `NATIVE_VERIFIED`

This makes a Snort free-text body correctly appear as:

```text
ENVELOPE_PARSED
BODY_UNPARSED
```

instead of incorrectly reporting that "the Syslog log could not be parsed."

## PAN-OS product decision

The common Palo Alto failure should be fixed through layering, not one more full-line PAN regex.

Recommended PAN flow:

```text
raw event
 -> framing
 -> Syslog envelope
 -> residual CSV
 -> source-preserving column extraction
 -> PAN log-type validation
 -> official PAN field dictionary
 -> semantic mapping
 -> normalization
```

This means a new timestamp wrapper does not require a new PAN parser.

PAN field lists also evolve over time, so the parser should:

- preserve all columns before naming them;
- use log-type plus field-count/profile evidence;
- never discard tail columns simply because a known dictionary is shorter;
- mark profile uncertainty for review rather than shifting columns silently.

## Where statistical/ML/LLM parsing belongs

The research does not justify putting Drain, neural models or LLMs in front of deterministic security-log parsing.

Recommended ordering:

1. deterministic framing;
2. deterministic Syslog envelope;
3. deterministic JSON/CEF/LEEF/KV/CSV;
4. deterministic vendor/log-family grammar;
5. only then template mining / statistical / LLM assistance for residual free text.

Candidate roles for Drain/Logram/LLM:

- discover recurring unknown templates;
- propose boundaries/variables;
- rank candidate body grammars;
- propose a reviewed parser repair;
- generate additional test fixtures.

They must not:

- overwrite deterministic source values;
- bypass fail-closed known-family validation;
- claim runtime/native verification;
- send sensitive raw customer logs externally by default.

## Product integration recommendation

The PoC hypothesis is validated strongly enough to integrate, but the PoC branch should not replace the active development branch wholesale.

Recommended integration sequence:

1. Introduce `syslog_envelope` as a first-class Parser IR stage.
2. Move body-format detection to `envelope.message`.
3. Decouple existing vendor parsers from outer timestamp/header parsing.
4. Add known-family fail-closed routing.
5. Expose envelope/body/semantic/normalization states in Test Lab.
6. Add RFC 6587 framing as a separate event-breaking concern.
7. Expand the security corpus with real vendor samples and negative mutations.
8. Add official PAN family dictionaries behind source-preserving CSV extraction.
9. Re-run Full User E2E on the same candidate before any product merge/release decision.

## Final PoC decision

**Adopt the layered Syslog architecture as the product direction.**

Measured evidence shows:

- broad security-log structural coverage improves substantially;
- timestamp/wrapper variants stop requiring duplicate vendor grammars;
- vendor body portability improves from 16/30 to 30/30 in the cross-wrapper test;
- deterministic matrix coverage is 210/210;
- malformed known-vendor bodies remain fail-closed;
- the entire current unit suite remains green at 772/772 tests;
- typecheck and production build remain green.

The remaining work is product integration and broader real-world corpus qualification, not another round of full-line regex expansion.
