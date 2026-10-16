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


## Extended ecosystem survey

The initial convergence was checked against a broader set of implementation families rather than relying on one collector or one SIEM.

### Protocol and collector layer

- RFC 3164 defines PRI, then a HEADER containing timestamp and hostname, then the remaining MSG/content. It also documents real-world timestamp/header deviations seen in relays and devices.
- RFC 5424 makes the boundary explicit as HEADER + STRUCTURED-DATA + optional MSG.
- OpenTelemetry Collector's Syslog operator supports RFC 3164, RFC 5424, and a framing-only `none` mode; in that mode the payload remains message data and a leading PRI can still be decoded.
- Vector explicitly attempts best-effort parsing across RFC 6587, RFC 5424, RFC 3164, and common deviations.
- rsyslog's RFC3164 parser has compatibility controls such as `detect.YearAfterTimestamp` and headerless detection rather than requiring every producer to emit one exact header shape.
- `StephenWakely/syslog-loose` contains the explicit implementation strategy "attempt to parse 5424 first, if this fails move on to 3164."

These are independent confirmations that transport/framing and Syslog envelope recognition should be upstream of product-specific payload parsing.

### Security analytics / SIEM layer

- Wazuh decoder `prematch` evaluates the content after a Syslog-like header, which is the same header/body separation used by this PoC.
- Splunk Connect for Syslog identifies PAN-OS with an MSG-format-based filter, then assigns product/log-family sourcetypes such as `pan:traffic`, `pan:threat`, `pan:system`, and `pan:config`. Splunk's PAN-OS field/classification pipeline also explicitly removes the Syslog header before field extraction.
- Microsoft Sentinel ASIM uses source-specific parsers beneath unifying parsers and normalizes the results into common schemas. Its parser-development guidance is explicitly Filter -> Parse -> Prepare fields and recommends representative samples and separate handling for parsing variants.
- Google Security Operations transforms source-specific raw logs into UDM, keeps parser identity tied to a log type, and supports parser extensions for `SYSLOG + JSON`, `SYSLOG + XML`, and `SYSLOG + CSV`. That is direct evidence for treating Syslog and the nested body format as composable layers rather than one complete-line regex.
- Elastic Dissect recommends delimiter-based extraction for reliably repeated structured text and reserves Grok/regex for shapes that actually need regex flexibility.

The common architecture is therefore:

`framing -> envelope -> source/body parser -> semantic mapping -> normalized schema`

rather than:

`one vendor-specific full-line regex -> normalized fields`.

### Vendor evidence

Palo Alto Networks' official Traffic log documentation defines an ordered positional body beginning with FUTURE_USE, Receive Time, Serial Number, Type, subtype, Generated Time, source/destination addresses, and subsequent fields. The product documentation also distinguishes multiple PAN-OS log families.

Splunk independently classifies PAN-OS message bodies into the same broad families after Syslog ingestion. Together these sources justify:

1. validating a PAN-OS structural signature at the body layer;
2. preserving every CSV value first;
3. selecting semantic field dictionaries only after the log type is known;
4. not duplicating the PAN body parser for every outer timestamp variant.

### Research and template mining

The Drain paper evaluates an online fixed-depth parse-tree approach on more than 10 million raw log messages and reports strong parsing accuracy and improved online runtime versus the compared online parser.

Drain3's maintained implementation adds a directly relevant operational recommendation: template-mining accuracy can improve when structured fields such as timestamp, hostname, and severity are removed before the free-text portion is mined.

That supports using template mining only as a late fallback for residual free text. It should not replace deterministic Syslog, JSON, CEF, LEEF, KV, CSV, or known vendor-body grammars.

No third-party parser code was copied into this PoC. The external implementations were used as architecture and behavior references; the candidate code is independently implemented and covered by local deterministic tests.

## Stage 2 — decouple vendor bodies from the outer Syslog wrapper

The first envelope candidate exposed a second architectural coupling: several existing vendor parsers still embedded the outer RFC3164 timestamp/hostname directly inside their vendor grammar.

A dedicated cross-wrapper test applied six existing security body families to five valid outer timestamp variants:

- Cisco ASA
- Juniper RT_FLOW
- Check Point bracket/colon KV
- Cisco ISE comma/KV
- WatchGuard
- Sophos KV

Before body/header decoupling, only 16 / 30 combinations were structurally extracted even though all 30 envelopes were valid.

The PoC then extracted bounded body-only helpers and invoked them only after a validated Syslog envelope. The same test became:

| Cross-wrapper metric | Stage 1 | Stage 2 |
| --- | ---: | ---: |
| Valid envelope combinations | 30 / 30 | 30 / 30 |
| Structurally extracted vendor combinations | 16 / 30 (53.3%) | 30 / 30 (100%) |
| Cisco ASA | 3 / 5 | 5 / 5 |
| Juniper RT_FLOW | 1 / 5 | 5 / 5 |
| Check Point bracket/colon KV | 0 / 5 | 5 / 5 |
| Cisco ISE comma/KV | 5 / 5 | 5 / 5 |
| WatchGuard | 2 / 5 | 5 / 5 |
| Sophos KV | 5 / 5 | 5 / 5 |

This confirms that the timestamp problem and vendor-body problem are the same architectural issue at two different layers: grammars were coupled across boundaries that should be composable.

## Large deterministic matrix

A generated deterministic matrix crosses:

- 5 valid PRI values;
- 6 body families: PAN-OS CSV, Fortinet KV, JSON, CEF, LEEF, pfSense CSV;
- 7 outer wrappers: RFC3164, year-before-time, year-after-time, RFC3339 Z, RFC3339 with offset/fraction, separated ISO date/time/timezone, and slash-date.

Result:

- 210 / 210 envelope parses
- 210 / 210 structured body parses
- 0 structural failures

A separate RFC5424 matrix exercises JSON, CEF, and LEEF after RFC5424 structured-data boundaries.

Boundary-invalid matrix inputs include invalid PRI, day, hour, minute, second, leap date, timezone, RFC5424 version, structured data, newline, and NUL cases. None were accepted by the envelope layer.

## Adversarial fail-closed findings

Broadening acceptance initially exposed an important failure mode: a malformed known vendor record could fail its strict parser and then be accidentally accepted by a looser generic CSV/message parser.

Examples found by the adversarial suite included:

- PAN-OS-like CSV with an impossible Receive Time;
- PAN-OS-like CSV with an unknown log type;
- Juniper RT_FLOW with an unsupported event name;
- malformed ASA variants;
- malformed Check Point bracket KV;
- malformed CEF/LEEF/JSON/KV bodies.

The final PoC adds a negative guard:

- when a body has a strong known-vendor signature, strict validation failure is terminal for that structural path;
- the event must not silently fall through and become a weaker generic "success";
- preserving an incomplete payload as a message is allowed only when the output is explicitly a message/partial result rather than structured traffic fields.

After the guard:

- adversarial suite: 31 / 31 PASS;
- cross-wrapper malformed-vendor suite: 9 / 9 rejected as structured successes;
- matrix-invalid suite: 16 / 16 rejected;
- fixed 12-event malformed corpus: 0 accepted.

## Final implementation recommendation

The PoC now supports a stronger product architecture than the original proposal:

1. **Event framing** — RFC6587/newline/multiline belongs here.
2. **Syslog envelope** — PRI/facility/severity, timestamp family, hostname, app/procid/msgid, structured data.
3. **Body dialect** — JSON, CEF, LEEF, KV, CSV, residual text.
4. **Vendor/log-family body grammar** — PAN-OS, ASA, Juniper, WatchGuard, Check Point, and future families, independent from the outer wrapper.
5. **Source-preserving extraction** — retain every source value before semantics.
6. **Semantic mapping** — apply official vendor dictionaries or reviewed mappings.
7. **Normalization** — map to Stellar/portable normalized fields only after extraction succeeds.
8. **Residual free-text fallback** — optional Drain-style/template mining after deterministic structure has been removed.

The product should keep separate result states for:

- envelope recognized;
- body structure recognized;
- vendor family recognized;
- source values preserved;
- semantic mapping complete;
- normalization complete.

This prevents "header parsed" from being reported as "event fully parsed" and prevents a malformed known vendor message from becoming a generic false positive.


## Final local qualification

Final candidate validation on the isolated PoC clone:

- full Vitest suite: 94 test files PASS;
- full Vitest assertions: 772 / 772 PASS;
- TypeScript typecheck: PASS;
- production build: PASS;
- deterministic Syslog matrix: 210 / 210 structured combinations PASS;
- vendor cross-wrapper matrix: 30 / 30 PASS;
- adversarial Syslog suite: 31 / 31 PASS;
- malformed vendor-body suite: 9 / 9 does not become a structured success;
- original Generic Structural focused regression: 29 / 29 PASS.

The Vite production build reports only the repository's existing large-chunk advisory; it is not a parser correctness failure.

This remains a PoC branch. It is intentionally not merged into the active product development worktree. Product integration should cherry-pick/reimplement the small architectural units into the active Funnel pipeline after reviewing the active branch's concurrent changes.

## Expansion round 2 — body dialect, framing, and strictness

After the first envelope/vendor-body decoupling result, the PoC continued against additional security-log structures and protocol deviations. The second round intentionally targeted gaps rather than repeating the original PAN-OS success cases.

Added coverage:

- RFC6587 octet-counted and non-transparent framing;
- RFC3164 timezone/year ordering variants;
- RFC5424 structured-data element/parameter extraction;
- RFC5424 UTF-8 BOM-prefixed bodies;
- Snort bounded alert bodies;
- embedded JSON and `@cee:` JSON;
- pipe, semicolon, and tab-delimited `key=value` bodies;
- short but deterministic 3–4 field space-KV bodies behind a validated envelope;
- IPv6-aware network token and flow-tuple validation;
- strict leap-year/calendar validation across common and vendor-specific headers;
- known-dialect downgrade guards so malformed vendor payloads cannot be rescued by a looser generic parser.

### Fixed corpus improvement

The original 49-event fixed corpus now measures:

| Metric | Initial baseline | Round 1 | Round 2 |
| --- | ---: | ---: | ---: |
| Structured parser success | 15 / 49 (30.6%) | 43 / 49 (87.8%) | 48 / 49 (98.0%) |
| Structured body extraction | 13 / 49 (26.5%) | 43 / 49 (87.8%) | 48 / 49 (98.0%) |
| Malformed fixed-corpus events accepted | 0 / 12 | 0 / 12 | 0 / 12 |

The only fixed-corpus record intentionally not promoted to a structured success is ordinary RFC5424 free text. Its envelope is parseable, but it does not contain deterministic structured body fields, so treating it as a structured event would inflate recall by changing the definition of success.

### Round-2 deterministic evidence

- dedicated PoC suites: 17 / 17 files PASS, 131 / 131 tests PASS;
- full repository unit suite: 106 / 106 files PASS, 802 / 802 tests PASS;
- TypeScript typecheck: PASS;
- production build: PASS;
- fixed corpus structured success: 48 / 49;
- 210-combination Syslog/body matrix: 210 / 210 PASS;
- vendor cross-wrapper matrix: 30 / 30 PASS;
- delimiter-aware KV matrix: 24 / 24 PASS;
- embedded JSON / CEE matrix: 8 / 8 PASS;
- short envelope KV matrix: 8 / 8 PASS;
- IPv6 positional CSV matrix: 4 / 4 PASS;
- RFC3164 timezone/year variants: 8 / 8 PASS;
- RFC5424 structured-data cases: 5 / 5 PASS;
- RFC5424 BOM structured bodies: 4 / 4 PASS;
- Snort fixed-corpus wrapper variants: 5 / 5 PASS.

Negative/adversarial evidence remains fail-closed:

- invalid timestamp/calendar matrix: 10 / 10 rejected;
- invalid RFC3164 timezone/year cases: 6 / 6 rejected;
- malformed delimiter KV: 5 / 5 rejected;
- malformed embedded JSON/CEE: 8 / 8 rejected;
- ambiguous/unsafe short KV: 5 / 5 rejected;
- malformed Snort: 5 / 5 rejected;
- invalid ASA network tokens: 5 / 5 rejected;
- invalid Juniper tuples: 5 / 5 rejected;
- malformed vendor-body cross-wrapper cases: 9 / 9 rejected;
- known-dialect downgrade attempts: 4 / 4 rejected.

### Round-2 architectural implication

The parser is now materially less dependent on enumerating vendor-specific complete-line regexes. The strongest reusable hierarchy observed by the tests is:

`framing -> envelope -> deterministic body dialect -> vendor refinement -> semantic mapping`

This is preferable to adding another full-line vendor rule whenever a timestamp, timezone, relay wrapper, or transport framing changes.

## Expansion round 3 — XML, schema-aware tabular logs, and multi-record streams

Round 3 targeted common security-log structures that do not fit the JSON/KV/CSV-only path and transport behavior that occurs before individual event parsing.

### Added parser capabilities

- bounded XML body extraction for standalone XML and XML nested inside RFC3164/RFC3339/RFC5424 Syslog envelopes;
- Windows Event XML leaf/attribute preservation, including `Data Name="..."` values;
- Zeek `conn.log`-style TSV candidate extraction with IPv4/IPv6 endpoint validation;
- Zeek `#fields` schema parsing and exact-cardinality row mapping;
- W3C/IIS `#Fields:` schema parsing with bounded quoted-space row mapping;
- RFC6587 multi-record stream splitting for concatenated octet-counted frames;
- RFC6587 non-transparent multi-record splitting for LF, CRLF, and NUL delimiters.

XML handling is deliberately bounded. DTD/entity declarations, XML stylesheets, parser errors, unsafe field names, deep/large trees, mixed text/child content, and shallow ambiguous XML are rejected rather than promoted to a structured success.

Zeek/W3C schema helpers preserve explicit source schema names when a header is provided. Headerless Zeek conn candidates remain source-preserving positional `column_N` output rather than inventing semantic names.

RFC6587 stream parsing uses UTF-8 octet lengths rather than JavaScript character counts. The PoC found and fixed a CRLF stream-boundary bug during testing.

### Round-3 deterministic evidence

- Round-3 focused suites: 6 / 6 files PASS, 16 / 16 tests PASS;
- all Syslog/security PoC suites: 23 / 23 files PASS, 147 / 147 tests PASS;
- full repository unit suite: 112 / 112 files PASS, 818 / 818 tests PASS;
- TypeScript typecheck: PASS;
- production build: PASS;
- Windows Event XML: 5 / 5 valid variants PASS;
- unsafe/malformed XML: 6 / 6 rejected;
- Zeek conn TSV: 5 / 5 standalone/wrapped variants PASS;
- malformed or metadata-only Zeek TSV: 6 / 6 rejected;
- Zeek `#fields` schema mapping: PASS, including exact-cardinality and unsafe/duplicate-field rejection;
- W3C/IIS `#Fields:` schema mapping: PASS, including quoted values and invalid schema/row rejection;
- RFC6587 multi-record octet-counted stream: PASS with UTF-8 multibyte payload;
- RFC6587 LF/CRLF/NUL multi-record streams: PASS;
- malformed/mixed/truncated RFC6587 streams: 10 / 10 rejected.

### Round-3 design conclusion

The parser boundary should be widened one level above a single event:

`stream framing -> logical record -> Syslog envelope -> nested body dialect -> optional explicit schema -> vendor refinement -> semantic mapping`

This avoids forcing TCP/TLS stream framing, Windows XML, Zeek TSV, and W3C schema handling into vendor-specific complete-line regexes. It also preserves explicit source schemas where available instead of guessing field names.

F5 BIG-IP/ASM research in this round did not justify another vendor-specific parser. Its documented remote output options overlap the already-qualified CEF, CSV, and key/value body dialects, so adding an F5-only full-line grammar would reduce reuse rather than improve the engine architecture.

### Round-3 schema follow-up

- Zeek schema handling now also consumes `#types`, `#path`, unset/empty markers, and bounded multi-row blocks; it no longer assumes that valid Zeek logs require six or more columns.
- W3C/IIS schema handling now accepts the authoritative `#Fields:` list without an arbitrary minimum column count, matching the customizable W3C field selection model.
- Final qualification after these schema changes remains 112 / 112 unit files and 818 / 818 assertions PASS, with typecheck and production build PASS.

## Expansion round 4 — cloud telemetry and schema-driven delivery logs

Round 4 extended the same source-preserving parser architecture to common cloud telemetry rather than adding cloud-vendor full-line regexes.

### Added capabilities

- AWS VPC Flow Log version 2 default field order as a bounded structural grammar;
- IPv4 and IPv6 VPC endpoints;
- ACCEPT/REJECT and OK/NODATA/SKIPDATA state validation;
- timestamp ordering, protocol number, port, account ID, and ENI validation;
- standalone VPC Flow records and records nested behind a validated Syslog envelope;
- W3C schema mapping extended to tab-delimited rows so explicit CloudFront `#Fields:` schemas can be reused without guessing column meaning.

The VPC parser preserves the documented source field names:

`version, account-id, interface-id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, log-status`

Values are not coerced into normalized semantics at this stage. The parser only validates the bounded source structure and preserves source values for later semantic mapping.

### Round-4 evidence

- AWS VPC Flow valid IPv4, IPv6, and NODATA records: PASS;
- Syslog-wrapped VPC Flow record: PASS;
- malformed VPC Flow cases: 10 / 10 rejected;
- CloudFront-style 33-field W3C tab schema: PASS;
- W3C tab row cardinality mismatch: rejected;
- full repository unit suite after cloud expansion: 113 / 113 files PASS, 821 / 821 tests PASS;
- TypeScript typecheck: PASS;
- production build: PASS.

### Cumulative architecture after four rounds

The evidence now supports a parser pipeline that is broader than the original Generic Structural implementation while retaining fail-closed behavior:

`stream framing -> logical record -> envelope -> deterministic body dialect -> optional explicit schema -> vendor/cloud source refinement -> semantic mapping -> normalization`

Reusable structural grammars now cover Syslog, JSON, embedded JSON/CEE, XML, CEF, LEEF, multiple KV delimiters, positional CSV, Zeek TSV, W3C schema rows, Snort alerts, PAN-OS, ASA/FTD, Juniper RT_FLOW, WatchGuard, Check Point-style KV, RFC6587 streams, and AWS VPC Flow records.

The remaining fixed-corpus free-text RFC5424 event is intentionally not counted as a structured extraction success because it contains no deterministic body structure to extract.
