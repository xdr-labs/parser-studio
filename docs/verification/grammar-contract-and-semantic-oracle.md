# Grammar Contract and Semantic Oracle

Status: introduced 2026-11-13 (Issue #249). This document is the working
standard for adding or changing a parsing grammar or a field mapping.

## Why defects kept recurring (measured on main `bed8db3`)

| Root cause | Evidence in the code |
|---|---|
| The same header grammar is hand-written in three languages | 148 literal copies of five Syslog header tokens: 69 in TypeScript, 60 in Ruby templates, 19 in Python (`contracts/grammar-duplication-baseline.v1.json`). `[!-~]{1,255}` (HOSTNAME) alone occurs 26 times in 8 files |
| Differential tests pass when both executors are wrong in the same way | F-1: `<134>Nov 13 10:00:00 srcip=10.1.1.1 ...` gives `syslog_hostname="srcip=10.1.1.1"` in `src/structuredFamilies.ts` and in `backend/templates/ruby-fragment.rb.tpl`; the generated Ruby then drops `srcip` and classifies the event as `syslog` instead of `session`. Browser and Ruby agree, so parity is green |
| "Parsed" is declared by the parser that parsed | No stage re-reads the raw line; a field swallowed into the wrong place is still a success |
| Policy is decided per consumer | F-2: `src/rfc5424Subset.ts` parses only VERSION 1, `src/syslogEnvelope.ts` and the Generic Structural Ruby helper accept `[1-9]\d{0,2}` |
| Regular-expression dialects differ silently | F-3 (found by the new property generator): `.` excludes U+2028 in ECMAScript but not in Ruby, so the browser rejects a line that the generated Ruby parses |
| The corpus follows the defects already found | Hand-picked samples; no generator that varies host, PRI, tag, order, Unicode or boundaries with an independent expectation |
| Target runtime differs from the developer runtime | Ruby 2.4.9 gates exist (#299, #301) but covered compiler variants, not grammar semantics |

## Architecture

```
contracts/syslog-header-grammar.v1.json        one declarative grammar (tokens, rules, alternatives, semantic limits)
        |  scripts/grammar/generate-grammar.mjs  (portable-subset validator, --verify in CI)
        +--> src/grammar/syslogHeaderGrammar.generated.ts   ECMAScript dialect  -> src/grammar/syslogHeader.ts
        +--> backend/src/syslog-header-grammar.generated.ts  Ruby dialect        -> injected into the Ruby templates by the compiler
        +--> Python dialect                                  -> Multi-Pass (roadmap)

contracts/semantic-goldens.v1.json             hand-authored expectations (raw text + RFC citation)
src/grammar/syslogHeaderModel.ts               model-rendered property cases, expectation computed from the model
src/grammar/parseStatus.ts                     FULL / PARTIAL / UNKNOWN / ERROR decided against the raw line
scripts/verification/semantic-oracle.ts        both executors versus the expectations + fault injection
scripts/verification/grammar-duplication-ratchet.mjs   hand-written copies may only decrease
```

### A. Single source of truth
A token pattern may use only the regular-expression subset that means the same
in ECMAScript, Ruby 2.4 and Python. The generator rejects `.`, `\d`, `\w`, `\s`,
anchors, back-references, capture groups inside tokens and lazy or possessive
quantifiers. Captures belong to rules and are read by name, so a consumer cannot
shift a group index. Semantic limits (`priMax`, calendar, supported RFC 5424
versions) are contract data.

### B. Semantic correctness oracle
Executors are compared with expectations, not with each other. A golden states
the source fields (browser extraction), the emitted event under a fixed mapping
profile (generated Ruby on Ruby 2.4.9), fields that must be absent, and the
status. The oracle refuses a golden whose expected source value is not literal
raw text.

### C. Parsing success contract
`classifyStructuredParse` re-reads the raw line with a separate, simpler
tokenizer. A key=value pair that is visible in the raw text but missing from
the extracted fields makes FULL impossible (PARTIAL). Extraction errors are
UNKNOWN, a raising extractor is ERROR. FULL does not require a Stellar mapping
for every vendor field.

Wired into the product (W7, first slice): `processEvent` in `src/parser.ts`
classifies every previewed event and puts the verdict on
`EventResult.parseStatus`. For a key=value body (format `kv`, or RFC 3164 /
RFC 5424 with body `kv`) a PARTIAL verdict adds the error diagnostic
`FIELD_LOSS_NOT_FULL`, so the event status is `fail`, `counts.failures` rises
and every existing gate that refuses failed samples refuses it. The RFC 5424
header fields are positional and are not counted as pairs (a HOSTNAME written
`a=b` is a host name); RFC 3164 gets no such exemption because its HOSTNAME is
optional. `src/parseStatusGate.test.ts` injects an F-1 style loss into the
extractor and requires `fail`. On the 3,897 audit lines no correctly parsed
line is classified PARTIAL (281 key=value parses, all FULL).

`auto` bodies and the key=value branches of a `mixed` allowlist are covered as
well: the extractor records which body dialect it actually parsed
(`bodyKindOf` in `src/structuredFamilies.ts`, kept beside the result so its
shape does not change) and the pipeline applies pair accounting whenever that
is key=value. The draft-based condition stays in place, so losing the record
cannot switch the check off.

Generated Ruby at run time (W7). A line that never appeared as a sample is
checked by the artifact itself: `parserstudio_extract` ends with
`parserstudio_assert_no_field_loss(text, result)` in both templates. For a
key=value body the original text is read again by a separate control flow
(every white-space separated token is visited, with no header and no pair
order; the key and quoted-value tokens are the contract's) and a pair that is
missing, has another value, or occurs more often in the text than in the
result raises, so the event becomes an error record instead of a parsed event
that lacks a field. A TAG (`kernel:`) or a pair read as the RFC 3164 host name
is refused the same way (RFC 5424 HOSTNAME is positional and exempt). The
browser applies the same two rules (`src/grammar/parseStatus.ts`,
`HEADER_MISREAD_NOT_FULL`). Proof: the native oracle injects three grammar
faults that lose a pair silently and prints, per fault,
`RUNTIME_FIELD_LOSS_GUARD ... wrong_events_without_guard=N
wrong_events_with_guard=0`; `backend/test/runtime-field-loss-guard.test.ts`
injects pair loss, value truncation and a skipped first pair on six routes in
both templates.

Not covered by the run-time check: CSV, JSON, CEF and LEEF bodies (the oracle
holds those), and Generic Structural, whose verdict is described below.

### D. Property-based and metamorphic cases
Every variant has its own expectation: base, double spaces, reversed pairs,
HOSTNAME omitted, PRI omitted (FULL for the tagless form, NEVER_WRONG for the
tagged form), TAB as separator (UNKNOWN), PRI and day out of range (UNKNOWN),
U+2028 inside a value (FULL). Values cover IPv4 and port boundaries, 64-bit
counters, UTF-8, quoted values that contain `=` and URLs that contain `=`.

### E. Generated artifact contract
The native oracle compiles real projects with `compilePair`, executes the
Fragment on Ruby 2.4.9 and checks event count, mapped values, types,
classification and absence. It also proves that the contract's Ruby regular
expressions capture exactly what its ECMAScript expressions capture.

### Fault injection
The gate must show that it can detect a new defect. Faults are injected into a
private copy of `src/` (TypeScript) and into the generated Fragment (Ruby); every
fault must be reported and the unmutated copy must reproduce the product result.
A `knownDefect` case is a strict expected failure: it must fail on the listed
engines and the gate fails when it starts to pass.

## Migration status

| Consumer | State |
|---|---|
| `src/structuredFamilies.ts` (RFC 3164 extraction and detection), `src/rfc5424Subset.ts`, `src/guided/autoParserEnvelope.ts` (tagless front door) | contract (`src/grammar/syslogHeader.ts`) |
| `backend/templates/ruby-fragment.rb.tpl`, `ruby-forwarder-family.rb.tpl` (`parserstudio_syslog_rfc3164`, `parserstudio_syslog_rfc5424`) | contract, injected by `injectHeaderGrammar` in `backend/src/compiler.ts`; a template with an unresolved `__PS_GRAMMAR_*__` placeholder does not compile |
| `src/genericStructural.ts`, `src/syslogEnvelope.ts`, `backend/templates/generic-structural-helper.rb.tpl`, `runtime/multipass/generic_structural_poc.py` (W4) | header tokens from the contract: PRI, BSD month, printable-ASCII host token, TAG, RFC 5424 VERSION (`T.*` in TypeScript, compiled once per expression; `__PS_GRAMMAR_TOKEN_*__` and `__PS_GRAMMAR_RFC5424_VERSION_PATTERN__` in Ruby; `TOKENS` in Python). 93 literal copies removed |
| the bodies of the Generic Structural sub-profiles, the other `runtime/multipass/*.py` files, a few UI helpers | hand-written; 49 token copies left in the ratchet (142 before W4) |

Resolved: F-1 (field loss when HOSTNAME is omitted), F-2 (one RFC 5424 VERSION
policy, including `detectStructuredFamily`), F-3 (U+2028 inside a value, on the
structured path and in the message of the generic envelope), F-4 (RFC 5424
TIMESTAMP with an impossible day: the browser rejected it, Ruby `Time.iso8601`
rolled it over), F-5 (a TAG such as `kernel:` read as HOSTNAME when HOSTNAME is
omitted). F-4 and F-5 were found by the independent audit of 2026-11-13. The
corresponding goldens and property variants are ordinary must-pass cases; the
faults `contract-hostname-any-printable` and `contract-hostname-trailing-colon`
re-introduce F-1 and F-5 in the contract and must be reported by both
executors. The native oracle runs every case through both Ruby templates
(`ruby-fragment` and `ruby-forwarder-family`).

Known differences that remain (evidence: independent audit, 2026-11-13):

- Python Multi-Pass: `security_envelope.py` (BSD envelope) and the RFC 5424
  VERSION / PRI checks of `structured_source.py`, `security_pairs.py` and
  `generic_structural_poc.py` read the generated
  `syslog_header_grammar_generated.py`; F-1 and F-5 are gone there and the
  oracle has a `python` engine. The other Multi-Pass header expressions are
  still hand-written (ratchet).
- Auto Parser front door, tagged path: still a hand-written header expression
  (W4). Its key=value validation now uses the contract parser.
- Generic envelope and Generic Structural extractor, browser versus Ruby 2.4.9
  (W4): the 34 differing audit lines are resolved (host token delimited by
  ASCII white space, exactly one SP removed before an RFC 5424 MSG, BOM kept,
  `.` spelled out in the BSD message profiles). On the audit's 3,897 lines the
  envelope is identical on all of them and the extractor has no one-sided
  accept and no field difference (707 parsed identically, 3,190 rejected by
  both). The grammar of the Generic Structural sub-profiles is still
  hand-written in TypeScript and Ruby; what is shared is the VERSION gate, the
  goldens (`genericCases`) and the faults.
- The oracle covers the structured RFC 3164 / RFC 5424 path with a key=value
  body, the forwarder-family template and Generic Structural goldens. JSON,
  CEF, LEEF and raw bodies and the mixed router are not in it yet (W6).
- The duplication ratchet counts exact literal copies; a re-spelled copy is not
  counted.

## Key=value body grammar (W3)

`fragments.kv_pair` in the contract is the one definition of a strict key=value
pair: `KEY="..."`, `KEY='...'` or `KEY=bare`, matched at a position (sticky in
ECMAScript, `\G` in Ruby, `pattern.match(text, pos)` in Python). SP and TAB
separate pairs; every other character, NBSP and U+2028 included, is value data.
The pair limit, the forbidden keys and the characters that are decoded after a
backslash are contract semantics.

Consumers: `src/grammar/kvBody.ts` (used by `strictKeyValues` and by the Auto
Parser front door, which previously had its own token expression with a
different white-space notion), and `parserstudio_key_values` /
`parserstudio_unescape` in both Ruby templates. `src/grammar/kvBodyModel.ts`
renders bodies from meant values (quotes of both kinds, escaped quotes,
Windows paths, escaped `=`, U+2028, NBSP, UTF-8, adjacency after a quote,
100/101 pairs, duplicate and forbidden keys, unterminated quotes) and the
oracle runs them through both executors and both Ruby templates.

The Python Multi-Pass source scanner (`runtime/multipass/source_kv.py`) reads
the same fragment, escape set, forbidden keys and pair limit from the generated
Python module. Before, it was a hand-written scanner that split pairs with
`str.isspace()` (so NBSP and U+2028 ended a value, defect F-8) and decoded a
different escape set (`\=` kept, `\ ` decoded). The oracle's `python` engine
sends the goldens and the model-rendered bodies through
`multipass_preview_api.preview`, the entry point the Analyze step calls.

Information separators (issue #214): U+001C..U+001F are never value data and
never a pair separator. `KV_BARE` excludes them, so the strict path of the
browser and of the generated Ruby now declines such a line the same way
Generic Structural and the Python preview already did (defect F-7). The
portable regex subset gained `\xHH` for ASCII code points for this purpose.

Owner policy D-1 (decided 2026-11-14): a field written more than once in one
event is never resolved by keeping one of its values.

| Engine | Behaviour |
| --- | --- |
| Python source preview | keeps the original key and every value in wire order; issue `DUPLICATE_SOURCE_FIELD`, status never `SOURCE_PARSED` |
| Browser extractor | declines the event; the message names the repeated field (`duplicateFieldMessage`) |
| Generated Ruby | declines the event (error record, no parsed event) |

It applies to key=value bodies (bare and under RFC 3164 / RFC 5424), CEF and
LEEF 1.0 / 2.0. The Analyze step names the repeated fields in plain words and
does not offer parser files while a field is repeated. The oracle enforces it
with hand-written goldens and model-rendered cases that carry
`expect.repeated` (every meant value, in order) and with fault injection in all
three engines (`ownerPolicies.D-1` in `contracts/semantic-goldens.v1.json`
lists them).

`parse_quoted_kv` in `runtime/multipass/engine.py` keeps its own pair expression; it has no caller (see below).

## CEF and LEEF (W6)

Covered by the oracle in all three engines: hand-written goldens taken from the
ArcSight CEF and IBM LEEF format guides (`familyCases`) and bodies rendered from
meant values (`src/grammar/cefLeefModel.ts`: header escapes, extension escapes,
multi-word values, Windows and UNC paths, U+2028, UTF-8, LEEF 1.0 and 2.0
separators, missing header fields, truncated escapes, an undefined LEEF
version). Faults are injected into the browser extractor, the generated Ruby
and the Python preview.

Defects this found:

- F-9: a CEF or LEEF line with U+2028 in a value was rejected by the browser
  only (`.` in two head expressions). Fixed with dotAll.
- F-11: the header splitter also decoded backslash escapes in the extension,
  and the extension grammar decoded them again - identically in the browser and
  the generated Ruby, so every differential test passed. A Windows path
  `filePath=C:\\Users\\new` came out as `C:\Users` LF `ew`, and the CEF
  guide's own example `act=blocked a \\ dst=1.1.1.1` lost `dst`. LEEF values,
  which have no escapes at all, lost one backslash of a UNC path. Fixed in
  `splitEscaped` and `parserstudio_split_escaped`: the text after the last
  header delimiter is kept exactly as written. The Python preview was already
  correct.
- F-10: the Python preview reported a malformed CEF/LEEF line as parsed through
  its permissive generic fallback. Fixed with `fragments.structured_family_claim`.

Owner policy D-2 (decided 2026-11-14): inside Generic Structural a line that
claims to be CEF or LEEF (`fragments.structured_family_claim`) is, for every
newly created parser, read by the CEF/LEEF grammar or declined. The marker is
`extraction.genericStructuralFamilyGrammar: "dedicated"` (draft, project
schema, validator, capability `genericStructuralDedicatedFamilies`); it is set
when Generic Structural is selected, built automatically or taken from an AI
recipe, and kept as stored on import. The result is
`{body: <CEF/LEEF fields>, generic: {mode: structured_family_cef |
structured_family_leef, source_raw}}`. A project without the marker keeps its
V15 output (legacy compatibility route: the three existing tests still pass
unchanged); its verdict for such a line is PARTIAL with the warning
`GENERIC_STRUCTURAL_NOT_FULL`, never FULL. A backend that does not advertise
the capability is refused before download (`BACKEND_PROFILE_UNSUPPORTED`).
Enforced by `ownerPolicies.D-2`: `genericCases` with `familyGrammar` and
`expect.status` run against the browser extractor and verdict and against two
compiled Ruby artifacts (with and without the marker) on Ruby 2.4.9; faults
`ts-generic-dedicated-gate-removed`, `ts-generic-claim-verdict-full`,
`rb-generic-dedicated-gate-removed`, `py-generic-family-claim-gate-removed`;
`src/ownerPolicyD2GenericFamilies20261114.test.ts` and
`backend/test/owner-policy-d2-generic-families.test.ts` read the same goldens.

Contract values (revision 5): the CEF extension key token (`CEF_KEY`), the
LEEF attribute key token (`LEEF_KEY`), `cefSupportedVersions`,
`leefSupportedVersions`, `cefMaxExtensionFields`, `cefExtensionEscapes` and the
forbidden keys are read from the contract by the browser extractor, by both
Ruby templates (`__PS_GRAMMAR_TOKEN_CEF_KEY__`, `__PS_GRAMMAR_CEF_*__`,
`__PS_GRAMMAR_LEEF_VERSIONS__`, `__PS_GRAMMAR_FORBIDDEN_KEYS__`) and by the
Python CEF passes. Defect F-13: the Python preview parsed `CEF:1|` while the
browser and Ruby implement CEF version 0 only; all three now read
`cefSupportedVersions`.

The Python LEEF pass (`decode_cef_or_leef` in `structured_source.py`) reads
`leefSupportedVersions`, `LEEF_KEY` and the forbidden keys as well; its own
bounded key expression used to reject an attribute key longer than 128
characters that the browser and Ruby accept.

Control flow (contract revision 6). The CEF extension and the LEEF delimiter
are contract fragments (`cef_pair`, `leef_delimiter`, `leef_attribute`; tokens
`CEF_WS`, `CEF_WS_RUN`, `CEF_NOT_WS`, `CEF_ESCAPE`, `CEF_PLAIN`,
`LEEF_DELIMITER_LITERAL`, `LEEF_HEX_DIGITS`; semantics
`leefDelimiterFieldVersions`, `leefHeaderFields`, `leefDefaultDelimiter`,
`leefDelimiterExtraCodePoints`). The five hand-written CEF extension scanners
are gone (one fragment plus a short loop per engine) and the five copies of
the LEEF delimiter rule, which had three different behaviours, are one. All
three engines now agree: a LEEF hex delimiter is `0x` or `x` plus one to four
hex digits, a white-space delimiter is refused, an empty attribute or a
trailing delimiter is refused, trailing white space of a CEF line is grammar.
`ruby-forwarder-family.rb.tpl` is generated from `ruby-fragment.rb.tpl` plus
an overlay (`scripts/grammar/generate-forwarder-template.mjs`; `--verify` in
CI), which removed 723 duplicated lines. Scanning is linear (200,000 spaces:
milliseconds in JavaScript, Ruby 2.4.9 and Python).

## Generic Structural: browser versus generated Ruby (differential, 2026-11-14)

W4 replaced token literals only, so its acceptance test is that nothing changes: 58,430 lines (every string
of the repository's fixtures and tests plus PRI, VERSION, month, host and key mutations of the 655 lines that
parse) were run through `extractGenericStructural` / `parseSyslogEnvelope` and through the compiled Ruby on
Ruby 2.4.9, in five configurations (legacy, dedicated, three profiles), before and after. The SHA-256 of the
complete output is identical on both sides (browser `56b91485...`, Ruby `e30c8ba3...`).

The same run compares the two engines with each other, which no earlier check did on mutated lines. On the
legacy configuration it found 33 lines parsed only by the browser, 24 parsed only by the generated Ruby and
33 parsed by both with a different field tree. Causes and state:

| Cause | Lines | State |
|---|---|---|
| Positional CSV route: 150 columns in Ruby, 100 in the browser; a PAN-OS row longer than 100 columns got a tree without `syslog.variant` / `generic.profile` from Ruby | 31 | fixed in Ruby (100, and the PAN-OS check of the browser) |
| `Time.new` rolls 30 February over to 2 March, so the Ruby envelope calendar accepted an impossible date; the positional route had no PAN-OS check at all | 23 | fixed in Ruby (calendar by arithmetic, as in the browser) |
| JSON body inside Generic Structural with an integer beyond 2^53: the browser parsed and rounded it, Ruby declined | 19 | fixed in the browser (`parseJsonBody`, one function for the three JSON routes) |
| `.` after PRI stops at U+2028 in JavaScript: another route, another tree | 2 | fixed in the browser (`[^\n]`) |
| An SD-NAME that is not valid (non-ASCII, longer than 32 characters, DEL in the SD-ID): the browser's envelope accepts it, Ruby declines | 14 | open |
| IP token: lexical rule in the browser, `IPAddr.new` in Ruby (`[::1]` is an address only in Ruby; `12:34:56` only in the browser) | 1 | open |

After the fixes: 6,123 lines parsed identically, 15 one-sided, 0 tree differences. Goldens
`generic-envelope-json-integer-beyond-2-53`, `generic-panos-receive-time-30-february`,
`generic-pri-space-kv-u2028`, `generic-panos-traffic-more-than-100-columns` and faults
`ts-generic-json-unsafe-integer-accepted`, `ts-generic-pri-space-kv-stops-at-u2028`,
`rb-generic-calendar-rollover`, `rb-generic-positional-150-columns` keep them.

Open, larger class. A second run put Unicode white space and separators (U+2028, U+2029, NBSP, U+0085, U+3000,
U+FEFF) and edge white space into 26,000 variants of parsing lines: 12,282 parse identically, 1,244 parse with
a different tree, 258 only in the browser, 194 only in Ruby. The cause is one difference used throughout the
hand-written sub-profiles: in JavaScript `\s`, `.` and `trim()` know Unicode white space and line separators,
in Ruby they are ASCII. The generated Ruby is the reference (the contract's KV_GAP already says SP and TAB
only). The remedy is on the browser side only (ASCII classes and an ASCII trim in `src/genericStructural.ts`)
and does not change the Ruby templates; it is not done yet, and this differential is not yet a CI gate. The
harness and both corpora are kept on dev-atlas in `~aella/.local/state/psgc-w4-differential/`.

## RFC 5424 model (W8)

`src/grammar/rfc5424Model.ts` renders RFC 5424 lines with a key=value MSG from
a model of the header fields (RFC 3339 timestamps with fractions and offsets,
a leap day, NILVALUE fields, one SD-ELEMENT) and of the meant pairs, and states
what the RFC does not allow: two SP between header fields, STRUCTURED-DATA
missing, PRI above 191, a day that is not on the calendar, plus the VERSION
policy. The browser, both Ruby templates on Ruby 2.4.9 and the Python preview
meet every expectation without a change.

## JSON model (W8)

`src/grammar/jsonModel.ts` renders a JSON object event from meant values in
spellings RFC 8259 defines as equal (compact, insignificant white space, every
non-ASCII character and `/` escaped, members reversed) and lists texts the RFC
does not allow (trailing comma, single-quoted or bare names, truncation, text
after the object, a leading-zero number, NaN). A repeated member name is
declined by product policy. The browser, the generated Ruby and the Python
preview meet every expectation without a change.

One difference is pinned, not changed: an integer beyond 2^53. The browser and
the generated Ruby decline the event (review safety); the Python preview keeps
it and reports exactly the digits written. The oracle allows a decline and
requires exact digits from whoever parses it, so a rounding engine fails.

## Parse status and Generic Structural (wired)

The strict pair accounting of `classifyStructuredParse` would report correct
Generic Structural parses as PARTIAL (message profiles keep the message as one
text field, SD-PARAMs sit under their SD-ELEMENT, `space_kv` gives the last
pair the rest of the line). `classifyGenericStructural`
(`src/grammar/genericParseStatus.ts`) therefore decides from the original line
and the result, the same way for every mode: a raw pair is accounted for when
a field of that name holds its value or a kept text field holds the pair as
written; the provenance copies `source_raw` and `message_raw` are not fields.
FULL needs every pair accounted for and the line read by the grammar it
claims; otherwise PARTIAL, reported as the warning
`GENERIC_STRUCTURAL_NOT_FULL` (a warning, not a failure, so an existing
project keeps working). A declined line is UNKNOWN. `processEvent` uses this
verdict for format `generic_structural`.

`parse_event` / `parse_quoted_kv` in `runtime/multipass/engine.py` have no
caller in the repository (preview API, tests, scripts), so that legacy
key=value path is not on any product path.

## CSV (W6)

RFC 4180 goldens (`csvCases`) and rows rendered from meant values
(`src/grammar/csvModel.ts`: comma, semicolon and TAB; enclosed fields, doubled
quotes, the delimiter inside a field, U+2028, UTF-8, empty fields; unterminated
quotes, a quote inside a bare field, text after a closing quote, one field
missing or extra). The browser tokenizer and the generated Ruby
(`CSV.parse_line` on Ruby 2.4.9) meet every expectation. The Python preview
reads comma rows only and detects the format by itself; it is held to "a row
offered as CSV carries exactly the meant values, a malformed row is never
offered". Defect F-12: the Python preview offered a row with a double quote
inside a bare field, which RFC 4180 forbids and the other two reject.

The product does not combine a declared forwarder with CSV, so there is no
forwarder-family variant for it.

## RFC 5424 VERSION policy (owner decision, 2026-11-13)

Only VERSION 1 is supported. A line with any other VERSION is never parsed,
labelled or shown as RFC 5424 and never FULL; the original line is kept and the
reason is reported as unsupported. The list lives in
`semantics.rfc5424SupportedVersions`; TypeScript, the Ruby export and the
Python Multi-Pass entry points all read it. Goldens cover 1, 2, 12, 999, 0, 01
and 1000; the Python engine probes five entry points per VERSION; the fault
`contract-version-2-supported` must be reported.

`fragments.rfc5424_version_head` (`<PRI>VERSION SP` followed by NILVALUE or the
start of an RFC 3339 date) is how every entry point recognizes a line that
claims to be RFC 5424. The Generic Structural extractors use it as a gate
before any other grammar: such a line used to succeed in the browser and in
Ruby as space-separated key=value with the header kept as opaque prefix tokens,
and in Python a three-digit VERSION slipped past a two-digit header expression
and came back as SOURCE_PARSED (found by the VERSION probe).

## Rules for adding or changing a grammar or a mapping

1. Change the contract and regenerate. Do not write a header pattern in a
   consumer; the ratchet fails on a new literal copy.
2. Add goldens authored from the specification or the publisher document, with
   provenance, including a negative and a boundary case.
3. Extend the model generator with the new variant and its own expectation.
4. Add one fault per new rule or semantic limit to the oracle mutants.
5. `semantic-oracle.ts ts` and `semantic-oracle.ts native` (Ruby 2.4.9) must pass.
6. Browser journey and downloaded-artifact native execution stay mandatory
   (existing Chromium and golden-vendor gates).
7. A template change needs a new owner-reviewed template hash; never edit
   `KNOWN_TEMPLATES` without that approval.

## Commands

```
node scripts/grammar/generate-grammar.mjs --write | --verify
node --test scripts/grammar/generate-grammar.test.mjs
node scripts/verification/grammar-duplication-ratchet.mjs [--write]
node backend/node_modules/tsx/dist/cli.mjs scripts/verification/semantic-oracle.ts ts
PARSER_STUDIO_EXPECT_RUBY=2.4.9 node backend/node_modules/tsx/dist/cli.mjs scripts/verification/semantic-oracle.ts native
node backend/node_modules/tsx/dist/cli.mjs scripts/verification/semantic-oracle.ts python
```

## Scope

This verifies Parser Studio output. It is not a Stellar Cyber import, Syslog
reception or indexing result.
