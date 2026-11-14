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
| `src/syslogEnvelope.ts`, Generic Structural Ruby helper | VERSION policy from the contract; the loose envelope expressions are still hand-written |
| `src/genericStructural.ts`, the rest of the Generic Structural helper, `runtime/multipass/*.py` | hand-written, counted by the ratchet (122 copies, down from 148) |

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
- Generic envelope, browser versus Ruby: 34 of 3,897 audit lines differ - a
  host token that contains U+2028 (`\S` differs between the runtimes) and BOM
  or double-space handling in an RFC 5424 message (W4).
- The oracle covers the structured RFC 3164 / RFC 5424 path with a key=value
  body. JSON, CEF, LEEF and raw bodies, the mixed router and the Generic
  Structural extractor are not in it yet (W4, W6).
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
oracle runs them through both executors and both Ruby templates. Not migrated:
the CEF/LEEF extension tokenizers (W6) and the Python key=value passes.

## RFC 5424 VERSION policy (owner decision, 2026-11-13)

Only VERSION 1 is supported. A line with any other VERSION is never parsed,
labelled or shown as RFC 5424 and never FULL; the original line is kept and the
reason is reported as unsupported. The list lives in
`semantics.rfc5424SupportedVersions`; TypeScript, the Ruby export and the
Python Multi-Pass entry points all read it. Goldens cover 1, 2, 12, 999, 0, 01
and 1000; the Python engine probes four entry points per VERSION; the fault
`contract-version-2-supported` must be reported.

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
