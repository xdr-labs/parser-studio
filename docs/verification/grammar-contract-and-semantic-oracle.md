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
        +--> Ruby dialect (same rule, \A...\z)               -> injected into the Ruby templates by the compiler
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
```

## Scope

This verifies Parser Studio output. It is not a Stellar Cyber import, Syslog
reception or indexing result.
