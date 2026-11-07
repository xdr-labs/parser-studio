# Parser Studio Cross-Engine Conformance Gate

## Scope and evidence levels

This is an executable correctness gate for the supported synthetic source subset,
not a claim of exhaustive Fluentd or actual Stellar Cyber DP qualification.

1. **SOURCE_PARSED**: a source grammar extracted fields with original byte accounting.
2. **DRAFT_COMPILED**: schema-valid Ruby/.conf pair generated; not yet executed.
3. **NATIVE_CONFORMANT**: the exact draft parsed by a real Ruby runtime and produced
   canonical values/error stages for the explicitly tested corpus.
4. **TARGET_VERIFIED**: real Stellar Cyber DP 7.0 installed and received the
   reviewed pair. This is NOT established by the current tests.

Do not treat a browser preview, an AI recipe, a passing schema, or a DRAFT
manifest as proof of NATIVE_CONFORMANT or TARGET_VERIFIED.

## Canonical assets

- runtime/multipass/semantic-policy.v1.json is the versioned shared policy for
  reviewed protocol names, conservative L4 carriers and enforcement dispositions.
  It ships alongside the Multi-Pass Python runtime.
- contracts/conformance-cases.v1.json contains independently-authored synthetic
  protocol, KV Unicode and bounded regex cases. It is never raw customer data.
- src/conformanceCorpus20261107.test.ts validates candidate and Auto Parser
  semantics, typed source preservation and fixed-seed mutation tests.
- tests/test_semantic_conformance_corpus.py validates Python dictionary
  source accounting, vocabulary and protocol mapping against the same fixtures.
- backend/test/canonical-conformance-native.test.ts checks native generated
  parser behavior and strict KV grammar in both Ruby template families.
- scripts/verification/canonical-cross-engine.ts is the mandatory differential:
  the same raw event is reviewed by the browser, authored into the final
  project, validated by backend, compiled into Ruby, executed by Ruby, and
  compared field by field and error stage by error stage. Missing Ruby fails
  this gate rather than pretending it passed.

## Required invariants

Compare the exact input bytes, original extracted fields, supported official
destination eligibility, typed normalized values, vendor-source retention,
unmatched spans, deterministic diagnostic stage and classification when present.

Never auto-promote unsupported protocols to official transport ports.
Do not trim Unicode whitespace differently in browser and native extraction.
Keep Unicode in quoted log text when the source grammar supports it.

## Test policy and rollout boundary

The CI runs the full frontend suite, scoped product backend suite, entire
Python inventory, mandatory native-Ruby conformance, and novice Chromium E2E.
A main-branch push triggers CI again, but public preview deployment is still
separately authorized and must verify actual deployed build hashes and live UI.

Local: npm test; npm run build; npm run test:authoring --prefix backend.
Python: python3 -m unittest discover -s tests -p 'test_*.py' -q.
Native: ./backend/node_modules/.bin/tsx scripts/verification/canonical-cross-engine.ts.

The native harness requires Ruby, and fails on hosts without it. Actual
Stellar target import and the separately isolated pinned Fluentd 1.17.1 /
Ruby 3.2 native project verifier remain distinct qualification stages.

Before adding a new parser grammar, include a positive canonical fixture,
a negative/uncertain fixture, a value-aware expected output and a bounded
mutation family, instead of declaring completion from an individual UI test.
