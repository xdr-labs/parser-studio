# P0-STD-7 — KV source complete-consumption and producer-unknown escaping

## Scope and authority

There is no universal RFC that defines one generic vendor-independent
security key=value escape or empty-value semantics. This PoC does NOT
misrepresent ad hoc producer backslash behavior as RFC conformance.
Instead, full original source-byte consumption, bounded lexing, field
identity and precise UTF-8 locations are universal prerequisite safety
contracts. Escape decoding / optional empty semantics require a separate
qualified producing system/source profile before certification.

This isolated source/browser PoC stacks ONLY on Draft PR #61 exact
6d9eae9f9ba43abea3bb9954bd3cb79338fa158f, which contains the
already-reviewed shared source-completeness scanner from P0-STD-5.
No product/main, previous Draft PR, dirty frontend/backend, native/DP,
sensors, credentials, production, deployment or merge modifications.

## Frozen independent lexical oracle BEFORE candidate scoring

- scripts/poc/freezeStdKvSourceCompleteness.py
- scripts/poc/standardKvSourceCompleteness.pinned.json
- SHA-256 831e755960e47b5b98844080c80f2a76966e9e51e6b291813d2ac18c86cf8127
- 14 independently authored synthetic lexical controls: five complete
  unambiguous source candidates, nine explicit REVIEW_ONLY_UNCERTAIN
  source texts, including trailing/middle raw, duplicate keys, unknown
  backslash/escaped quotes/equals, incomplete assignments and quotes.

The positive answers pre-register the complete original name, raw
value lexeme, expected decoded value and absolute UTF-8 name/value
intervals independently from the candidate implementation. All cases
are synthetic: NOT real publisher goldens, native evidence, or a
universal claim about escaping.

## Demonstrated RED -> GREEN

- Unchanged baseline: 9 FAILED / 6 PASSED narrow outcomes; browser
  best-effort regex accepted several partial source matches/unknown
  producer escapes, and duplicate-key failure leaked partial fields.
- Existing standardSourceCompletenessGate.ts (introduced in PR #61) is
  reused directly, with no new vendor or ad hoc escape lexer.
- Browser parser.extractKV now delegates to reviewed strictKeyValues
  instead of a second regex parser that matched only selected tokens.
- Generic strictKeyValues inspects the full source and declines to
  decode unknown escapes or silently claim fields from raw leftovers;
  malformed and ambiguous cases retain an error and zero output
  fields. Known explicitly configured allowEmptyUnquoted handling
  remains an option, but does not bypass other source issues.
- RFC5424 nested generic KV uses the same scanner and never applies
  Syslog/CEF/LEEF escape rules as generic vendor KV rules.

This is a source-lexical safety preflight only, not a validation of
manufacturer-provided escape semantics or a native Fluentd/Stellar
parser. The existing source inspector always keeps
completeSourceClaim:false and nativeStellar:NOT_VERIFIED.
Uncertain records remain REVIEW_ONLY, not false-complete.

## Tests, regression boundaries and remaining work

- Independent 14/14 synthetic outcomes; related focused 49/49 PASS.
- Full deterministic, TS/Vite, SHA-pinned historical safety replay
  and exact-head CI are separate mandatory gates.
- Historical 1,361 original / 2,892 invalid mutations (197
  REVIEW_ONLY) and previously independent 50 source examples are
  **regression-only**, not new source accuracy.
- Producer-specific verified log definitions, independent original
  escape/empty-value oracle, W3C/Zeek declaration and duplicate
  handling, source-vs-relay/native proof, and STD-8..11 remain open.

## Reproduction

    python3 scripts/poc/freezeStdKvSourceCompleteness.py
    npx --no-install vitest run src/poc/standardKvSourceCompletenessParity.test.ts
    npm test
    npm run build
    git diff --check
