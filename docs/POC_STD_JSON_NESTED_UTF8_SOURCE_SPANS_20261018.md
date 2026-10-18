# P0-STD — JSON nested field original-byte accuracy, RFC8259 and RFC6901

## Standards source, source-only objective

Primary independent standards:
- RFC 8259, JSON grammar, duplicate member names, string Unicode
  escaping and number-range interoperability:
  https://www.rfc-editor.org/rfc/rfc8259
- RFC 6901, JSON Pointer reference tokens, including escaping tilde
  as ~0 and solidus as ~1, and zero-based array indices:
  https://www.rfc-editor.org/rfc/rfc6901

Goal: preserve exact source name/value lexical bytes, hierarchical
member identity, array element identity and UTF-8 byte start/end for
already-lexically-eligible JSON, without materializing an unsafe
JavaScript Number or silently overwriting duplicate source keys.
A source byte/JSON Pointer claim is NOT a validated producer-native
typed field or a Stellar Dictionary normalization.

This is an isolated source-stage worktree rooted exclusively in
the new cross-family Draft PR #75 exact HEAD
67e267625b2b73f19a960c08afd5d02033fed406.
No product/main, other Draft PRs, intentional frontend 11/backend 10
dirty worktrees, Native Stellar/Fluentd target, DP, sensors, credentials,
production, release, deployment or merge changes are authorized.

## Frozen independent source answers before executing candidate

- Generator: scripts/poc/freezeStdJsonNestedOriginalSpans.py
- Original/source exact answer:
  scripts/poc/standardJsonNestedOriginalSpans.pinned.json
- SHA-256: 03c6e1ae49a5cfb2c2c034d4ae584e777115acecdb08d006928286ff1db614e0
- Eighteen authored standards-derived **synthetic** records:
  nine eligible and nine ambiguous/malformed/bounded negative controls.
- On the nine eligible records, thirty-two original ordered
  field/container/array-element assertions are pre-authored with
  RFC6901 pointer, original lexical member-name token, original raw
  value token, and exact original UTF-8 byte start/end. Null member
  name/source offsets distinguish array elements from object members.

Positive controls include nested objects and arrays, scoped duplicate
names in distinct objects, original UTF-8 non-ASCII/emoji bytes,
escaped JSON member names including Unicode alias, RFC6901 slash/tilde
token escaping, original escaped surrogate pairs, empty containers,
boolean/null/decimal values, and root array/string. Negative controls
include duplicate names (including escaped equivalence), unsafe
numeric range/precision, unpaired surrogates, invalid escapes,
trailing garbage, truncated nesting and over-depth resource denial.

This fixture's expected source bytes and pointers are derived only
from independently authored literal inputs and pre-declared expected
names and lexemes, never from Parser Studio parser outputs. They are
NOT publisher-device wire captures, Native Stellar goldens or new
manufacturer accuracy.

## RED -> GREEN general grammar implementation

- RED on unchanged post-audit source branch: eighteen source-span
  contract assertions failed because the existing reviewed JSON
  scanner returned no nested original-byte field claims.
  It already correctly classified unsafe source inputs.
- GREEN extends the **existing** bounded JsonBoundedAudit scanner in
  src/standardSourceCompletenessGate.ts in place. No second JSON lexer,
  vendor-specific regex or JavaScript-value reserialization.
- The scanner carries parent JSON Pointer identity through recursive
  arrays/objects and records raw quoted member/source value interval
  boundaries. A bounded O(source length) UTF-16-index to UTF-8-byte
  lookup table maps original character positions to original byte
  positions without repeatedly copying prefixes or confusing UTF-8
  multibyte/surrogate-pair characters.
- Every raw field slice is verified against original received UTF-8
  bytes using strict TextDecoder. Escaped member identities use
  RFC6901 ~0/~1 escaping; array items have positional indices and
  no fabricated original key token.
- On lexical errors, duplicate/equivalent member names, unsafe
  integer/decimal/exponent, malformed Unicode or resource bounds,
  **zero** jsonRawSpans are emitted. No partially parsed fields
  leak into a successful source map.
- The shared scan retains its existing REVIEW_ONLY_LEXICAL /
  REVIEW_ONLY_UNCERTAIN / ABSTAIN_UNSAFE states and explicitly retains
  sourceFieldValuesDecoded:false, completeSourceClaim:false,
  nativeStellar:NOT_VERIFIED, autoPromoted:false.
- Existing browser JSON field extraction, JSON text sequences, NDJSON,
  JSON batch, generic source routing and producer-specific semantic
  interpretation are not upgraded, rewritten or auto-promoted.

## Test boundaries and remaining work

- Frozen eighteen narrow synthetic disposition/UTF-8 source outcomes
  and thirty-two original field value/name source intervals PASS.
- Related focused scanner/safety suites 47/47 PASS.
- Full deterministic Vitest, TS/Vite build, historical SHA-pinned
  safety replay and exact-HEAD CI are mandatory separate gates.
- Existing 1,361 originals plus 2,892 mutation invalids
  (197 REVIEW_ONLY) and prior independent 50 source cases remain
  historical safety ONLY. Any newly authored synthetic tests are
  NOT added to native/manufacturer extraction accuracy.
- Remaining: producer-authoritative complete JSON nested field values
  and types, independent device-wire truth, schema/semantic profiles,
  multiple relay transport captures and original source-vs-native
  event comparison before any source-complete/native certification.

## Reproduction

    python3 scripts/poc/freezeStdJsonNestedOriginalSpans.py
    npx --no-install vitest run src/poc/standardJsonNestedOriginalSpans.test.ts
    npm test
    npm run build
    npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
    git diff --check

All changes remain in the isolated source PoC. No product deployment
or merge is authorized.
