# P0-STD-5 — JSON source-loss safety before browser extraction

## Authority, risks, provenance

Scope: xdr-labs/parser-studio Issue #1 P0-STD-5. Isolated PoC branch based
exclusively on existing initial standards audit Draft PR #56 exact HEAD
2335895dbf8c9f3c6f67c1ff8b468f2a8f9f20e6. Other PRs/product/main,
dirty worktrees and live native/DP/sensor/deployment are untouched.

- RFC 8259 section 4: JSON object member names **SHOULD be unique**.
  Duplicate semantics are not interoperable; this gate marks them REVIEW
  rather than incorrectly calling them syntactically invalid JSON.
- RFC 8259 section 6: numbers can exceed IEEE-754 binary64 range or
  precision. Lexically valid but not faithfully representable JSON values
  require a review disposition, not a lossy JavaScript Number success.
- RFC 8259 section 8.2: JSON grammar can express unpaired Unicode
  surrogates, with unpredictable behavior across implementations.
  The conservative source contract marks them for REVIEW, rather than
  silently replacing raw lexical bytes or declaring decoded completeness.
- RFC 7464: JSON Text Sequences require per-record JSON inspection
  in addition to record framing; valid framing does not imply lossless
  JSON field extraction.

Primary RFCs:
https://www.rfc-editor.org/rfc/rfc8259
https://www.rfc-editor.org/rfc/rfc7464

Only public references are retained. Full standard/customer text is not
copied into this repository.

## Independent source-case oracle (frozen before execution)

Generator: scripts/poc/freezeStdJsonSourceSafety.py
Fixture: scripts/poc/standardJsonSourceSafety.pinned.json
SHA-256: e30314ba68ec1165e79eff85f05a1cfa96abeb5ba0a614816e1d405d64e1054c

14 authored **synthetic standards-derived** examples, with original raw
UTF-8 length + SHA and independently specified disposition/issue:
- Four lexically eligible: ordinary UTF-8 nested JSON, valid escaped
  Unicode surrogate pair, repeated names only across different object
  scopes, and object array/value types.
- Seven REVIEW_ONLY_UNCERTAIN: same-scope duplicate keys (including a
  Unicode-escaped alias), exponent overflow, unsafe integer, excessive
  decimal precision, lone high/low Unicode surrogate.
- Three malformed ABSTAIN_UNSAFE controls: trailing garbage, invalid
  backslash escape and truncated object.
These are not independent manufacturer wire goldens, complete-event
FP/FN evidence or native Stellar output proof.

## RED -> GREEN isolated common repair

- RED unchanged browser: 7 failures in the new frozen suite, as browser
  JSON.parse accepted each uncertain input as complete after value loss
  or non-interoperable interpretation.
- Existing src/poc/standardSourceCompletenessGate.ts source checker was
  **moved**, not rewritten, to src/standardSourceCompletenessGate.ts;
  the prior PoC import is preserved through a re-export shim.
- New small adapter src/jsonSourcePreflight.ts maps the already-reviewed
  source disposition into common structured user-visible errors.
- Authoring extraction, RFC5424 JSON bodies, JSON arrays/Records batches,
  RFC7464 JSON text sequences, NDJSON records, and bounded generic
  embedded/prefixed JSON use this same scanner before JSON.parse.
- Individual records retain original raw bytes until lexical qualification.
  A preflight GREEN is **lexical eligibility only** and does NOT establish
  complete original source-field offsets, product/native compatibility,
  or vendor field semantics.
- Source gate remains bounded (default 64KiB, explicit per-surface up
  to 1MiB) with maximum object nesting and element count. Unknown or
  oversized inputs review/abstain; no silent auto promotion.

### Historical holdout change, explicitly not new extraction F1

A prior F5/Zscaler/Cisco nine-example browser coverage test assumed
9/9 parsing success. After fail-closed JSON lexical eligibility, the
six F5/Zscaler sources still parse; the three Cisco AMP cases now
abstain because their event identifiers were embedded as already-rounded
JavaScript Number values above MAX_SAFE_INTEGER. Their original integer
lexemes cannot be recovered from those pre-serialized fixtures, so
source correctness is UNSCORABLE without publisher-authored raw bytes.
The same nine-item denominator is retained (6 accepted / 3 review).
This is an intentional false-complete correction and must not be
advertised as improving manufacturer accuracy or lost extraction recall
with an independent native golden. Previously expected assertions that
malformed JSON or unsafe integer was silently accepted were changed
to require fail-closed behavior; generic malformed JSON preview errors
keep the original 'Invalid JSON object' text.

## Reproduction, controls, limitations

    python3 scripts/poc/freezeStdJsonSourceSafety.py
    npx --no-install vitest run src/poc/standardJsonSourceSafetyParity.test.ts
    npm test
    npm run build
    git diff --check

Full deterministic tests, historical replay, and GitHub exact-head CI
must be recorded from actual outcomes. The 1,361 original records,
2,892 mutation-invalid records (197 REVIEW_ONLY historical) and 50
previous independent source samples remain **regression safety only**.

Remaining: JSON source-native/JSON map offsets for real publisher events,
non-JSON KV/W3C/Zeek, CSV source whitespace and inter-dialect contracts,
bounded multi-pass conflicts, real source/relay goldens and STD-8..11.
Product/main/native/DP/sensor/merge/deployment remain prohibited.
