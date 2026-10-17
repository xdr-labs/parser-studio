# P0-STD-7 — Zeek directive-bound schema, #close boundary and UTF-8 source positions

## Provenance, scope and isolation

Zeek logger source defaults are pinned immutably under first standards-audit
Draft PR #56, source file ZEEK.source SHA-256:
03f1926501caf800b101665f20d5aa104a40f64932112b77de6b55e192a14625
(upstream Zeek revision 63f863c6a4d5cc95a724863ab31237c02eda0eac):
https://raw.githubusercontent.com/zeek/zeek/63f863c6a4d5cc95a724863ab31237c02eda0eac/scripts/base/frameworks/logging/main.zeek

Primary/source specification is **not** redistributed. This is a
conservative isolated source-stage interpretation of Zeek writer directives
and block/framing boundaries, not a comprehensive normative certification
of every Zeek plugin, event type, output stream or native target.

Worktree based exclusively on standards-audit Draft PR #56 exact
2335895dbf8c9f3c6f67c1ff8b468f2a8f9f20e6. No product/main,
previous Draft PRs, pre-existing dirty frontend/backend worktrees,
native Fluentd/Stellar/DP/sensor, credentials, production, deployment,
release or merge modifications.

## Pre-frozen independent source oracle

- generator: scripts/poc/freezeStdZeekRecordBoundaries.py
- expected input/answer: scripts/poc/standardZeekRecordBoundaries.pinned.json
- SHA-256: 7f4b4c4309409dc3e92bf4fb86f1b369f88f0039980db5e63b9cc1d8fb3ac561
- Four positive, ten negative separately authored *synthetic* source blocks.
  Original physical wire UTF-8 length, row count, ordered field identities,
  literal raw value lexemes, byte start/end, and close state are fixed
  **before** candidate execution.

Positive cases cover explicit #separator/#fields/#types, #open/#close,
Unicode rows and literal #unset_field/#empty_field tokens. An unclosed
but lexically valid fragment is marked closed:false rather than inventing
transport completion. Negative cases include data before #fields or #types,
data or directives after #close, #path rotation without fresh schema,
unknown directives, duplicate separator, close before data, ignored
internal blank physical records, late marker changes and late #open.

## Demonstrated RED -> GREEN shared grammar correction

- Unchanged source parser: RED 14 failed / 1 passed. Three positives
  lacked an explicit close/source-span claim and ten unsafe boundary
  variants were silently accepted; the unclosed fragment also did
  not expose closed:false.
- Existing src/zeekTabular.ts block parser is corrected in place:
  * count every physical line and original byte (LF/CRLF; mixed rejected);
  * keep declarations before physical data and reject duplicates/unknowns;
  * treat #close as a terminal boundary, never accepting rows after it;
  * refuse schema/path rotation or marker changes without block framing;
  * preserve #empty_field and #unset_field literally, never silently
    convert producer markers to inferred null/typed values;
  * add rowFieldSpans per field, with original absolute UTF-8 byte
    start/end; validate each slice against received source bytes.
- The lexical closed flag and source offsets do NOT imply native parser
  completeness, semantic event typing, manufacturer-authored truth,
  or permission to merge into product.
- Existing standalone Zeek schema and Syslog-wrapped Zeek tests remain
  unaffected. Unknown directives or multi-block source remain REVIEW
  / unsupported rather than false complete.

## Measured limits and follow-up

- Authored 14/14 normative outcome checks and all prior related 23/23
  tests pass locally.
- Full Vitest/TS/Vite/historical safety/exact-head CI must pass as
  independently observed before qualified PoC closure.
- Existing 1,361 original / 2,892 mutated-invalid (197 REVIEW_ONLY) +
  previously independent 50 source examples remain historical safety
  replay, not new vendor accuracy.
- Genuine Zeek publisher wire goldens, native engine mapping, W3C-specific
  scheme directives, multi-block rotation, and STD-8..11 remain open.

## Reproduce

    python3 scripts/poc/freezeStdZeekRecordBoundaries.py
    npx --no-install vitest run src/poc/standardZeekRecordBoundaries.test.ts
    npm test
    npm run build
    git diff --check
