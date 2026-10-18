# P0-STD-7 — Bounded Zeek declared-schema rotation and original-source field bytes

## Source authority and exact isolation

Zeek official ASCII writer/source defaults are pinned by the original
standards audit Draft PR #56 from immutable upstream commit
63f863c6a4d5cc95a724863ab31237c02eda0eac, source SHA256
03f1926501caf800b101665f20d5aa104a40f64932112b77de6b55e192a14625:
https://raw.githubusercontent.com/zeek/zeek/63f863c6a4d5cc95a724863ab31237c02eda0eac/scripts/base/frameworks/logging/main.zeek

The Zeek ASCII logging writer emits declarative #separator, #path,
#fields, #types, #open, and #close markers. This PoC accepts a *bounded*
source stream of independently closed file-format blocks with fresh
declarations after every close. It does not claim complete Zeek
writer/version coverage, an authoritative network transport protocol,
producer-native semantics, or all Zeek logs being concatenable.

The source-only branch is rooted exclusively at previously qualified
cross-family Draft PR #68 exact HEAD
90e73aca5ed417d8c13484e70b084c3f7b1d29f9.
All source Draft PRs and roadmap PR #51 remain unchanged/unmerged.
Product HEAD da94aa9, main, frontend 11 and backend 10 intentional
dirty worktrees, native Fluentd/Stellar, DP/sensors, credentials,
production, release and deployment remain untouched.

## Frozen independent synthetic source expectations

Before candidate implementation the independent author froze:
- generator: scripts/poc/freezeStdZeekRotationStream.py
- oracle: scripts/poc/standardZeekRotationStream.pinned.json
- SHA256: 6415e09bafa6ecac25889c1a882d5b6c9f9017b47f77a246039d80b4f030e7ee
- 13 authored standard-grammar examples: five valid, eight invalid;
  unrelated to real publisher-captured device traffic.

The expected original-byte SHA and wire length, ordered per-block
declared path/field names, complete physical record count, block
boundaries, row count, original lexical cell values and **absolute
original UTF-8 field byte intervals** are fixed before parser scoring.
The valid set covers single, same-schema and changed-schema blocks,
three block rotation with Unicode emoji, and two CRLF-delimited blocks.

Negative controls include unexpected rows after #close, missing
second-block #fields, schema type width drift, unknown directives,
unclean/truncated final block, extra non-block records, mixed LF/CRLF
physical lines, and a second block with zero event records. Failures
must not silently drop a physical record or attribute one block's
fields to another schema.

## RED -> GREEN and bounded source-only architectural correction

- RED on unchanged source branch: 5 failed / 9 passed. Existing
  parseZeekTsvBlock correctly handled one declared file block, but
  there was no authenticated bounded concatenated-rotation candidate.
- Introduced only an **isolated source observer**
  src/poc/standardZeekRotationSource.ts, rather than weakening the
  product security-input event breaker or duplicating the single-row
  Zeek grammar.
- The block observer counts **every received physical byte**, enforces
  a uniform LF/CRLF delimiter, a complete terminal row, a new declared
  #separator for every block, and an explicit terminal #close before
  allowing a subsequent source schema.
- Each complete block is fed unchanged to the existing, independently
  qualified parseZeekTsvBlock; field source intervals are then
  adjusted to their absolute original stream byte positions, and every
  original slice is decoded independently using strict UTF-8.
- Limits: original stream at most 1 MiB, max 32 declared blocks,
  1,000 total rows. If any block is malformed, source Unicode drift,
  an untrusted directive, ambiguous row rotation, mixed framing
  delimiter, or unconsumed bytes appear, **all output blocks abstain**.
- All emitted results explicitly state autoPromoted:false,
  nativeVerified:false and producerProfileQualified:false; even
  complete source syntax is review-only, not source-semantic or
  native-certified success.

## Acceptance and remaining work

- Frozen 13/13 narrow synthetic outcomes PASS.
- Relevant Zeek/source suites 34/34 PASS.
- Full Vitest, TypeScript/Vite, SHA-pinned 1,361 original + 2,892
  mutated-invalid (197 REVIEW_ONLY unchanged), prior independent
  50, and Exact-HEAD CI are mandatory separate gates and must be
  reported from actual results.
- Existing history must NEVER be counted as new accuracy gain.
- True Zeek publisher source-vs-relay provenance, #open/#close
  timestamps backed by actual devices, multi-file writer semantics,
  Native Fluentd/Stellar parsing and full user E2E remain NOT VERIFIED.
  Nonqualified source remains PARTIAL/REVIEW_ONLY/UNSCORABLE.

## Exact reproduction

    python3 scripts/poc/freezeStdZeekRotationStream.py
    npx --no-install vitest run src/poc/standardZeekRotationSource.test.ts
    npm test
    npm run build
    npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
    git diff --check
