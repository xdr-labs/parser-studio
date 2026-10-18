# P0-STD W3C Extended Log Format: mandatory version/schema before data

## Primary published source, authority and strict scope

Official W3C Extended Log File Format Working Draft (March 1996):
https://www.w3.org/TR/WD-logfile.html

The draft is explicitly a **Working Draft** rather than a final W3C
Recommendation. Its Format/Entries clauses describe Version and Fields
as required directives that should precede all log entries. The draft
defines format version 1.0, a declared field list, whitespace-delimited
rows, quoted strings with doubled interior quotes, and LF or CRLF
physical record terminators. No later schema/version protocol is
assumed for the same undelimited file.

This is a bounded single-document **source-only** subset. A different
future Version, an unsupported producer extension, a concatenation
of log files, or a missing/truncated record terminator must not be
silently treated as a complete known v1 event.

The source-only PoC is branched exclusively from qualified cross-family
Draft PR #68 exact HEAD
90e73aca5ed417d8c13484e70b084c3f7b1d29f9.
Product HEAD da94aa9, main, historical Draft PRs, frontend 11/backend
10 existing dirty files, target native Fluentd/Stellar, DP/sensors,
credentials, production, release and deployment are **untouched**.

## Frozen independently authored grammar oracle before scoring

- Generator: scripts/poc/freezeStdW3cRequiredDeclarations.py
- Fixture: scripts/poc/standardW3cRequiredDeclarations.pinned.json
- SHA256: c51f6586c0d74c1bb3d968b5d38cc71131032d435d40eb280c15224ea5350984
- Cases: **18 authored synthetics**, six supported v1 documents and
  twelve invalid/unqualified controls. These are NOT a publisher
  device-wire sample set, native Fluentd/Stellar results or new
  manufacturer-accuracy evidence.
- Independently authored expected original wire, SHA, UTF-8 length,
  ordered field names, original raw lexical and decoded values, and
  absolute source byte start/end are frozen before parser execution.

The positive cases cover required directives in either pre-entry
order, other known writer directives before rows, LF/CRLF, tabs,
quoted doubled-quote values and multirow source accounting. The
negative cases cover missing/late/repeated Version or Fields,
unknown VERSION 2/1.1, empty/malformed/lowercase Version tokens,
and a physically unterminated last source row.

## Measured RED -> GREEN: generic source grammar fix

- RED on the existing source-stage browser log block parser:
  **9 FAILED / 10 PASSED** in the new 19-test suite. The browser
  falsely accepted source with missing/late/repeated or unknown
  versions and a missing final physical row terminator.
  No valid frozen source was rejected.
- GREEN: update the existing src/w3cTabular.ts block parser
  **in place**, not by creating vendor-specific regexes or a
  parallel data-row parser:
  * preserve independently qualified field/cell/source-span scanning;
  * require one known Version 1.0 directive before any data row;
  * require Fields before data as already documented;
  * reject repeated, misplaced or unqualified Version directives;
  * require the final physical record terminator (LF or CRLF);
  * keep permissible unrelated directives and the original input
    field names and source positions untouched.
- No W3C schema rotation is assumed across a single document.
  If a producer later supplies explicit trustworthy concatenation
  boundaries, those are separate source framing evidence requiring
  a new independent qualification, not arbitrary auto-union.

## Acceptance and remaining evidence

- All 18 frozen outcomes with exact field byte spans PASS on a
  source-only candidate; related regression 48/48 PASS.
- Full deterministic Vitest, TypeScript/Vite build, original SHA
  historical safety replay and exact-head CI must be independently
  verified before PoC closure.
- Existing 1,361 historical originals + 2,892 invalid mutations
  (197 REVIEW_ONLY) and preceding 50 independent sources are safety
  replay only, not a new producer field-F1 denominator.
- Only source syntax was audited. The W3C draft's ASCII-only
  normative data and Parser Studio's bounded UTF-8 compatibility
  handling are separate support assertions, not universal standards
  compliance. Actual IIS/CloudFront version/firmware, live relay
  origination, time origin/hostname, native target and full
  field-value/type FP/FN remain REVIEW_ONLY / UNSCORABLE.

## Reproduce in isolation

    python3 scripts/poc/freezeStdW3cRequiredDeclarations.py
    npx --no-install vitest run src/poc/standardW3cRequiredDeclarations.test.ts
    npm test
    npm run build
    npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
    git diff --check

Keep DRAFT/UNMERGED. No product deployment or Native engine changes.
