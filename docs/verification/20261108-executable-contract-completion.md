# Executable operator contract completion — 2026-11-08

This work addresses audit [#266](https://github.com/xdr-labs/parser-studio/issues/266)
and the incomplete H1/H3 implementation in [#249](https://github.com/xdr-labs/parser-studio/issues/249).
Candidate SHA, PR CI and browser acceptance receipts are recorded in those issues;
passing a local subset must not be substituted for the final candidate receipt.

## Executable scope

`contracts/execution-coverage.v1.json` names all eleven shipping extraction formats,
six normalized types, six enrichment operators, both parser-template configurations,
and the independent source/byte and native execution gates. The backend gate refuses
a newly advertised grammar without a corresponding reviewed oracle inventory.
This is the bounded ParserProject v0.1 contract, not a claim about every possible
manufacturer log, arbitrary Ruby or a Stellar Cyber target installation.

| Audit | Implementation | Independent evidence |
|---|---|---|
| A01 regex characters | Shared AST lowering uses Unicode JS matching, native ASCII whitespace, strict end semantics; nonportable boundaries, class intersections and non-ASCII byte escapes fail closed | Astral capture, NBSP, line separator, escaped backslash and rejected syntax cases |
| A02 source types | One browser-safe scalar coercion module and pinned destination-type checks; ignore sentinels apply only to original strings; compound-to-string uses JSON encoding | Arrays for IP/port/integer/boolean, null/missing/ignored inputs, shadowed toString/valueOf |
| A03 valid partial fields | Both native templates insert the same `canonical-operators.rb.tpl`, including parse/reset, normalization, enrichment rollback and error callback | Mapping and enrichment errors retain unrelated fields in both configurations; an invalid record between two replays cannot reuse previous output |
| A04 timestamps | Canonical UTC ISO milliseconds during operators; only final official timestamp wire encoding uses epoch milliseconds | Offset copy to official/vendor outputs, pre-epoch fractional precision, Gregorian calendar and UTC year limits |
| A05 split | Literal escaped delimiter, with explicit empty-part preservation | Consecutive/trailing spaces, TAB versus space and emoji delimiter |
| A06 Unicode case | Both runtimes consume the same checked-in Unicode 15.0 full per-codepoint mapping table, independent of host ICU | Greek sigma, Turkish dotted I, German sharp S and a post-version codepoint |
| A07 lookup errors | Lookup, conversion and assignment share the field-scoped failure boundary; every unrelated mapping continues | Conflicting literal/nested paths retain action/user fields and identify the failed source |
| A08 regex limits | Browser, backend and native use a 256 UTF-8-byte contract | Multibyte oversized pattern rejected before compilation |

The same browser regex extractor is used for standalone and RFC3164/RFC5424
body modes, including conventional temporal captures. Relay parsing reuses the
ordinary strict BSD decoder; relay timestamp text and UTF-8 prefix offsets are
checked on one- and two-hop inputs. Failed extraction emits no fabricated normalized
source/transport object. Project import selects the canonical project assignment,
then proves both generated files by exact regeneration; pinned operator data is
verified independently rather than mistaken for another project payload.

## Required evidence

- Frontend independent operator corpus: 60 authored fixtures, ordinary/family
  variants where applicable, with six authoring rejections and explicit expected
  normalized values and error phases. The same fixtures feed the native gate.
- `scripts/verification/operator-conformance.ts`: 104 compiled projects, 208
  expected-result replays plus an invalid intermediate event for every project.
- `scripts/verification/grammar-conformance.ts`: 24 compound/framing/relay
  projects, 48 expected-result replays and 24 deliberately invalid records.
- `backend/test/h3-independent-cross-grammar-native.test.ts`: positive and
  negative goldens over eight standard formats in both template configurations,
  with typed fields, classification, retained unrelated values and error truth.
- Existing independent Python source-byte oracle, source-boundary rejection,
  fixed-seed ordering, multilingual source preservation and official-vendor
  excerpt holdouts remain mandatory. They are source evidence; they are not
  silently relabeled as target execution evidence.
- The existing mandatory native CI step now executes both new matrix programs.
  Their sanitized count/hash receipts accompany the existing native artifact;
  no raw source or normalized customer values are uploaded.
- Same-candidate TypeScript/builds, offline backend suite without native skips,
  frontend suite, Python inventory and real Chromium authoring/download paths
  must pass before integration.

Local development Ruby is task-local 3.2.3. The dedicated isolated CI profile
remains Ruby 3.2.11/locked Fluentd; final CI is required to qualify that profile.
Public execution of arbitrary generated Ruby remains disabled.

## Completion boundaries

H1's reviewed executable v1 scope and H3's required synthetic/operator/template
coverage are implemented by this candidate. Qualification is tied to the exact
candidate receipts in #266, not to a count of unrelated green tests. New grammar,
operator or type support must extend the independent coverage inventory first.
The evidence does not prove a universal absence of future defects or a real-vendor
accuracy percentage.

H4's operator release gate remains separate from GitHub branch enforcement.
On this continuation the repository is observed public; protection GET returns
404 (unprotected) and Rulesets GET returns an empty list. The old private-plan
403 is no longer the current blocker. This work did not change visibility,
credentials, repository permissions or branch policy; enforcement still requires
the separately authorized policy change.

H5 remains NOT VERIFIED: the reference rickmodular device is offline and no
reachable designated DP 7.0 lab has been provided. No DP import/installation,
sensor receive or production operation is part of these synthetic receipts.
