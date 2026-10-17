# Isolated Lossless Grammar and Evidence-First Funnel PoC (2026-10-17)

## Decision and safety boundary

**Current status: an independently exercised, source-preserving parser *candidate
diagnostic*; not a qualified replacement extraction engine or a Stellar native
parser.** Retain the qualified baseline Multi-Pass/Generic Structural product
path untouched. Never equate "a grammar candidate exists" with field-accurate
parser success, semantic normalization, export qualification, or a target
runtime PASS.

- Repository: `xdr-labs/parser-studio`.
- Base commit: `6b4f125d01e8d90a9306ba64b1a2c46b1f84c863`.
- Workstream: `poc/lossless-grammar-arbiter-20261017`, separate worktree.
- No changes to existing `src/securityInputPipeline.ts`,
  `src/genericStructural.ts`, vendor recognizers, runtime adapters,
  product worktrees, DP or sensors.
- Source input never leaves the local fixture store except when the owner
  supplies it to a deliberately selected development tool. No automatic AI
  data transfer.

## Root-cause analysis and architecture

The existing engine already handles multiple security log families well, but
success from a permissive fallback does not establish exact original source
fields. Vendor grammar patches can artificially increase structural pass
counts while producing wrong fields. Current line, delimiter, quotation and
repeat-key parsing is implemented by multiple specialized consumers.

This PoC adds a **common source-only lexical observation layer**:

1. Existing Syslog envelope recognition owns a credible/strict header first.
   A syntactically invalid PRI/timestamp is **not** silently converted to a
   recognized Syslog event.
2. A bounded lexer tries space-, pipe-, semicolon-, tab- and comma-separated
   `key=value`, positional CSV/TSV, and a one-token preserved-prefix KV shape.
   It keeps exact UTF-16 offsets **and** UTF-8 byte offsets, original field
   spellings, quoted/escaped values, source raw, and repeated source fields.
3. The second pass replays span byte offsets, delimiter boundaries, quoted
   value decoding and complete field consumption directly from raw source.
   It refuses tampered candidate values, even when reported spans are plausible.
4. An evidence arbiter refuses conflicting named candidates, gives exact
   source-named fields precedence over anonymous positional columns, and
   downgrades unparsed prefixes or repeated fields to `partial_candidate`.
   Unsupported prose, malformed input and unsupported vendor grammars keep
   `raw_only` or `invalid_envelope`.
5. The qualified baseline remains the only owner of an already successful
   event. New `candidate_only` and `partial_candidate` records remain
   review suggestions, explicitly `sourceOracleVerified: false`.

The lexer's limits are 16 KiB per record, 256 fields and at most two
deterministic passes. There is no AI or recursive regex search, no arbitrary
guess at column names, and no automatic promotion into an exportable parser.
An unknown single-token prefix is retained as raw, not attributed as an
independently proven hostname/source. All repeated source key occurrences
are kept in order rather than collapsed into an overwriting dictionary.

## Pre-frozen upstream sample, split and evidence

Public upstream: `elastic/integrations` commit
`ee918d03f4a90dacd32673546c64a633308796ef`. The **13 source
fixture files**, with SHA-256/byte-size event counts, are pinned in
`scripts/poc/losslessGrammar.manifest.json`. Independent file-level
development/evaluation split is pinned in
`scripts/poc/losslessGrammar.split.json`.

- **6 vendors**: Fortinet FortiGate, Zscaler ZIA, Suricata, Cisco ASA,
  SonicWall, AWS.
- **265** input records, frozen before lexical implementation.
- Frozen logical `records.json` SHA-256:
  `70fb8f5e9e0753c763c66936880d3ca2b8e590cbadeabf0c8c7a674b7e858039`.
- Development: **124** events / **112** baseline structurally accepted.
- File-disjoint evaluation: **141** events / **117** baseline structurally
  accepted. This was selected before parser changes, but remains a public
  fixture set from known log families: it is not a statistically
  representative population of future customer logs.
- All records, per-event baseline results, source-value oracles and
  source bytes reside only in private local state
  `~/.local/state/parserstudio-lossless-fresh-20261017/` with restricted
  permissions; no raw fixture bytes are checked into Git.

## Measured outcome

| Criterion | Development (124) | File-held-out evaluation (141) | Combined |
| --- | ---: | ---: | ---: |
| Original parser structurally accepted | 112 | 117 | **229/265** |
| Original parser behavior changed | 0 | 0 | **0 regressions** |
| Accepted records with source raw preserved | 112 | 117 | **229/229** |
| Additional diagnostic review candidates | 8 | 2 | **10** |
| New automatically accepted events | 0 | 0 | **0** |
| Independent flat-KV source attribute sets matched | 61/61 | 76/76 | **137/137** |
| Additional prefixed-KV source attribute sequences matched | 8/8 | 0 | **8/8** |
| Independently compared attribute value mismatches | 0 | 0 | **0** |

The eight development-only review candidates are SonicWall records with a
leading unparsed endpoint token followed by a KV body. An **independent
Python `shlex` oracle** validates each candidate's decoded source keys,
values, ordering and repeats **8/8**, but does not certify what the prefix
means or that the event is ready for normalization; all remain **Partial**.

The two evaluation-only review candidates are Cisco ASA lines that a generic
CSV tokenizer can split into temporary columns. These **are not**
independently source-named fields; they must not count as parsed successes.
The other **26/36** originally unparsed records yield no safe full-body
candidate in this PoC. This is an accepted abstention, not an undisclosed
test failure.

**Interpretation:** These measurements demonstrate *source preservation and
diagnostic review utility* of the shared scanner, not a measured increase in
verified extraction accuracy. The per-record decision boundary, source
field values, and security-negative controls are more important than a
structural percentage.

## Fail-closed verification

- Full regression suite on the isolated candidate: **161/161 files,
  1,005/1,005 tests PASS**. TypeScript and production build are separate
  required acceptance gates, recorded alongside the commit/Issue evidence.

- `src/poc/losslessGrammar.poc.test.ts`: deterministic quote, escape,
  UTF-8 span, overlapping grammar, replay tamper, prefix preservation,
  repeat-key and malformed-envelope controls.
- `src/poc/losslessAdversarial.poc.test.ts`: 288 synthetically corrupted
  KV controls and supplementary malformed CSV, oversize, NUL, unsafe key
  and invalid timestamp guards.
- Independent Python and TypeScript tokenizers evaluate the original
  published source fields separately; their values must match. Both oracle
  counts and all sample denominators are *hard* gates; missing oracle
  files do not count as PASS.
- Preserve the earlier 571-record four-vendor strict corpus gates,
  790-record source holdout, Juniper `junos@` and bare-bracket oracles,
  Sophos independent oracle, typecheck, full Vitest suite and Vite build.

## Reproduction in the isolated PoC worktree

```sh
python3 scripts/poc/fetchLosslessGrammarCorpus.py
npx vite-node scripts/poc/createLosslessBaseline.ts
python3 scripts/poc/createLosslessIndependentOracle.py --split development
python3 scripts/poc/createLosslessIndependentOracle.py --split evaluation
npx vite-node scripts/poc/runLosslessGrammarComparison.ts
npx vite-node scripts/poc/runLosslessGrammarComparison.ts --evaluation
npx vitest run src/poc/losslessGrammar.poc.test.ts src/poc/losslessAdversarial.poc.test.ts
npx vite-node scripts/poc/runFreshVendorHoldout.ts
npx vite-node scripts/poc/runJunosBracketOracle.ts
npx vite-node scripts/poc/runJunosBareFlowOracle.ts
npx vite-node scripts/poc/runSophosKvOracle.ts
npx vite-node scripts/poc/runPublicSecurityHoldout.ts
npm test
npm run typecheck
npm run build
```

Source fetching requires explicit network access; offline runs reuse the
checksum-pinned private source files. The baseline script preserves an
already frozen snapshot and fails rather than overwriting drift. If a new
dataset, engine baseline, or parser grammar is evaluated, create a new
manifest/split rather than rewriting these frozen source records.

## Next engineering decision

Keep the new lexer and arbiter isolated until a subsequent source-certified
integration unit confirms there is no loss of original fields in the complete
Multi-Pass funnel. The next useful capabilities are a source-grammar
registry with explicit trust ownership and a reviewed mechanism to export
verified token spans into the parser intermediate representation.

Separately design a new independently sourced test set (not additional
iterations over the same public records), then certify structural
abstentions and complete **field** recall/precision denominators before
claiming a universal accuracy improvement. Cisco ASA sentence events need
real source semantics/templates rather than anonymous comma-count success.
Only after that should product UI review, parser generation, native Stellar
runtime testing and Full User E2E be attempted under their own gates.

## Continued research: explicit independent source-evidence gate

`src/poc/sourceEvidence.ts` now defines a **fixture-level, provenance-bound
source-field contract**. A source candidate can receive only the
`source_value_exact` label after all of the following:

1. The candidate passes the bounded second-pass raw-span/value replay and
   retains **source-named** fields rather than invented positional columns.
2. A reviewed independent source oracle identifies the original record's
   SHA-256, pinned 40-character upstream commit, fixture ID, original optional
   prefix, and ordered source field names/values.
3. The independently calculated source bytes hash and all field occurrences
   match exactly. Duplicate names must retain their original order; a lost
   repeated value is a mismatch.
4. The resulting certificate still sets `mappingVerified: false`,
   `nativeRuntimeVerified: false`, `productPromotionAllowed: false`, and
   `requiresHumanReview: true`.

Five deterministic tests cover source identity mismatch, altered field values,
wrong order, untrusted provenance, manipulated token replay, anonymous CSV
non-certification, and source-exact but still partial repeated/prefixed fields.

An *independent source oracle* is provenance evidence supplied by a reviewer,
not something the parser is allowed to invent or construct from its own
candidate. Even a perfect byte/value match does not establish which Stellar
normalized field should receive the value, or whether a native parser
executable will reproduce this output.

## Further unopened-file public evaluation: 222 records

After freezing and comparing the first 265-event corpus, a **different set
of nine previously unused public upstream files** was selected and frozen to
private state before its first parser evaluation. They are pinned in
`scripts/poc/losslessGrammarBlind.manifest.json`.

- Same published upstream revision:
  `ee918d03f4a90dacd32673546c64a633308796ef`.
- Logical event corpus SHA-256:
  `153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32`.
- Six families, 222 records; **217/222** baseline structurally parsed and
  **217/217** original event raws retained exactly.
- Remaining **5** Cisco ASA events stayed unparsed. The common lexer
  proposed **0** independently source-qualified additional fields on this
  dataset, and promoted **0** events.
- The independent Python source-field tokenizer found **zero** complete flat
  or prefixed KV rows that it could certify from these *original complete
  records*. This is an explicit **NOT SCORABLE** source-field oracle gate for
  this particular corpus: **do not report 0/0 as PASS**, or use 217/222 as
  a field accuracy estimate.
- This further evaluation illustrates conservative abstention and unchanged
  original parser behavior on new source files. It does not demonstrate a
  statistically unbiased future deployment success rate or improvement in
  native/Stellar mapping.

Reproduction, with all raw source bytes remaining in private state:

```sh
python3 scripts/poc/fetchLosslessBlindCorpus.py
python3 scripts/poc/createLosslessBlindOracle.py
npx vite-node scripts/poc/runLosslessBlindEvaluation.ts
npx vitest run src/poc/sourceEvidence.poc.test.ts
```

## Acceptance interpretation and roadmap

The bounded lossless scan, independent source-value replay and conservative
candidate diagnostics are implementable core components. The two source
corpora together contain 487 public example records, but only 145 original
source-field sets in the first corpus have matched independent source-value
oracles; the second corpus does not provide field-oracle evidence. Never
combine the different denominators into one all-vendor field accuracy
percentage.

Remaining work before *product-level* parser adoption:

- An independently trusted source grammar registry and explicit content
  ownership/provenance beyond developer fixture scripts.
- Verified normalization field mappings (using the actual supported Stellar
  dictionary) and collision/missing-source-field policies.
- True novel/vendor-unseen source-field precision **and recall**, including
  scored unsupported/free-text abstentions and a separately verified native
  parser path, without continuously tuning the holdout.
- Feature-gated integration into the existing bounded Multi-Pass Funnel,
  browser/Full User E2E, and native Stellar export/DP validations where
  authorized. This PoC does none of those and must not be silently merged.
