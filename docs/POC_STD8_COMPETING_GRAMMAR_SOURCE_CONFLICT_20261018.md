# P0-STD-8 — Bounded Multi-Pass competing-grammar source conflict audit

## Scope and evidence

Owner-required standards-first parsing accuracy and source-fidelity audit,
Issue #1 P0-STD-8, isolated source-stage branch based exclusively on
qualified Draft PR #62 exact
bdeeba41d84b643478aa8d125464808608e76190.
That base preserves the PR #61 JSON fail-closed source-completeness
review and shared KV source-consumption grammar. Product/main/other
Draft PRs, dirty frontend/backend, native Fluentd/Stellar, DP/sensors,
credentials, release, deployment and merge are NOT modified.

There is no single official RFC that mandates an application to infer
whether a three-cell comma/tab source is anonymous CSV/TSV or named KV.
RFC 4180 covers comma-based positional rows but does not prohibit '='
as ordinary source data. A generic KV grammar can independently recognize
each source cell as key=value. If the producer has not identified its
format or fields, either interpretation is plausible and the engine
must NOT silently select source-named KV solely because it looks
semantically useful. The rule is universal, not a manufacturer regex.

Reference: https://www.rfc-editor.org/rfc/rfc4180
and previously pinned KV/source trust and bounded Funnel contracts in
Issue #1 and Draft PRs #56/#62.

## Pre-frozen independent oracle before scoring

- generator: scripts/poc/freezeStd8ConflictingSourceCandidates.py
- oracle: scripts/poc/standard8ConflictingSourceCandidates.pinned.json
- SHA256 c51b4f4f2dbcd8d2675b2ba7aaae8014467a2f54f3c310b5121d8b246eddbfa6
- 14 independently authored synthetic source bodies including:
  * three named KV vs anonymous CSV/TSV ambiguities, including Unicode,
  * a previously protected conflicting named-grammar body,
  * duplicate source names, unqualified forwarder prefix,
  * ordinary KV, ordinary unlabeled CSV and source-wrapped Syslog KV,
  * JSON and CEF format ownership, arbitrary prose, invalid outer Syslog,
    and an already-qualified baseline-preservation case.

The source raw bytes, SHA256, exactly 14 denominators, baseline-qualification
flag, known alternative candidate families and expected final
abstention/evidence disposition were frozen before candidate scoring.
These are NOT native/publisher wire goldens and do not establish complete
event or independently measured manufacturer field FP/FN.

## RED -> GREEN shared, deterministic correction

- RED on unchanged source Funnel: 3/15 tests failed when both a
  key=value candidate and an anonymous positional comma/tab candidate
  replayed the same original bytes. The old adjudicator selected
  source-named KV (candidate_only) based on naming priority alone.
- GREEN: existing bounded inspectGrammarFunnel now returns
  ambiguous with selected:null when both naming categories are qualified
  on the same original body. No union, no implicit producer schema,
  no unverified success.
- Among same-category alternatives, exact raw name and value byte
  positions are now part of the deterministic interpretation
  fingerprint. Identical names/decoded values but competing original
  source offsets cannot silently be considered the same field claim.
- Truly single-grammar KV/CSV cases remain source-only candidates;
  repeated names and forwarder prefixes remain PARTIAL, and
  known structured formats, unsupported prose or malformed Syslog
  never become alternative parse successes.
- The prior test that intentionally preferred KV over equally plausible
  anonymous CSV was updated to require explicit ambiguity instead.
  This is an intentional change to the source-evidence acceptance
  policy, not a manufacturer-specific behavior fix.

All candidate evidence still says sourceOracleVerified:false,
and a lexical candidate's original byte spans are rechecked.
No acceptance of runtime/native completeness or automatic export is
made by this PoC.

## Exit limits and verification

- Frozen 14/14 synthetic adjudication dispositions;
  33/33 related focused tests PASS.
- Full deterministic Vitest, TS/Vite, SHA-pinned historic safety and
  exact-HEAD CI are separate gates. Their measured outcomes must be
  recorded before declaring local/remote PoC completion.
- Previous 1,361 originals, 2,892 mutated invalids (197 REVIEW_ONLY),
  and earlier independent 50 source cases are safety-only, never
  relabeled newly discovered log accuracy.
- Real producer CSV/KV schema goldens, true native target, multiple
  event/relay framing, timestamp provenance, large-stream arbitration,
  and P0-STD-9..11 remain unqualified and require separate evidence.

## Reproduction

    python3 scripts/poc/freezeStd8ConflictingSourceCandidates.py
    npx --no-install vitest run src/poc/standard8ConflictingSourceCandidates.test.ts
    npm test
    npm run build
    git diff --check
