# Structural Hypothesis Engine — Security-Product PoC v3 (2026-10-15)

## Decision status

**PROMISING / LIMITED. Continue PoC; do not integrate into the product engine yet.**

This PoC evaluates whether batch-level structural learning can recover source
values that the current single-event Multi-Pass engine deliberately leaves
incomplete. The learner uses source syntax only. Product/vendor identity is
never an admission feature and semantic/Stellar Dictionary mapping is out of
scope.

Three independent hypothesis families now show measurable value:

1. cross-event delimiter/key-anchor grammar induction;
2. numeric event-code literal-anchor / variable-slot templates;
3. relative R-gram residual signatures for repeated security-message bodies.

All accepted candidates are additive. An already `SOURCE_PARSED` event is
never reinterpreted. A learned candidate can complete an event only through a
residual-only merge that preserves every baseline field/span and adds new,
non-empty exact source spans wholly inside baseline residual regions.

## Scope

Only security-product telemetry is in scope. General application/OS prose logs
are excluded.

The current corpus covers **21 security-product families** and **15 security
categories**, including:

- AWS WAF
- Suricata IDS/IPS / network detection
- Zeek NDR/network telemetry
- Darktrace NDR
- ExtraHop NDR
- Trellix EDR and ePO
- Trend Vision One EDR/XDR
- CrowdStrike EDR
- SentinelOne EDR
- FortiGate NGFW
- PAN-OS NGFW
- Check Point NGFW
- Cisco ASA/VPN
- Cisco Secure Email Gateway
- Zscaler ZIA SWG/cloud firewall
- F5 BIG-IP WAF/NGFW
- Cisco ISE NAC / identity security
- Juniper SRX NGFW/IDS/IPS
- Sophos UTM
- Sophos XG NGFW/UTM

Public fixtures are pinned to their source revision; raw fixtures stay in
ignored local research cache. The tracked evidence contains only digests,
structural metadata and value-free metrics.

## Baseline

Product source-engine candidate:

`4596f4629a4cb7b900eb459cadffb0d2813c7957`

PoC branch/worktree:

- branch: `poc/structural-hypothesis-engine-20261015`
- worktree: `/home/aella/parser-studio-structural-hypothesis-poc-20261015`

The current product worktree and unrelated E2E worktrees are not modified.

## Primitive A — cross-event delimiter/key-anchor grammar

The learner finds quote-aware comma/semicolon `key=value` anchors across a
sample stream and keeps only structurally stable evidence:

- repeated anchors;
- compatible anchor order;
- optional first key behind a variable-width prefix;
- minimum prefix-position evidence;
- learned terminal-anchor evidence.

Values extend to the next learned structural key anchor rather than to the next
delimiter. This recovers values containing unquoted delimiter characters while
remaining bounded.

Current single-split gain: **5 Cisco ISE promotions**.

## Primitive B — positional CSV corpus confirmation

This experiment confirms an already-extracted unlabeled positional CSV only
when multiple samples prove stable width. It never invents column meaning and
never changes values/spans.

Admission requires:

- zero source residual;
- only `UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION`;
- at least three eligible training records;
- one width with at least 80% support;
- exact holdout width match.

Current extraction gain: **0**. This is retained as a negative result; the
thresholds are not relaxed merely to increase COMPLETE rate.

## Primitive C — event-code literal-anchor templates

For security records with a generic numeric event-code shape, training records
are grouped by numeric message ID. Deterministic sequence alignment/LCS derives
stable literal anchors and variable gaps.

Admission requires:

- at least two same-code training examples;
- at least six stable literal anchors;
- sufficient anchor coverage;
- stable terminal-position evidence;
- every training example self-parses;
- truncation/deletion/NUL training mutations fail closed.

Current single-split gain: **2 Cisco ASA/VPN promotions**.

## Primitive D — relative R-gram residual signatures

The R-gram layer addresses a different class: a known/partially known envelope
followed by a repeated security-product message body.

It observes only one bounded baseline residual region. Dynamic lexical classes
such as numbers, IP addresses, URLs, email addresses, long hashes and quoted
values become `<VAR>`; literal words/punctuation remain relative anchors.
Exact token sequences are grouped across training samples.

A hypothesis is admitted only when:

- the same residual signature appears at least three times;
- at least five literal anchor tokens remain;
- at least one variable slot exists;
- variable slot count is bounded;
- the baseline has no malformed/resource-limit hard issue;
- the residual/token count stays inside explicit size limits.

At holdout time the exact learned signature must match. The candidate emits
only variable source slots with exact UTF-8 spans; no semantic names are
invented.

Cisco Secure Email provides a concrete independent structural class. Its
single-event parser correctly kept repeated text-mail body formats PARTIAL.
Cross-event R-gram learning recovered those repeated variable slots without a
vendor-name admission rule.

Current single-split gain: **10 Cisco Secure Email promotions**.

## Residual-only no-loss merge

The acceptance boundary is stricter than candidate self-parsing:

`baseline fields/spans + learned values wholly inside baseline residual only`

A candidate is rejected if:

- the baseline is already complete;
- raw input differs;
- any baseline source span disappears;
- no new non-empty candidate value lies wholly inside baseline residual;
- the baseline reports malformed/resource-limit evidence such as unclosed,
  truncated, invalid, NUL/size, byte-limit, field-limit or depth-limit.

This prevents a learned grammar from obtaining a better status by re-segmenting
or replacing source claims that the current parser already made.

## Security-only single-split result

Current tracked benchmark:

- source files: **81**
- security-product families: **21**
- security categories: **15**
- evaluation events: **417**
- disjoint train/holdout evaluation events: **364**
- tiny-file no-regression control events: **53**
- baseline `SOURCE_PARSED`: **298**
- baseline incomplete: **119**

Accepted new completions:

- total: **17 / 119 = 14.3% of baseline-incomplete evaluation events**
- delimiter/key-anchor: **5**
- event-code template: **2**
- relative R-gram: **10**

Promotion families:

- Cisco ISE: **5**
- Cisco ASA/VPN: **2**
- Cisco Secure Email: **10**

Extraction evidence:

- additional source-value spans: **78**
- residual bytes removed: **2,308**
- promotions preserving every baseline span: **17 / 17**
- baseline span loss: **0**
- raw mismatch: **0**

Adversarial safety:

- mutation attempts: **85**
- mutation families include truncation, prefix loss, NUL corruption and
  grammar-specific required-anchor deletion
- false-complete: **0**

AWS WAF, Suricata, Zeek, Darktrace, ExtraHop, EDR/XDR, firewall, SWG and other
already-complete records remain no-regression/abstention controls. No promotion
is counted merely because an issue/status can be cleared without recovering
new source values.

Machine-readable evidence:

- `structural-hypothesis-security-poc-summary.json`

## Three-split repeatability

Three deterministic train/holdout splits were run over the same pinned
security-only corpus.

Aggregate:

- evaluation cases: **1,251**
- baseline incomplete cases: **356**
- accepted promotions: **52**
  - delimiter/key-anchor: **15**
  - event-code template: **5**
  - relative R-gram: **32**
- accepted promotions preserving every baseline span: **52 / 52**
- baseline span loss: **0**
- raw mismatch: **0**
- additional source-value spans across splits: **244**
- residual bytes removed across splits: **7,298**
- mutation attempts: **260**
- mutation false-complete: **0**

Aggregate promotion families:

- Cisco ISE: **15**
- Cisco ASA/VPN: **5**
- Cisco Secure Email: **32**

Per split:

- split A: **20** promotions, mutation false-complete **0**
- split B: **18** promotions, mutation false-complete **0**
- split C: **14** promotions, mutation false-complete **0**

Machine-readable evidence:

- `structural-hypothesis-security-multisplit-summary.json`

## Tests and regression

Focused Structural Hypothesis suite after Primitive D: **17 / 17 PASS**.

The fresh PoC worktree lacks several historical ignored commercial/CEF cache
files and the optional Drain3 cache. Those cache-dependent tests fail on missing
inputs rather than parser assertions. The latest cache-independent regression
excludes exactly those nine known cache-dependent cases and completed:

- tests run: **414**
- PASS: **407**
- optional skips: **7**
- failures: **0**
- errors: **0**

This is the reproducible code-regression gate for the isolated PoC worktree.

## Interpretation

The result is stronger than v2 because gain now spans **three structurally
different security-product classes**:

1. delimiter/KV records with variable-value boundaries;
2. event-code messages with repeated positional slots;
3. repeated security message bodies identified by relative lexical anchors.

The architecture that is now supported by evidence is:

`qualified single-event parser
 -> cross-event hypothesis learning on incomplete samples
 -> exact candidate match
 -> residual-only no-loss merge
 -> grammar-specific adversarial qualification`

This is a useful direction for Auto Parser because it learns from the user's
sample batch without requiring the user to know the vendor log grammar.

It still does **not** qualify for product integration. The 17 promoted
single-split events and 52 repeated-split promotions do not yet have a fully
independent vendor-native field/span oracle. They prove additive structural
recovery and safety against the current baseline, not semantic correctness or
native parser compatibility.

## Next PoC gates

Continue without weakening admission rules:

1. build independent source-value/span gold for learned promotions, starting
   with Cisco Secure Email and Cisco ASA;
2. add relative-anchor hypotheses to additional non-JSON IDS/IPS, EDR and NDR
   long-tail security logs;
3. test counterexample-guided specialization when a learned signature accepts a
   structurally similar negative;
4. expand grammar-derived mutations beyond deletion/truncation to reordering,
   duplicate anchors, embedded delimiters and quote corruption;
5. compare a bounded hypothesis ensemble against the frozen product baseline on
   a larger fresh security-only holdout;
6. integrate into the product only if exact source TP/FP/FN and false-complete
   gates remain at least as strong as the current qualified engine.

No product integration, PR merge, release, production, DP/sensor, auth,
credential or target-loader action is authorized by this PoC.
