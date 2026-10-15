# Structural Hypothesis Engine — Security-Product PoC v3 (2026-10-15)

## Decision status

**PROMISING / LIMITED. Continue PoC; do not integrate into the product engine yet.**

This PoC evaluates whether batch-level structural learning can recover source
values that the current single-event Multi-Pass engine deliberately leaves
incomplete. The learner uses source syntax only. Product/vendor identity is
never an admission feature and semantic/Stellar Dictionary mapping is out of
scope.

Three hypothesis families were implemented and challenged under the same
strict residual-only acceptance boundary:

1. cross-event delimiter/key-anchor grammar induction;
2. numeric event-code literal-anchor / variable-slot templates;
3. relative R-gram residual signatures for repeated security-message bodies.

Only the relative R-gram family currently survives the final no-loss gate with
independently validated new source values. Earlier delimiter/template promotions
were rejected after hardening because candidate values re-segmented already
claimed baseline source regions.

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

Final strict single-split gain: **0 accepted promotions**. Earlier apparent Cisco ISE gains were rejected because the learned candidate re-segmented baseline claims rather than adding only residual values.

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

Final strict single-split gain: **0 accepted promotions**. Two earlier ASA/VPN candidates were rejected by the strengthened exact-baseline-or-residual representation rule.

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

Final strict single-split gain: **6 Cisco Secure Email promotions**.

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

Final accepted new completions:

- total: **6 / 119 = 5.0% of baseline-incomplete evaluation events**
- delimiter/key-anchor: **0**
- event-code template: **0**
- relative R-gram: **6**
- promotion family: **Cisco Secure Email only**

Extraction evidence:

- additional source-value spans: **12**
- residual bytes removed: **492**
- promotions preserving every baseline span: **6 / 6**
- baseline span loss: **0**
- raw mismatch: **0**

Adversarial safety:

- mutation attempts: **30**
- mutation families: truncation, prefix loss, NUL corruption and required-literal deletion
- false-complete: **0**

Independent source-value validation of the 12 new spans:

- **6 / 12** exactly equal Elastic's pinned official expected value for
  `email.message_id`;
- **6 / 12** are the URL reputation-score slot independently documented by
  Cisco for the exact mail-log shape;
- unvalidated added spans: **0**.

The learner did not receive Elastic expected values, Cisco field semantics or
vendor/product identity. The references are evaluation-only.

AWS WAF, Suricata, Zeek, Darktrace, ExtraHop, EDR/XDR, firewall, SWG and other
security records remain no-regression/abstention controls. No promotion is
counted merely because an issue/status can be cleared without recovering new
source values.

Machine-readable evidence:

- `structural-hypothesis-security-poc-summary.json`
- `structural-hypothesis-cisco-reference-summary.json`

## Three-split repeatability

Three deterministic train/holdout splits were run over the same pinned
security-only corpus.

Aggregate:

- evaluation cases: **1,251**
- baseline incomplete cases: **356**
- accepted promotions: **21 / 356 = 5.9%**
- accepted primitive: **relative R-gram only**
- promotion family: **Cisco Secure Email only**
- accepted promotions preserving every baseline span: **21 / 21**
- baseline span loss: **0**
- raw mismatch: **0**
- additional source-value spans across splits: **44**
- residual bytes removed across splits: **1,752**
- mutation attempts: **105**
- mutation false-complete: **0**

Per split:

- split A: **7** promotions, **15** new spans, **589** residual bytes removed
- split B: **7** promotions, **15** new spans, **589** residual bytes removed
- split C: **7** promotions, **14** new spans, **574** residual bytes removed

Independent reference validation across all three splits:

- promotion occurrences: **21**
- unique promoted events: **14**
- added spans: **44**
- Elastic official expected exact matches: **21**
- Cisco-documented reputation-score values: **21**
- Cisco-documented URL values not emitted by the Elastic expected output: **2**
- independently validated added spans: **44 / 44**
- unvalidated added spans: **0**

Machine-readable evidence:

- `structural-hypothesis-security-multisplit-summary.json`
- `structural-hypothesis-cisco-reference-multisplit-summary.json`

## Primitive E — aligned residual partial augmentation

The strict completion gate is intentionally not the only useful outcome. Some
security logs contain a stable, independently verifiable value inside a residual
while surrounding free text remains unknown. Requiring full-record grammar
proof would leave that value unextracted.

The aligned residual learner therefore operates in a second, lower-authority
mode:

`incomplete event batch
 -> group the same residual ordinal/count
 -> learn an LCS of exact relative anchors
 -> identify a source-type slot that is stable across train samples
 -> require every learned anchor on holdout
 -> add only the independently shaped source atom
 -> preserve PARTIAL status`

It never clears issues and never turns an incomplete event into
`SOURCE_PARSED`. Existing source spans are immutable.

The first independently validated target is Snort IDS/IPS fast-log input. The
generic tokenizer was also corrected so a punctuated numeric source token such
as a date/time is represented as one value rather than several two-digit
fragments. No Snort/vendor identifier is an admission feature.

Three deterministic train/holdout splits over the pinned Snort fast fixture:

- holdout event occurrences: **12**;
- baseline PARTIAL: **12 / 12**;
- augmented event occurrences: **11**;
- unique augmented events: **8**;
- added source spans: **11**;
- added spans exactly consistent with Elastic's pinned official
  `SNORT_DATE` / expected `@timestamp`: **11 / 11**;
- status unchanged: **12 / 12**;
- baseline span loss: **0**;
- learned-anchor deletion counterexamples: **11**;
- false additions after anchor deletion: **0**.

The official evaluation-only reference is the pinned Elastic grammar
`SNORT_DATE=%{MONTHNUM}/%{MONTHDAY}(/%{YEAR})?-%{TIME}`.
The learner never receives the expected timestamps or this grammar.

A second independently validated aligned-atom family is WatchGuard Firebox
NGFW. The same generic tokenizer now keeps a complete ISO8601-style source
timestamp as one dynamic token rather than splitting its date/time components.
No WatchGuard/vendor identifier participates in learning.

Three deterministic splits across pinned WatchGuard alarm, diagnostic and event
fixtures:

- holdout event occurrences: **435**;
- baseline incomplete: **396**;
- augmented event occurrences: **382**;
- added source spans: **382**;
- added spans independently consistent with the pinned official
  `watchguard_firebox.log.timestamp`: **382 / 382**;
- status unchanged: **435 / 435**;
- baseline span loss: **0**;
- learned-anchor deletion counterexamples: **382**;
- false additions after anchor deletion: **0**.

The broader abstention/regression pass, rerun after this extension, now covers
**98 source files / 25 security families / 688 holdout events**:

- baseline complete: **411**;
- baseline incomplete: **277**;
- augmented events: **123**;
- added spans: **123**;
- augmented families: **Snort and WatchGuard only**;
- baseline span loss: **0**;
- status changes: **0**.

All other WAF, Suricata, EDR/XDR, NDR, NGFW, VPN, NAC, SWG and email-security
families abstained in the aligned-atom layer. Cisco Secure Email remains covered
separately by the strict complete-residual R-gram path.

Machine-readable evidence:

- `structural-hypothesis-snort-aligned-summary.json`
- `structural-hypothesis-watchguard-aligned-summary.json`
- `structural-hypothesis-aligned-security-summary.json`

## Tests and regression

Focused Structural Hypothesis suite after the aligned-residual extension:
**23 / 23 PASS**.

A fresh full discovery attempted **429 tests**. Exactly eight tests require
historical ignored security/commercial holdout evidence or the optional Drain3
research dependency unavailable in this isolated worktree; those eight error on
missing external inputs rather than parser assertions.

The cache-independent regression then excluded exactly those eight identified
external-evidence tests and completed:

- tests executed: **421**
- optional skips: **28**
- failures: **0**
- errors: **0**

This is the reproducible code-regression gate for the isolated
security-expansion PoC worktree.

## Rejected follow-up — masked residual R-gram

A follow-up experiment masked all baseline value spans and learned only the
remaining residual token pattern. On Cisco ISE `CISE_Alarm`, it appeared to
promote three holdout events while preserving every baseline span. Independent
comparison against Elastic's pinned official expected output rejected the
result:

- candidate promotions: **3**;
- added spans: **12**;
- every added span length: **2 bytes**;
- added spans exactly matching an independent expected field value: **0 / 12**;
- all matches were only incidental substrings of larger expected values.

Verdict: **REJECTED_FALSE_STRUCTURAL_SEGMENTATION**. The exploratory code was
removed and none of these candidates are counted in the PoC gain. This is a
useful counterexample: baseline-span preservation alone is not sufficient;
newly recovered values also need independent correctness evidence.

Machine-readable negative evidence:

- `structural-hypothesis-masked-rgram-negative.json`

## Interpretation

The strict result is narrower than the earlier exploratory result but much
stronger evidentially.

The valid improvement now has two bounded modes:

1. **complete-residual R-gram recovery** — when the entire remaining residual
   grammar is repeated and independently qualified, emit the variable slots and
   allow the normal residual-only no-loss merge to complete the event;
2. **aligned residual atom augmentation** — when only one stable typed source
   position is proven, add that exact source span but deliberately keep the
   event PARTIAL.

The resulting candidate architecture is:

`qualified single-event parser
 -> batch-learned residual hypotheses
 -> [complete residual R-gram] exact signature + no-loss completion
 -> [partial aligned atoms] exact anchors + typed source span, status unchanged
 -> grammar-specific counterexamples / independent reference validation`

The first mode recovered Cisco Secure Email values across three deterministic
splits with every added span independently validated. The second mode recovered
both Snort IDS/IPS timestamp source spans and WatchGuard Firebox NGFW ISO
timestamp source spans across three splits, again with every added span
independently validated, while leaving all affected events PARTIAL.

The delimiter/key-anchor, event-code template and masked-residual experiments
remain useful research negatives. They proposed plausible structure but failed
the strict no-loss or independent-value correctness gates and are not counted as
improvement.

This PoC therefore supports **adding a low-authority batch-learned residual
layer after the current Multi-Pass/Generic Structural engine**, not replacing
it. It now has independently verified gain in three security-product families
spanning email security, IDS/IPS and NGFW, while the broader WAF/EDR/NDR/NAC/SWG
corpus demonstrates conservative abstention and zero baseline-span loss. This is
still PoC evidence rather than product integration approval.

## Next PoC gates

Continue without weakening admission rules:

1. freeze this three-family security-expansion evidence and keep all
   pre-hardening 17/52 promotion counts superseded;
2. acquire a genuinely fresh unseen security-only corpus before any further
   grammar tuning, preserving WAF, IDS/IPS, EDR/XDR, NDR, NGFW, email/security
   gateway, NAC and SWG diversity;
3. expand counterexamples to token reordering, duplicated literals, embedded
   delimiters and quote corruption, while retaining required-anchor deletion;
4. only then create a separate product-integration candidate that runs this
   learned layer after current Multi-Pass/Generic Structural and below
   standards/verified profiles;
5. productize only if exact source-value/span precision remains 100% on
   independently scored additions/promotions, baseline span loss stays zero,
   PARTIAL-only layers never inflate completeness, and false-complete remains
   zero.

No product integration, PR merge, release, production, DP/sensor, auth,
credential or target-loader action is authorized by this PoC.
