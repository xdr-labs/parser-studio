# Structural Hypothesis Engine — Security-Product PoC v4 (2026-10-15)

## Decision status

**PROMISING / LIMITED. Continue PoC; do not integrate into the product engine yet.**

This PoC evaluates whether batch-level structural learning can recover source
values that the current single-event Multi-Pass engine deliberately leaves
incomplete. The learner uses source syntax only. Product/vendor identity is
never an admission feature and semantic/Stellar Dictionary mapping is out of
scope.

Four hypothesis families were implemented and challenged:

1. cross-event delimiter/key-anchor grammar induction;
2. numeric event-code literal-anchor / variable-slot templates;
3. relative R-gram residual signatures for repeated security-message bodies;
4. repeated leading numeric skeletons for partial source-value recovery.

The first three compete only for strict residual-only whole-event promotion.
Only the relative R-gram family currently survives that final no-loss gate with
independently validated new source values. Earlier delimiter/template promotions
were rejected after hardening because candidate values re-segmented already
claimed baseline source regions.

The fourth family intentionally has a different contract: it may add exact
source-value spans proven by repeated sample structure, but it must preserve the
event's PARTIAL state and all original issues/residual regions. This allows
accuracy-first extraction gains without falsely certifying the whole grammar.

All accepted candidates are additive. An already `SOURCE_PARSED` event is
never reinterpreted.

## Scope

Only security-product telemetry is in scope. General application/OS prose logs
are excluded.

The current corpus covers **22 security-product families** and **16 security
categories**, including:

- AWS WAF
- Suricata IDS/IPS / network detection
- Snort IDS/IPS
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

## Primitive E — leading numeric skeleton partial recovery

This layer addresses a different requirement: maximize exact source-value
recovery even when the whole record grammar cannot yet be certified.

Across a training batch it learns only repeated leading numeric/separator
skeletons, for example a shape equivalent to:

`<NUM>/<NUM>-<NUM>:<NUM>:<NUM>`

or:

`<NUM>:<NUM>:<NUM>-<NUM>:<NUM>:<NUM>`

The learner is not given vendor/product identity, field semantics, expected
timestamps or a fixed Snort/Sophos grammar. Admission requires:

- at least three training samples with the exact same numeric/separator shape;
- at least four numeric slots and at least two distinct punctuation separators;
- explicit slot-count and prefix-length bounds;
- exact holdout skeleton match;
- every emitted value span wholly inside a baseline residual region;
- no operation past NUL/size/resource-limit safety issues.

Unlike the whole-event hypotheses, this layer **does not clear issues or
residuals and cannot turn PARTIAL into SOURCE_PARSED**. It only appends
temporary source slots with exact UTF-8 spans.

Independent validation:

- Snort fast IDS/IPS: three splits, **60 / 60** added spans exactly match the
  pinned Elastic `SNORT_DATE` source boundaries; **12 / 12** evaluated
  holdout occurrences also match expected timestamp components.
- Sophos UTM DHCP/DNS: three splits, **54 / 54** added spans exactly match
  Elastic's pinned `SOPHOS_TIMESTAMP` source boundaries; **9 / 9** evaluated
  holdout occurrences match expected timestamps.
- learner reference-value leakage: **none**;
- baseline span loss: **0**;
- raw mismatch: **0**.

Machine-readable evidence:

- `structural-hypothesis-snort-numeric-prefix-multisplit-summary.json`
- `structural-hypothesis-sophos-numeric-prefix-multisplit-summary.json`

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

- source files: **85**
- security-product families: **22**
- security categories: **16**
- evaluation events: **430**
- disjoint train/holdout evaluation events: **371**
- tiny-file no-regression control events: **59**
- baseline `SOURCE_PARSED`: **304**
- baseline incomplete: **126**

Final accepted new completions:

- total: **6 / 126 = 4.8% of baseline-incomplete evaluation events**
- delimiter/key-anchor: **0**
- event-code template: **0**
- relative R-gram: **6**
- promotion family: **Cisco Secure Email only**

Whole-event promotion extraction evidence:

- additional source-value spans: **12**
- residual bytes removed: **492**
- promotions preserving every baseline span: **6 / 6**
- baseline span loss: **0**
- raw mismatch: **0**

Additional partial-only source recovery:

- augmented incomplete events: **7**
- added source-value spans: **38**
- Snort IDS/IPS fast format: **4 events / +20 spans**
- Sophos UTM: **3 events / +18 spans**
- baseline span loss: **0**
- raw mismatch: **0**
- every augmented event remains **PARTIAL**

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

- evaluation cases: **1,290**
- baseline incomplete cases: **377**
- accepted whole-event promotions: **21 / 377 = 5.6%**
- accepted whole-event primitive: **relative R-gram only**
- promotion family: **Cisco Secure Email only**
- accepted promotions preserving every baseline span: **21 / 21**
- whole-event added source spans: **44**
- residual bytes removed by whole-event promotions: **1,752**
- partial-only augmented events: **21**
- partial-only added source spans: **114**
- partial families: **Snort fast 12 / Sophos UTM 9**
- baseline span loss: **0**
- raw mismatch: **0**
- mutation attempts: **105**
- mutation false-complete: **0**

Per split:

- split A: **7** complete promotions plus **7** partial augmentations / **38** partial spans
- split B: **7** complete promotions plus **7** partial augmentations / **38** partial spans
- split C: **7** complete promotions plus **7** partial augmentations / **38** partial spans

Independent reference validation across all three splits:

- promotion occurrences: **21**
- unique promoted events: **14**
- added spans: **44**
- Elastic official expected exact matches: **21**
- Cisco-documented reputation-score values: **21**
- Cisco-documented URL values not emitted by the Elastic expected output: **2**
- independently validated added spans: **44 / 44**
- unvalidated added spans: **0**

Independent partial-recovery validation across all three splits:

- Snort fast augmentation occurrences: **12**
- Snort fast added spans: **60 / 60 exact** against pinned `SNORT_DATE`
- Snort expected timestamp consistency: **12 / 12**
- Sophos UTM augmentation occurrences: **9**
- Sophos UTM added spans: **54 / 54 exact** against pinned
  `SOPHOS_TIMESTAMP`
- Sophos expected timestamp consistency: **9 / 9**
- combined independently validated partial spans: **114 / 114**
- partial baseline span loss: **0**
- partial raw mismatch: **0**
- malformed-shape/NUL mutation attempts: **63**
- mutation attempts producing any partial augmentation: **0**
- mutation false-complete: **0**
- every augmented event remains **PARTIAL**

Machine-readable evidence:

- `structural-hypothesis-security-multisplit-summary.json`
- `structural-hypothesis-cisco-reference-multisplit-summary.json`

## Tests and regression

Focused Structural Hypothesis suite on the final research candidate:
**29 / 29 PASS**.

The previously missing ignored LEEF evidence was reconnected from the preserved
PoC worktree, and the existing pinned Drain3 0.9.11 ignored dependency was added
to the test-only `PYTHONPATH`. No tracked dependency or product runtime was
changed.

Exact current worktree full discovery:

- tests run: **435**
- optional skips: **4**
- failures: **0**
- errors: **0**
- result: **PASS**

Together with the focused **29 / 29 PASS** and the dedicated independent
reference benchmarks, this is the reproducible code-regression gate for the
final isolated PoC worktree.

## Fresh prospective security holdout — v4 abstention result

A separate source set was frozen in
`STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_20261015.json` before Parser
Studio read or evaluated the fixtures. It contains 27 files from four previously
unused security-product families:

- Barracuda WAF;
- NETSCOUT Sightline NDR/DDoS;
- Symantec Endpoint security;
- WatchGuard Firebox NGFW.

The frozen v4 hypothesis engine was then evaluated without tuning across three
deterministic train/holdout splits. Files with fewer than four events were never
reused as both train and holdout.

Aggregate across the three splits:

- evaluation events: **903** (**301 per split**);
- baseline SOURCE_PARSED: **351**;
- baseline PARTIAL: **483**;
- baseline RAW_ONLY: **69**;
- new whole-event promotions: **0**;
- new whole-event source spans: **0**;
- partial-only augmented events: **0**;
- partial-only added source spans: **0**.

Per-family evaluation occurrences across all splits:

- Barracuda WAF: **54**;
- NETSCOUT Sightline: **105**;
- Symantec Endpoint: **78**;
- WatchGuard Firebox: **666**.

This is an important negative result. The v4 learner did not force a speculative
grammar onto unseen products merely to raise coverage. It also means the
cross-event primitives demonstrated on Cisco Secure Email, Snort and Sophos do
**not yet generalize broadly enough** to justify product integration.

Machine-readable evidence:

- `structural-hypothesis-fresh-security-holdout-summary.json`

After this result was recorded, these fixtures may be used as development data.
Any improvement learned from them must be validated on a **new pre-frozen
security holdout** before it can count as generalization evidence.

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

## Fresh open-world security holdout

A separate source set was frozen before evaluation at the same pinned
`elastic/integrations` revision. It contains 27 files from four previously
unused security-product families:

- Barracuda WAF;
- NETSCOUT Sightline NDR/DDoS;
- Symantec Endpoint / EDR;
- WatchGuard Firebox NGFW.

The frozen set contains **820 source events**. Deterministic splitting produced
**301 evaluation events**, of which **276 are fully disjoint holdouts** and 25
come from files too small to split and are retained only as controls.

Fresh-holdout baseline:

- `SOURCE_PARSED`: **120 / 301**;
- incomplete: **181 / 301**.

Structural Hypothesis v4 result on those 181 incomplete events:

- whole-event promotions: **0**;
- partial augmentations: **0**;
- unsafe raw/span replacements: **0**;
- abstentions: **181 / 181**.

No admission threshold was relaxed after seeing this result. WatchGuard message
identifiers did not repeat sufficiently across train/holdout for safe template
learning, and the Symantec positional CSV samples did not meet the existing
support/width qualification gates. Those cases remain incomplete rather than
receiving vendor-specific exceptions.

This is useful negative evidence: the current learned primitives improve known
repeated structural classes but **do not yet provide open-world recall gains on
these four new families**. At the same time, they fail closed instead of
manufacturing fields on unseen structures.

Machine-readable evidence:

- `STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_20261015.json`
- `structural-hypothesis-fresh-security-holdout-summary.json`

## CSV-cell label refinement — development evidence only

A follow-up parser learns repeated labels embedded inside already extracted
unlabeled CSV cells and adds child value spans without replacing the parent CSV
spans or clearing `UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION`.

This primitive was designed after inspecting the first fresh holdout, so the
first-holdout families are **development evidence only**, not prospective
generalization evidence.

Independent multi-split validation:

- Symantec Endpoint: **3 augmentation occurrences / 6 added spans / 6 of 6
  exact** against Elastic's pinned expected `site` and `server` values;
- NETSCOUT Sightline NDR: **17 augmentation occurrences / 68 added spans / 68
  of 68 exact** against the independently specified Change Log grammar;
- every parent CSV span remained byte-identical;
- every augmented event remained **PARTIAL**;
- learner input contained neither reference values nor vendor/product identity.

These results establish that the primitive can refine a known repeated CSV-cell
shape safely, but they do not count as fresh open-world recall evidence.

Machine-readable evidence:

- `structural-hypothesis-symantec-csv-label-multisplit-summary.json`
- `structural-hypothesis-netscout-csv-label-multisplit-summary.json`
- `structural-hypothesis-csv-label-development-summary.json`

## Additional v5 development primitives

### Extended BSD/syslog envelope refinement

The first fresh holdout exposed a repeated composite syslog envelope that the
single-event parser only partially recognized. A batch learner now qualifies
the structural shape without using vendor identity:

`PRI + BSD timestamp + hostname + 0..2 middle tokens + optional inner ISO
timestamp + appname + optional procid + body`.

Validation uses the pinned Elastic WatchGuard default pipeline grok
(`4c64981d839ccbbf403490fc6ab646cfbebdf604`) as an independent source-boundary
reference. Across three deterministic mixed-product splits:

- augmentation occurrences: **414**;
- added source spans: **2,891**;
- exact official grok capture spans: **2,891 / 2,891**;
- baseline spans preserved: **414 / 414 events**;
- every event remained incomplete;
- malformed-shape/NUL mutation attempts: **828**;
- mutations producing any augmentation: **0**;
- mutation false-complete: **0**.

This is development evidence because the primitive was designed after the first
fresh holdout was observed.

Machine-readable evidence:

- `structural-hypothesis-watchguard-extended-bsd-multisplit-summary.json`

### Explicit residual typed labels

A second conservative layer learns only repeated residual syntax of the form
`ExplicitLabel=<typed value>`, where the value is already independently
recognizable as a bounded IP/number/URL/quoted value and the label is not a
common lowercase generic KV token. It never clears residual bytes or issues.

Across three mixed-product development splits:

- augmentation occurrences: **26**;
- added source spans: **26**;
- exact pinned WatchGuard expected values: **26 / 26**;
- baseline spans preserved: **26 / 26 events**;
- every event remained incomplete;
- learned labels were limited to repeated structural evidence
  (`GatewayEndpoint`, `Gateway-Endpoint`, `Tunnel`);
- NUL / broken-assignment mutation attempts: **52**;
- mutations producing any augmentation: **0**;
- mutation false-complete: **0**.

The learner did not receive those label names as vendor rules; they were learned
from repeated source syntax in the mixed security batch.

Machine-readable evidence:

- `structural-hypothesis-watchguard-typed-label-multisplit-summary.json`

### Rejected broad multi-residual R-gram

A broader experiment attempted to emit every typed atom from repeated residual
region signatures. It had high apparent recall but insufficient precision:

- candidate events: **141**;
- candidate spans: **1,413**;
- independently supported official leaf values: **426**;
- unvalidated spans: **987**.

Verdict: **REJECTED_LOW_PRECISION_ATOMIZATION**. Exact repeated residual shape
alone is insufficient to define source-field boundaries. The implementation was
removed; only the negative evidence is retained.

Machine-readable negative evidence:

- `structural-hypothesis-multi-residual-rgram-negative.json`

## Second pre-frozen security holdout

A second source set was selected from file metadata only and committed as
`aa6d893` before raw fixture acquisition or evaluation. It contains **14 pinned
pipeline log files** from five previously unused product families:

- Proofpoint On Demand email security;
- Netskope CASB/SWG;
- Fortinet FortiManager security management;
- Pulse Connect Secure VPN/ZTNA;
- Juniper Junos network security.

The current hypothesis ensemble, including CSV-cell label refinement, was then
run unchanged.

Prospective result:

- evaluation events: **100**;
- baseline SOURCE_PARSED: **51**;
- baseline incomplete: **49**;
- whole-event promotions: **0**;
- partial augmentations: **0**;
- abstentions: **49 / 49 incomplete events**;
- pinned Git blob verification: **14 / 14 files**.

No admission threshold was relaxed after seeing the result. This second negative
holdout confirms that the verified gains are real for repeated structures but
still do **not** constitute broad open-world parser generalization.

Machine-readable evidence:

- `STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_2_20261015.json`
- `structural-hypothesis-fresh-security-holdout-2-summary.json`

## Third pre-frozen security holdout

A third source set was frozen in Git before raw acquisition under the canonical
manifest commit `1167d19`. It contains **20 pinned pipeline log files** from
five previously unused security-product families:

- Cisco Secure Endpoint EDR;
- Microsoft Defender for Endpoint EDR;
- Cloudflare edge/WAF security;
- Cisco Umbrella DNS/SWG/IPS;
- Fortinet FortiClient endpoint security.

All **20 / 20** manifest files were verified against their pinned upstream Git
blob SHA before evaluation. The v5 candidate was then run unchanged and without
vendor identity as a learner feature.

Prospective result:

- evaluation events: **204**;
- baseline SOURCE_PARSED: **203**;
- baseline incomplete: **1**;
- whole-event promotions: **0**;
- partial augmentations: **0**;
- abstentions: **1 / 1 incomplete event**;
- raw/span replacement violations: **0**.

This holdout confirms safe abstention, but it is **not a positive open-world
recall test** because the existing qualified engine already parsed 99.5% of the
evaluation events. The single remaining Cisco Umbrella event did not satisfy any
learned admission contract and remained incomplete. No threshold was relaxed.

Machine-readable evidence:

- `STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_3_20261015.json`
- `structural-hypothesis-fresh-security-holdout-3-summary.json`

## Interpretation

The strict v4 result supports **two complementary batch-learned layers** above
the current single-event Multi-Pass / Generic Structural engine. The v5
development candidate keeps those layers and adds three more conservative
partial-only refinements: CSV-cell labels, composite BSD/syslog envelopes and
explicit residual typed labels.

Whole-event learned recovery:

`qualified single-event parser
 -> repeated residual R-gram learning
 -> exact holdout signature match
 -> dynamic source slots only
 -> residual-only no-loss merge
 -> adversarial qualification`

This path can promote an event to `SOURCE_PARSED` only when the learned grammar
accounts for the remaining source without replacing any accepted baseline
claim. Cisco Secure Email is the independently validated example: across three
splits the PoC added **44 / 44 independently correct source spans**.

Partial learned recovery:

`qualified incomplete event
 -> repeated structural skeleton learning
 -> exact holdout skeleton match
 -> add only source slots wholly inside baseline residual
 -> preserve original issues/residual/status`

This path deliberately does **not** certify the whole grammar. It improves
source-value recall while leaving the event PARTIAL. Snort IDS/IPS and Sophos
UTM independently validate this behavior with **114 / 114 exact added spans**
across three splits.

Together, the independently validated multi-split evidence is therefore
**158 / 158 newly recovered source spans** across three different security
product families and two structurally different learned primitives, with zero
baseline span loss. The earlier delimiter/key-anchor, event-code template and
masked-R-gram experiments remain retained negative evidence and are not counted
as gains.

The architecture supported by the PoC is consequently:

`existing qualified parsers
 -> strict batch-learned complete candidate when provable
 -> bounded batch-learned partial candidates on residual only
 -> deterministic no-loss adjudication
 -> semantic/Stellar mapping later`

This is materially more useful than optimizing only the SOURCE_PARSED rate,
because Parser Studio's primary KPI is exact original source-field/value
recovery. It also avoids forcing a speculative grammar to appear complete.

## PoC decision

**POC_SUCCESS_LIMITED.** The experiment proves that batch-learned structural
hypotheses can safely improve the current parser when a repeated grammar is
actually evidenced:

- **158 / 158 independently validated new source spans** across Cisco Secure
  Email, Snort IDS/IPS and Sophos UTM in three deterministic splits;
- the v5 development candidate adds **2,991 / 2,991 independently validated
  added-span occurrences** across three partial-only refinements:
  - CSV-cell labels: **74 / 74** on Symantec Endpoint and NETSCOUT Sightline;
  - extended BSD/syslog envelope: **2,891 / 2,891** exact pinned WatchGuard
    grok capture spans;
  - explicit residual typed labels: **26 / 26** exact pinned WatchGuard
    expected values;
- these 2,991 development spans are deliberately excluded from
  prospective-generalization claims because all three refinements were designed
  after the first holdout became development data;
- complete promotions preserve every baseline span and raw event;
- partial augmentation never upgrades PARTIAL to SOURCE_PARSED;
- complete-candidate mutation false-complete remains **0**;
- dedicated Snort/Sophos partial mutations produced **0 unexpected
  augmentations** as well as **0 false-complete**;
- the first fresh Barracuda/NETSCOUT/Symantec/WatchGuard holdout abstained on
  **181 / 181** incomplete events;
- the second pre-frozen Proofpoint/Netskope/FortiManager/Pulse/Junos holdout
  abstained on **49 / 49** incomplete events, even with CSV-cell label
  refinement enabled;
- the third pre-frozen Cisco Secure Endpoint/Defender/Cloudflare/Umbrella/
  FortiClient holdout verified **20 / 20** pinned files; the existing engine
  completed **203 / 204** evaluation events and the learned layer safely
  abstained on the single remaining incomplete event.

The same evidence also shows the limit: current qualified evidence has not yet
shown measurable recall gain on an independently pre-frozen unseen product
family. Holdout #3 had too little incomplete-source opportunity to provide a
meaningful positive recall test, while holdout #2 remained a full abstention
result.

The PoC supports a **strict additive candidate layer** as a research direction,
not replacement of Multi-Pass / Generic Structural and not unconditional
enablement as the default Auto Parser path.

## Final PoC disposition

**Close this research PoC as POC_SUCCESS_LIMITED.** Further improvement should
move to a separate integration/next-generation PoC rather than continuing to
add primitives to this branch.

Productization remains gated by all of the following:

1. independently scored added-span precision remains **100%**;
2. baseline source-span loss remains **0** and raw preservation remains
   **100%**;
3. partial recovery never certifies whole-record completeness;
4. complete-candidate false-complete remains **0** under adversarial mutation;
5. any new grammar family must prove gain on a newly frozen holdout rather than
   on data used to design that grammar.

No product integration, PR merge, release, production, DP/sensor, auth,
credential or target-loader action is authorized by this PoC.
