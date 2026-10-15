# Structural Hypothesis Engine — Security-Product PoC v2 (2026-10-15)

## Decision status

**PROMISING / LIMITED. Continue PoC; do not integrate into the product engine yet.**

The PoC now validates two independent cross-event structural primitives on
security-product logs:

1. repeated delimiter/key-anchor grammar induction for variable-width KV records;
2. literal-anchor / variable-slot event-template induction for repeated numeric
   security event codes.

Both are additive to the current product Multi-Pass engine. They never replace
an already `SOURCE_PARSED` event. A candidate is accepted only through a
residual-only merge that preserves every existing baseline field/span and adds
new value spans wholly inside baseline residual regions.

The result is repeatable across deterministic train/holdout splits and the
current mutation gate has zero false-complete results. The gain is still
concentrated in Cisco ISE and Cisco ASA/VPN records, so this is not yet evidence
of open-world generalization across all security products.

## Scope

Only security-product telemetry is in scope. General application/OS prose logs
are excluded.

Security-product families exercised:

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
- Zscaler ZIA SWG/cloud firewall
- F5 BIG-IP WAF/NGFW
- Cisco ISE NAC / identity security
- Juniper SRX NGFW/IDS/IPS
- Sophos UTM
- Sophos XG NGFW/UTM

The learner receives no vendor/product identity and performs no semantic/Stellar
Dictionary mapping. Product/family labels exist only in the benchmark harness
for reporting. Public fixtures are pinned by source revision and raw fixture
content remains in ignored local research cache.

## Baseline

Product source-engine candidate:

`4596f4629a4cb7b900eb459cadffb0d2813c7957`

PoC branch/worktree:

- branch: `poc/structural-hypothesis-engine-20261015`
- worktree: `/home/aella/parser-studio-structural-hypothesis-poc-20261015`

The product worktree and its unrelated dirty changes are not modified.

## Primitive A — cross-event delimiter/key-anchor grammar

For each sample stream the PoC detects quote-aware comma/semicolon key anchors,
retains anchors repeated across training samples, rejects unstable anchor order,
infers an optional first key behind variable-width prefixes, learns minimum
prefix evidence, and learns terminal-key evidence.

Values extend to the next structural key anchor rather than merely the next
delimiter. This can recover unquoted multi-word values that contain delimiter
characters.

Admission is deliberately conservative:

- at least three learned anchors;
- compatible learned anchor order;
- learned terminal-anchor evidence;
- minimum prefix-position evidence;
- JSON/CEF/LEEF roots are not reinterpreted;
- malformed/resource-limit baseline issues are not cleared;
- existing complete results are never evaluated for replacement.

## Primitive B — positional CSV corpus confirmation

A bounded secondary experiment checks whether already-extracted unlabeled
positional CSV can be confirmed by cross-sample width consistency.

It never invents column meaning and never changes fields or spans. It may only
clear `UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION` when:

- source residual is already zero;
- no other parser issue exists;
- at least three training records are eligible;
- one width has at least 80% support;
- the holdout width matches exactly.

Current security corpus result: **no new extraction promotion**. This remains a
negative result and thresholds were not relaxed.

## Primitive C — cross-event literal-anchor event templates

For security records containing a generic numeric event-code shape, training
records are grouped by numeric message ID. The learner uses deterministic
sequence alignment/LCS over literal tokens to derive stable anchors and the
variable gaps between them.

A template is admitted only if:

- the same numeric event-code group has at least two training examples;
- at least six stable literal anchors remain after alignment;
- anchor coverage is sufficiently high;
- stable terminal-position evidence exists;
- every training example self-parses;
- training truncation/deletion/NUL mutations fail closed.

The parser emits only source-side variable slots with exact UTF-8 spans. It does
not assign semantic names to those slots.

This primitive recovered Cisco ASA/VPN records that the current parser retained
as `ASA_MESSAGE_BODY_UNPARSED`.

## Residual-only no-loss merge

The initial PoC candidate could reinterpret some already-extracted baseline
value boundaries. That behavior is rejected.

The current merge contract is:

`baseline fields/spans + candidate values wholly inside baseline residual only`

A promotion is invalid if:

- any baseline source span disappears;
- raw input changes;
- the candidate is not structurally complete;
- no new non-empty value exists wholly inside a baseline residual region;
- the baseline has malformed/resource-limit signals such as unclosed,
  truncated, invalid, NUL/size, byte-limit, field-limit, or depth-limit issues.

The accepted single-split promotions preserve **7/7 baseline span sets** with
**0 span loss** and **0 raw mismatch**.

## Security-only evaluation result

Current corpus:

- **20 security-product families**
- **14 security categories**
- **376 evaluation events**
- **323 events** come from files large enough for disjoint deterministic
  train/holdout splits
- **53 events** come from very small files and are used only as no-regression
  controls; they are not treated as independent generalization evidence

Single deterministic split:

- baseline `SOURCE_PARSED`: **290**
- baseline incomplete: **86**
- accepted additional structural completions: **7**
  - delimiter/key-anchor: **5**
  - event-template: **2**
- recovered incomplete events: **7 / 86 = 8.1%**
- additional exact source value spans: **58**
- residual bytes removed: **1,130**
- accepted promotions preserving every baseline span: **7 / 7**
- baseline span loss: **0**
- raw mismatch: **0**
- bounded mutation attempts on promoted events: **35**
- mutation types: **5**
- mutation false-complete: **0**

Promotion families:

- Cisco ISE: **5**
- Cisco ASA/VPN: **2**

AWS WAF, Suricata, Zeek, Darktrace, ExtraHop, EDR/XDR, firewall and SWG
fixtures act as broad no-regression/abstention controls in this version. No
promotion is claimed merely because a status can be changed without recovering
new source values.

Machine-readable evidence:

- `structural-hypothesis-security-poc-summary.json`

## Multi-split repeatability

Three deterministic train/holdout splits were run across the same pinned
security-only corpus.

Aggregate:

- evaluation cases across three splits: **1,128**
- baseline incomplete cases: **260**
- accepted promotions: **20**
  - delimiter/key-anchor: **15**
  - event-template: **5**
- accepted promotions preserving every baseline span: **20 / 20**
- baseline span loss: **0**
- raw mismatch: **0**
- promoted families:
  - Cisco ISE: **15**
  - Cisco ASA/VPN: **5**
- mutation attempts across promoted events: **100**
- mutation false-complete: **0**

Per split:

- split A: **9** promotions, mutation false-complete **0**
- split B: **6** promotions, mutation false-complete **0**
- split C: **5** promotions, mutation false-complete **0**

Machine-readable evidence:

- `structural-hypothesis-security-multisplit-summary.json`

## Tests

Focused Structural Hypothesis tests: **14 / 14 PASS**.

Cache-independent vendor-engine regression after excluding exactly nine tests
that require unavailable historical ignored CEF/commercial cache files or the
optional Drain3 cache:

- runner tests: **411**
- PASS: **400**
- optional skips: **11**
- failures: **0**
- errors: **0**

An unfiltered discovery run demonstrated that the excluded cases fail only on
missing ignored evidence/dependency cache inputs (`multipass-cef` fixtures and
Drain3), not on assertion failures introduced by this PoC.

Focused PoC tests cover:

- cross-event delimiter/key-anchor learning;
- quoted and unquoted delimiter handling;
- unseen holdout keys after grammar qualification;
- learned prefix and terminal evidence;
- truncated fail-closed behavior;
- JSON/CEF/LEEF non-reinterpretation;
- residual-only baseline span preservation;
- malformed/resource-limit issue protection;
- event-template alignment and variable-slot extraction;
- event-template truncation rejection;
- positional CSV confirmation and unstable-width rejection.

The PoC remains separate from product integration. Existing source-engine code
is not modified by this branch.

## Interpretation

The hypothesis layer now demonstrates a real extraction gain that a
single-event parser cannot obtain safely from the same event alone:

`sample batch -> learn stable structure -> parse only incomplete events ->
preserve all baseline claims -> add residual source values -> adversarial gate`

The key result is not the seven events themselves. It is that the approach can
recover two structurally different long-tail security-log classes while
remaining additive and fail-closed:

- repeated delimiter/KV structure with variable values;
- repeated event-code messages with positional variable slots.

However, the current benefit is still limited to two product families. It does
not yet justify product integration.

## Next PoC steps

Continue without weakening current admission rules:

1. add R-gram/relative-anchor hypotheses for variable-position firewall/NDR
   records;
2. add bounded multi-dialect delimiter/CSV search only where source values are
   genuinely missing;
3. add counterexample-guided grammar refinement using rejected holdouts;
4. derive stronger grammar-specific mutation/fuzz cases automatically;
5. enlarge independent security-product holdouts, especially IDS/IPS, EDR and
   NDR long-tail non-JSON formats;
6. require independent field/span gold before any learned grammar is promoted
   from PoC evidence to product qualification.

No product integration, PR merge, release, production, DP/sensor, auth,
credential, or target-loader action is authorized by this PoC.
