# Typed Residual Security-Log PoC — 2026-10-15

## Status

**POC_SUCCESS_LIMITED — additive source-recall improvement demonstrated; not approved for product integration.**

This isolated PoC keeps the qualified Multi-Pass / Generic Structural engine as
the base and tests whether repeated type/shape evidence across a batch of
incomplete security-product events can recover exact source fields that the
single-event parser conservatively leaves residual.

Product source-engine reference:
`4596f4629a4cb7b900eb459cadffb0d2813c7957`

PoC branch:
`poc/masked-residual-rgram-20261015`

No production, DP/sensor, target-loader, release, merge, authentication or
credential action is part of this PoC.

## Scope

Security-product telemetry only: WAF, IDS/IPS, EDR/XDR, NDR/network telemetry,
NGFW/UTM, SWG/cloud firewall, NAC/identity security and email security.

The learner receives no vendor/product identity, official expected output,
Stellar Dictionary mapping or semantic destination field.

## Candidate architecture

`qualified Multi-Pass parser -> incomplete event -> batch typed-shape support
-> strict residual match -> recall-only augmentation -> preserve raw/status/issues`

An already SOURCE_PARSED event is never reinterpreted.

New spans must be wholly inside baseline residual regions. Existing source
fields/spans, raw bytes, status and issue set remain unchanged.

## Typed shapes in this PoC

1. SYSLOG_TIMESTAMP: whole `MMM d HH:mm:ss` source field.
2. SNORT_DATE: whole `MM/DD[/YYYY]-HH:mm:ss[.fraction]` source field.

Range checks reject invalid month/day/hour/minute/second values. Numeric
subcomponents are never promoted as separate fields.

## Pinned independent references

Public reference revision:
`elastic/integrations@57ac255efb40d98151337b4ff11b9015679391ed`

Cisco ISE default pipeline blob:
`0674392df50caf70303f451935210ed0056f926c`

Cisco ISE expected-output blobs:
- Administrative/Operational Audit: `82b9ec6813c716deb45ef87977095f00aac816ac`
- CISE Alarm: `69067ea045c2f1db99674e77dd954796a78ea525`
- Guest: `8f916a66302492099540b9e46f1632ec71ddbc37`
- Identity Stores Diagnostics: `b73a87ef52faeb7e3bb3535db112081e0897b78a`

Snort plaintext parser blob:
`197aa96409995a42bba8f4c86ad1b01557724198`

Snort expected-output blobs:
- Fast: `d0daa4817ee0d8b01ba2bd68c7ab67ab8e71a7d3`
- Full: `f1d170a48f4a8c33e73b130d5a2acf48e0dd0a4b`

Snort Full multiline config blob:
`d6f314c62a78d34a051dc61d0e84289a0f7c5d4b`

The pinned Snort grammar captures the entire source field:
`SNORT_DATE=%{MONTHNUM}/%{MONTHDAY}(/%{YEAR})?-%{TIME}`.

## Exact-reference three-split result

Six referenced streams, three deterministic train/holdout splits:

- augmentation occurrences: **56**
- unique augmented events: **41**
- Cisco ISE unique augmented events: **27**
- Snort unique augmented events: **14**
- added source spans: **56**
- exact official source span + value: **56 / 56**
- official expected timestamp consistent: **56 / 56**
- unvalidated added spans: **0**
- baseline completeness preserved: **56 / 56**
- baseline issues preserved: **56 / 56**
- raw mismatch: **0**

Across split occurrences:
- Cisco ISE: **38 / 38 exact**
- Snort IDS/IPS: **18 / 18 exact**

Machine-readable evidence:
`structural-hypothesis-typed-reference-multisplit-summary.json`

## Adversarial typed-field gate

Mutations invalidate typed fields by changing date/time ranges, removing
required separators and inserting NUL bytes.

- mutation attempts: **224**
- mutation augmentations: **0**

## Broad security-family gate

Family-level, three-split control:

- security-product families: **21**
- security categories: **15**
- split-evaluation cases: **1,146**
- baseline complete: **779**
- baseline incomplete: **367**
- augmentation occurrences: **85**
- unique augmented events: **58**

Augmentation occurred only in independently referenced families:
- `cisco_ise`
- `snort`

No typed augmentation occurred in the other families, including AWS WAF,
Suricata IDS/IPS/NDR, CrowdStrike, SentinelOne, Trellix, Trend Vision One,
Darktrace, ExtraHop, FortiGate, PAN-OS, Check Point, Cisco ASA/VPN, Juniper
SRX, F5 BIG-IP, Sophos UTM/XG, Zscaler ZIA and Cisco Secure Email controls.

Broad-control invariants:
- unvalidated augmentation family: **0**
- baseline status changes: **0**
- baseline issue changes: **0**
- raw changes: **0**

A Trellix EDR slice with only one unique event is recorded as too small for
batch learning rather than being used to fabricate support.

Machine-readable evidence:
`structural-hypothesis-typed-security-controls-summary.json`

## Corrected negative evidence: masked R-gram on Snort

An earlier exploratory masked-R-gram run incorrectly treated Snort Full
physical lines as complete events.

Applying the pinned multiline contract produces:
- physical lines: **41**
- logical events: **7**
- logical events exactly matching official expected originals: **7 / 7**

After correct framing:
- Snort Fast masked-R-gram hypotheses, three splits: **0**
- Snort Full masked-R-gram hypotheses, three splits: **0**
- accepted masked-R-gram augmentations: **0**

The physical-line positive result is rejected and superseded.

Machine-readable evidence:
`structural-hypothesis-snort-reference-multisplit-summary.json`

This establishes a product rule: **event framing must precede cross-event
grammar learning.**

## Tests

Focused Structural Hypothesis suite:
- **24 / 24 PASS**
- failures/errors: **0**

Full vendor-engine discovery after restoring the pinned ignored research
fixtures and optional Drain3 research dependency:
- tests: **430**
- PASS: **409**
- optional skips: **21**
- failures: **0**
- errors: **0**

The reconstructed ignored LEEF research fixture was accepted only after the
public documentation example matched the committed manifest SHA-256 exactly:

`5f8c57ff520a1311e5f6a5bd5dc064018dbdbe02f9edfb3d34cfd2502302d6e3`

## Interpretation

The PoC demonstrates a real but bounded improvement.

Cross-event evidence is useful when it is used to qualify a whole source-field
shape and only augments residual source bytes. It is unsafe to treat arbitrary
repeated token fragments as new source fields or to use batch regularity alone
to declare SOURCE_PARSED.

Supported direction:

`standards/profiles -> Generic Structural/Multi-Pass -> residual recursion
-> batch-learned typed residual augmentation -> independently qualified
residual grammars -> user/AI-assisted recovery`

Do not replace the current engine with an unconstrained grammar learner.

## Product decision

**Keep the current Auto Parser source engine as the base.**

Typed residual augmentation is a promising additive candidate because it has:
- independent exact source spans: **56 / 56**
- typed-field corruption acceptance: **0 / 224**
- unvalidated-family augmentation: **0**
- existing raw/status/issues changes: **0**
- full regression: **430 tests, 0 failures/errors**

It remains research-only. Product integration should wait for a fresh
post-freeze security-only holdout that confirms the same precision on
additional source-field types and at least one non-timestamp structural class.

## Next PoC gates

1. Add independently referenceable typed source shapes only when authoritative
   field boundaries are available.
2. Prove at least one non-timestamp residual class.
3. Expand fresh WAF, IDS/IPS, EDR, NDR, NGFW, SWG, NAC and email-security
   holdouts.
4. Require 100% exact source field/value/span precision on accepted learned
   augmentations.
5. Keep mutation false augmentation at zero.
6. Integrate only after the fresh holdout passes without weakening current
   Multi-Pass qualification.
