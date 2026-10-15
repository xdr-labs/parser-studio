# Structural Hypothesis Engine — Security-Product PoC v1 (2026-10-15)

## Decision status

**PROMISING / LIMITED. Do not integrate into the product engine yet.**

The PoC validates one useful new primitive: cross-event delimiter/key-anchor grammar
induction can recover exact source structure that the current single-event
heuristics deliberately leave incomplete. The first security-only holdout shows
a measurable improvement with no regression to existing complete events and no
false-complete result in the bounded mutation gate.

The gain is currently concentrated in Cisco ISE-style delimiter/KV records.
This is evidence to continue the research, not evidence that the approach
generalizes to every security-product format.

## Scope

Only security-product telemetry is in scope. General application/OS prose logs
are excluded.

Security categories exercised:

- AWS WAF
- Suricata IDS/IPS / network detection
- Zeek NDR/network telemetry
- Trellix EDR and ePO
- Trend Vision One EDR/XDR
- FortiGate NGFW
- PAN-OS NGFW
- F5 BIG-IP WAF/NGFW
- Cisco ISE NAC / identity security
- Juniper SRX NGFW/IDS/IPS
- Sophos UTM
- Sophos XG NGFW/UTM

The learner receives no vendor/product identity and performs no semantic/Stellar
Dictionary mapping.

## Baseline

Product source-engine candidate:

4596f4629a4cb7b900eb459cadffb0d2813c7957

PoC branch/worktree:

- branch: poc/structural-hypothesis-engine-20261015
- worktree: /home/aella/parser-studio-structural-hypothesis-poc-20261015

The product worktree and its unrelated dirty changes were not modified.

## Primitive A — cross-event delimiter/key-anchor grammar

For each sample stream the PoC detects quote-aware comma/semicolon key anchors,
retains anchors repeated across training samples, rejects unstable anchor order,
infers optional first fields behind variable-width prefixes, and learns
terminal-key evidence.

Values extend to the next structural key anchor, not merely the next delimiter.
This allows unquoted multi-word values that themselves contain delimiters.

Safety requirements:

- never replace an already SOURCE_PARSED event
- do not reinterpret JSON/CEF/LEEF roots
- require at least three learned anchors
- require compatible anchor order
- require learned record-termination evidence
- preserve complete raw-byte accounting
- preserve exact UTF-8 source-value spans
- fail closed on NUL input

The first implementation used anchor quorum without termination evidence and
produced two false-complete truncated mutations. That was treated as RED.
Adding learned terminal-anchor evidence removed both failures.

## Primitive B — positional CSV corpus confirmation

A second experiment tests cross-sample structural consistency for unlabeled
positional CSV. It never changes fields or spans. It may only clear the existing
UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION issue when at least three training
records agree, one width has at least 80 percent support, the holdout width
matches exactly, source residual is zero, and no other parser issue exists.

Current security corpus result: **no new qualified product promotion**.

The remaining Cisco ISE candidate had insufficient support and Juniper widths
were unstable (4/7/8). This is retained as a negative result; thresholds were
not relaxed.

## Security-only holdout result

Value-free result from 66 source files / 13 security-product families:

- holdout events: **332**
- current baseline SOURCE_PARSED: **261**
- current baseline incomplete: **71**
- cross-event hypothesis attempts: **14**
- additional structural completions: **5**
- additional source value spans: **56**
- residual bytes removed: **800**
- protected already-complete events reinterpreted: **0**
- bounded mutation attempts on promoted events: **10**
- mutation false-complete: **0**

All five current promotions are Cisco ISE records. AWS WAF, Suricata, Zeek,
EDR/XDR, NGFW and other already-complete security records remain controls and
are not reinterpreted.

Machine-readable evidence:
structural-hypothesis-security-poc-summary.json

## Tests

Focused PoC result: **10/10 PASS**.

Coverage includes cross-event anchor learning, unquoted and quoted delimiters,
new holdout keys, weak-training abstention, JSON/CEF/LEEF non-reinterpretation,
truncated fail-closed behavior, complete-baseline protection, positional CSV
span preservation, and unstable CSV-width rejection.

The repository-wide cache-dependent suite cannot be reproduced completely in
this fresh worktree because historical ignored research caches were removed.
The unavailable inputs are old commercial raw cache files, independent holdout
cache files, and the optional Drain3 cache. Those errors are environment/evidence
cache availability errors rather than failures introduced by this PoC.
Cache-independent regression: **397 tests PASS / 9 optional skips / 0 failures or errors**.

## Interpretation

The result supports a batch-level structural evidence layer above the current
per-event Multi-Pass engine, but does not support replacing the current engine.

Recommended layering if follow-up PoCs continue to pass:

qualified standards/profiles -> Generic Structural -> cross-event structural
hypotheses -> residual candidate recovery -> user/AI repair

The next research step should add another independent hypothesis family rather
than weaken this one:

1. R-gram / sequence-alignment anchors for variable-position security fields
2. multi-dialect CSV/TSV hypothesis search where the current parser is genuinely incomplete
3. counterexample-guided grammar refinement
4. grammar-derived mutation/fuzz qualification before accepting a learned grammar

No product integration, merge, release, production, DP/sensor, or target-loader
action is authorized by this PoC.
