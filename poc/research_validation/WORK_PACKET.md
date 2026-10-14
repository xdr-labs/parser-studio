# ACTIVE Independent Security-Source Validation PoC

Status: ACTIVE / CHATGPT_CHAT / Chat mode / dev-atlas / engine research only.
Owner scope: ordinary security-system logs, including complex AWS WAF, IPS/IDS,
NGFW and network-security source formats. Sentence-style prose is not primary
scope. Dictionary mapping is later; masking recognition is lowest priority.

## Isolation and current comparison
- Repository: xdr-labs/parser-studio; issue14; draft PR15, unmerged.
- Worktree: /home/aella/parser-studio-validation-poc-20261014
- Branch: poc/research-validation-20261014. Only poc/research_validation/ changes.
- Actual main comparison: c2f464444a7aa899bd8b251507234720e4cbdde2,
  security_source.parse_security_source, not the historical parse_source API.
- Main worktree and its generic-body WIP remain untouched. No reset/clean/stash,
  main packet replacement, production, auth change, merge or release.

## Completed security checkpoint
- Main added CEE support concurrently; final comparison was refreshed using an
  isolated exact-current snapshot. Do not reuse obsolete CEE gains.
- Unmodified security284:279 field-scored /7580 fields, zero FP/FN in current
  and selected composition. Five NUL-corrupted records separately retained;
  one malformed KV tail prefix-scored as PARTIAL. Full complete276/284.
- Official AWS WAF10 code blocks:8 JSON examples/268 fields exact;2 non-parseable
  snippets retained outside field scoring. FortiGate IPS7/292 and Suricata
  alert24/748 are explicit subsets of the original corpus.
- CEE forms264 derived from66 bodies: current and composed6836/6836 fields;
  whole independent CEE replacement loses1709 fields. REJECT replacement.
- Zeek187 physical=127 data+60 metadata/preamble. Current0 TP/44 FP/3132 FN;
  current+declared-metadata3132 TP/0 FP/FN. The6 provenance preambles remain raw.
- Selected security_document.py uses the current security API for every ordinary
  event. Original284 output structures are unchanged. No H1 KV replacement.
- Prior malformed-metadata guard and preamble accounting WIP finalized; prior
  denials are not current blockers. Independent57/57 and main-scope58/58 PASS,
  no skips. Generic repository CI is recorded on the actual research commit.

## Authoritative evidence
SECURITY_VALIDATION_RESULT.md; final-current-security-summary.json;
security-current-tests.json; current-main-regression-tests.json. Original logs,
reference examples and private predictions remain ignored. Earlier reports are
historical; source-derived transport forms are not new production captures.

## First remaining executable work
Extend independently sourced commercial IPS/NGFW CEF/LEEF and rare version
subtypes; freeze the candidate before new source acquisition and compare the
actual current security entry point. Preserve existing negative results. Then
qualify source-schema rotation/mixed-source admission and only additive fixes.
No generic prose mining, repeated broad research, main-engine integration,
Dictionary, UI, native/DP/sensor or release work in this lane without scope change.

## Resume discipline
Read this packet plus issue14's latest checkpoint and actual Git/PR/CI state.
If the main lane advanced, use its latest committed security API rather than an
old core API or dirty source files. Preserve all worktrees and licensed caches.
Retry old restrictions only if an actual remaining operation is still blocked;
none is presently outstanding. User configuration action: none.
