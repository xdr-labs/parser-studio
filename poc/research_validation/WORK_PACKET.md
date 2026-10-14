# ACTIVE Independent Security-Source Validation PoC

ACTIVE / CHATGPT_CHAT / Chat mode / dev-atlas / engine research only.
Owner scope: ordinary security-system logs including AWS WAF, IPS/IDS, NGFW,
CEF/LEEF and network-security formats. No prose-primary KPI. Dictionary later;
masked-token recognition lowest priority. No UI, DP/sensor, hosted LLM,
production/auth changes, merge or release.

## Isolation
- Repository xdr-labs/parser-studio; issue14; draft PR15, unmerged.
- Worktree /home/aella/parser-studio-validation-poc-20261014
- Branch poc/research-validation-20261014; only poc/research_validation/ changes.
- Actual main baseline c2f464444a7aa899bd8b251507234720e4cbdde2,
  security_source.parse_security_source. Main dirty WIP was not used or changed.
- Previous research comparison d318ca4b9dc99040e90bdc1e48d4eeb791ef958f.
  Latest research commit/CI are recorded in issue14's latest verified checkpoint.

## Completed follow-on
- LEEF xHH additive adapter:192 authored security conformance events,3552 native
  field/value/byte spans. Main0 TP/0 FP/3552 FN; addon3552/0/0,192 exact records.
  144 SOURCE_PARSED,48 PARTIAL duplicate warnings; do not claim192 complete.
- Mixed security-source regression: prior composer captured JSON/CEF/LEEF under
  stale table schema; #close failed to release state; unknown # records became
  metadata. RED3/6, fixed. Existing284 source records arranged in293-record
  mixed stream: old0/0/7580, fixed7580/0/0;284 outputs identical to main.
  This fixes document composition, NOT a core-engine accuracy increase.
- Fresh upstream LEEF8 records after candidate freeze:4 valid/25 native fields
  exact in BOTH;4 malformed missing-delimiter templates preserved. No extra gain.
- Existing WAF/IPS284, official WAF8/268, CEE264/6836 and Zeek127/3132 regressions
  retained. Source284 includes5 NUL controls,279 field-scored,276 fully complete.
- Independent75/75 PASS, no skips. Main modules exact-commit hash verified.
- No global KV/CEE replacement; earlier negative comparisons retained.

## First remaining operation / narrow blocker
Complete commercial CEF independent native-field oracle/scoring. Four pinned
Elastic input collections are already in .cache/cef-leef/: Check Point,
Cisco ASA, Forcepoint NGFW/SMC, Trend Micro;22 originals are event.original.
Do not use predecoded message prose as raw input. Correct frozen predictions:
.cache/cef-leef/frozen-source-predictions.json. Field accuracy is NOT SCORED.

The create/run request for poc/research_validation/cef_reference.py and
poc/research_validation/test_cef_reference.py was denied twice by OpenAI's
security-state determination, with a normal same-tool/device/path retry after
successful access verification. Both files remain absent. On resume reassess
conditions and normally retry Remote_Desktop_Commander.start_process on
**dev-atlas d39830c5-a953-43f2-b9cf-5f8d87ad832e**, same worktree/target files.
Do not bypass a repeated denial. No owner setting change is currently indicated.
The CEF oracle must independently score native header/extension names, decoded
values, repeat occurrences and UTF-8 byte spans; no ECS/Dictionary gold aliases.

## Evidence / next order
SECURITY_FOLLOWON_RESULT.md; security-followon-summary.json;
leef-upstream-summary.json; security-current-tests.json;
final-current-security-summary.json; CEF/LEEF source and freeze manifests.
Raw sources/predictions remain ignored; no redistribution.

Finish CEF scoring -> independent valid commercial xHH LEEF and rare subtypes ->
only then additive integration feasibility. No repeated broad research, prose
mining, completed fixture reacquisition or main-worktree edits. If main advances,
compare its latest committed security API, not dirty files or old parse_source.
