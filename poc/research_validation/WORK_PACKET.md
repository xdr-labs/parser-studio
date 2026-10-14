# ACTIVE Independent Security-Source Validation PoC

ACTIVE / CHATGPT_CHAT / Chat mode / dev-atlas / engine research only.
Scope: ordinary security-system logs including AWS WAF, IPS/IDS, NGFW, NDR,
CEF/LEEF. No prose-primary KPI. Dictionary later; masking recognition last.
No UI, native/DP/sensor, hosted LLM, production/auth changes, merge or release.

## Isolation and exact comparison
- Repository xdr-labs/parser-studio; issue14; draft PR15, unmerged.
- Worktree /home/aella/parser-studio-validation-poc-20261014
- Branch poc/research-validation-20261014; only poc/research_validation/ changes.
- Current main baseline c2f464444a7aa899bd8b251507234720e4cbdde2,
  security_source.parse_security_source. Never use dirty main files.
- Research parent bb42d010f2ea2b8a3938b0b05d0525fcce7b0f45.
  Exact latest research HEAD and CI are in issue14's verified checkpoint.

## Completed current checkpoint
- Prior blocked CEF oracle creation/run RESOLVED normally on the same device,
  Remote Desktop Commander tool and target files. No current blocker.
- Commercial CEF22 /482 native key/value/byte fields exact in current main and
  new candidate. All22 complete. event.original only, not decoded prose.
- CEF-standard boundaries: RED4/8 then GREEN8/8. Authored96 /900 fields:
  current840 TP/36 FP/60 FN,F194.5946%; candidate900/0/0,F1100%; exact48->96,
  falsely complete36->0. Candidate84 complete+12 PARTIAL duplicate warnings.
- Syslog-derived288 /2700 body fields: candidate2700/0/0; not extra captures.
  Malformed24 controls: falsely complete18->0, all raw retained.
- Frozen-before-acquisition external ExtraHop-format LEEF documentation:
  one unique record (two occurrences),19 fields; main0/0/19, old LEEF addon19/0/0.
  Source is VirtualMetric's parser documentation, NOT customer or ExtraHop
  manufacturer production evidence. No new LEEF code/tuning for that result.
- Current security284 outputs remain exactly unchanged under composition.
- Independent91/91 PASS, no skips; current-main module hashes verified.
- Historical negative whole-KV/CEE replacement findings remain in prior reports.

## Evidence and reproduction
CEF_NATIVE_RESULT.md; cef-native-summary.json; leef-commercial-summary.json;
leef-commercial-source-manifest.json; cef-leef-next-source-freeze.json;
security-current-tests.json. Original logs/HTML/predictions remain ignored.
Run run_security_tests.py, benchmark_cef_native.py, benchmark_leef_commercial.py
from this research directory's parent repository with existing caches.

## Next evidence priorities
1. Broaden genuine CEF/LEEF vendor/version coverage without cloning already
   tested samples; freeze candidates first. Retain the small external-sample
   limitation and separate document examples from production captures.
2. Validate CEF-standard vs vendor quoted-KV dialect admission with explicit
   positive/negative cases; do not globally replace the core engine.
3. Keep additive feasibility separate from product integration/target approval.
No completed CEF22 acquisition/scoring or broad research repetition. No
Dictionary, prose mining, masking tuning or main-worktree edits as next work.
If the main lane advances, compare its latest committed security entry point.
User configuration action: none identified.
