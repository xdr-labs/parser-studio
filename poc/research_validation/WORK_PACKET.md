# Independent extraction validation PoC

Status: ACTIVE. Owner explicitly requested a separate verification PoC and an apples-to-apples comparison with the current engine on 2026-10-14.

Implementer: CHATGPT_CHAT, Chat mode, dev-atlas.
Baseline: acc3a903e19597af44635b243fa4be3b4949e35f, the actual local/remote PR13 head at start. Main PoC and its untracked test_source_kv.py are not edited. Only poc/research_validation/ may change. No production, UI, Dictionary work, hosted AI, credential changes, merges or releases.

## Bounded experiment order
1. Freeze baseline and create independent exact field/value/byte-span scoring.
2. Compare occurrence-preserving lexical KV, raw-only multi-sample dialect inference, and explicit source-metadata import. These are research-inspired prototypes, not reproductions of every cited paper.
3. Run independent generated conformance cases and already pinned actual-source compatibility corpus separately. Freeze candidate before first external source read; evaluate additional upstream logs independently. Preserve negative results, unknown source-redaction status and all denominators.
4. Run safety/negative/metamorphic regressions, ablations and timing; publish aggregate-only evidence.
5. Commit/push separate draft PR, verify remote and CI, append comparison to Issue1 without replacing its ongoing ACTIVE packet.

## Acceptance
No baseline source edits; raw records retained; source fields include constant values; false-positive fields and falsely complete records are counted. No universal accuracy or new-vendor generalization claim from synthetic or familiar corpus scores. No raw fixtures, learned customer templates or credentials committed. Only proposed adoption if measured evidence supports it.

## Latest executed checkpoint — H2r follow-on

Main comparison remains exact 2fee28f; the main worktree now has 14 untracked body-alignment experiments, preserved and NOT included. H2r is independently implemented in layout_inference.py and tested; no main engine files changed. Authoritative current evidence: NEXT_POC_RESULT.md, layout-comparison-summary.json, flow-source-manifest.json and layout-baseline-integrity.json.

New-source AWS-format upstream fixtures: 33 physical = 11 train + 21 heldout + 1 JSON control; zero exclusions. Current and previous H2 have 0/638 correct fields on the 21 space records; H2r has TP506/FP0/FN132, F1 88.46%, exact16/21. Candidate frozen before new source acquisition. These are Elastic regression fixtures, not verified production data or unmasked-only evidence. Five rare/untrained cases remain RAW_ONLY and count as misses.

New authored conformance240: main F1 14.81%, previousH2 39.02%, H2r93.88%. PreviousH2 false COMPLETE72 -> H2r0, but H2r still emits72 false positional proposals on source-switch prose; that is24 more FP than main. Do not present this as globally safe or hide partial predictions. Prior264 remains main67.47% / H2,H2r93.20%; known256/14645 and mainKV128/352, JSON128/512 plus64 routing probes remain unchanged.

H2r focused15/15 PASS; complete independent suite32 PASS/1 ERROR. H3 malformed-metadata error remains. Same candidate.py guard and benchmark.py Zeek-accounting edits were blocked again on two normal same-tool/dev-atlas/path attempts; unchanged hashes prove no edits. No bypass. A distinct H2r implementation retry succeeded normally and does not call or replace H3/Zeek. Do not re-label old Zeek data as scored.

Next: normally retry the same H3 operations under permitted current conditions; otherwise continue the separate ambiguity/rare-source validation without bypass. Preserve frozen first-pass negatives; no broad research repeat, no H1 replacement, no production, integration, merge or release. User configuration action: none identified.
