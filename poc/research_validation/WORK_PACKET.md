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

## Latest executed checkpoint — authoritative over initial plan

Comparison complete for H1/H2 against both initial acc3a90 and concurrently advanced 2fee28f. Preferred slice is current engine plus guarded H2; do NOT replace the full engine or current KV. See EXECUTION_RESULT.md and selective-h2-summary.json. The full prototype remains unqualified: 12/13 candidate tests pass and one malformed-metadata test errors. External Zeek corpus was acquired but its scoring assertion is unresolved. The candidate guard patch and external accounting patch each hit two security-state denials including same-tool retry; no bypass performed. First remaining action is to retry those exact narrow operations under newly permitted conditions, then score external data. Existing main ACTIVE packet is not superseded.
