# Final bounded Auto Parser PoC — evidence-based closure

**Decision: ENGINE_POC_LIMITED / NOT QUALIFIED.** Do not claim `ENGINE_POC_PASS` or product/native target acceptance.

## Last bounded improvement

The selected Accuracy-First Multi-Pass engine remains based on `security_source.parse_security_source`. Added exact source-native Cisco ASA/FTD `connection_id` when a bounded decimal token immediately follows an explicitly recognized Built/Teardown TCP/UDP/ICMP connection grammar. This preserves the original byte span and PARTIAL status. Focused tests pass; the complete Python source-engine suite is **299/299 PASS**. No wholesale engine replacement or semantic guessing.

## Evaluation and immutable denominators

The original five-vendor fixture batch has **513 unique events** (Cisco ASA 261, SonicWall 220, CrowdStrike 15, SentinelOne 8, Zscaler ZIA 9). After the bounded repairs, **252/513 SOURCE_PARSED (49.1228%)**, **256 PARTIAL**, **5 RAW_ONLY**; source raw retained and parser exceptions zero. This is a *parser status rate*, not exact field F1, and is far below the pre-registered 95% event gate. Cisco ASA body grammar is the principal unresolved class. All 513 events have already been inspected and used for development and therefore **cannot count as a fresh post-fix blind holdout**.

Independent stdlib field/value/type/UTF-8 span oracle on the JSON-only subset: **32/32 exact events, 3,372 TP / 0 FP / 0 FN, F1 100%**, raw 32/32. This does not establish an all-vendor F1, nor qualify Cisco ASA/SonicWall or two fresh independent batches. No verified complete field gold exists for the entire 513-event set.

## Exit disposition

The strict `ENGINE_POC_ACCEPTANCE.md` PASS gate is **NOT MET**. In accordance with the owner's bounded final-improvement decision, stop open-ended engine PoC cycles here and freeze the best verified Multi-Pass candidate for Auto Parser integration. Remaining unsupported/partial regions must be surfaced with exact source spans in the product and routed through the two planned AI-assisted recovery cases: whole-log fallback for RAW_ONLY and selected-range repair for PARTIAL/wrong/user-desired fields. Those AI UI features and native Ruby/CONF parity have separate acceptance gates and are not claimed implemented by this PoC closure.

No raw upstream fixtures are committed; ignored private cache retains source provenance. No PR merge, release, DP/sensor or production writes authorized.
