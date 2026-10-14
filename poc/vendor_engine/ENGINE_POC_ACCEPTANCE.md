# Parser Studio Engine PoC — Pre-registered Exit Gate

Scope: security-system source field extraction (not natural-language logs, Dictionary semantics, Ruby/CONF, DP or sensor E2E). Candidate is the frozen accuracy-first Multi-Pass parser, based on the existing security-source engine.

**PASS requires all of the following, measured on a genuinely new, independently referenced security corpus frozen before parser inspection:**

1. At least 500 unique source events from at least five security products, at least three format families, and at least two product/version or event-type variants not used in engine development. Deduplicate by raw SHA; derived whitespace/field-order mutations, generated events and previously exposed fixtures cannot count toward the 500.
2. Independently annotated native field path, exact typed value and UTF-8 source byte span: micro F1 >= 99%, and complete exact-event rate >= 95%, both with every eligible event in the denominator. Publish per-product breakdown and exclusions; exclusions cannot count as passes.
3. Zero false-complete events, zero original-byte loss, zero parser crashes and zero unbounded CPU/memory/recursion; unresolved events must remain PARTIAL/RAW_ONLY with raw preserved.
4. No regression on frozen existing corpus and full source-engine unit suite PASS. Exact final Git HEAD CI SUCCESS.
5. Two independent evaluation batches with no newly observed P0/P1 extraction defects. Any correction must be followed by a new unexposed batch, never by promoting the repaired training sample to a fresh holdout.

If a criterion is not demonstrated, the gate is **NOT QUALIFIED** (not PASS). If a measured threshold fails, it is **FAIL** and requires RED -> minimal correction -> regression -> genuinely fresh holdout. Product integration may use the selected candidate as an engineering input, but does not turn this independent acceptance gate into PASS.

Source license/provenance, SHA manifest, evaluator/reference independence, no raw-data redistribution and masking priority-last are mandatory.
