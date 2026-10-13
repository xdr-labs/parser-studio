# Vendor Adaptive Engine — Standalone Research PoC (NOT a Product Feature)

**Owner-requested scope:** Engine and evaluation only, with NO Web UI changes, backend REST deployment, live DP/sensor operations, production release, or Ruby/CONF grammar compilation. This standalone Python script is **not** wired into the app.

## Source and reproducibility

- Repository: `xdr-labs/parser-studio`, standalone branch `poc/adaptive-vendor-engine`, based on UI Draft PR #7 at `5103ede1ff306e7cee809b5a26cd5d3ec1a13798`.
- Development host: `dev-atlas`. Working directory: `/home/aella/parser-studio-engine-poc-20261013`.
- Eight source datasets / 256 raw records: Fortinet FortiGate Traffic (13), Event (28), UTM (28); Palo Alto PAN-OS Traffic (100), Threat (76); Trellix EDR (1), ePO (3); Trend Micro Vision One (7).
- Actual raw events and per-event expected outputs are from upstream Elastic Beats and Elastic integrations. Exact immutable commit, public raw/gold URLs and SHA256 digests are in `manifest.json`.
- **Upstream contents are research-only / file-license-review pending (Elastic License / x-pack). Neither raw nor expected JSON files are committed.** Their bytes currently live in local ignored `poc/vendor_engine/.cache/` only. On a fresh checkout, reacquire public inputs only after reviewing relevant rights, confirm each SHA256 and restore the .cache filenames exactly. The Python corpus verifier rejects mismatched digests, malformed expected records and row-count mismatch. No source files can be redistributed from this project merely because their upstream URLs are public.

## Implemented (local POC, not native verification)

- Profile recognizer and type-aware parsing: Fortinet PRI+quoted KV, PAN-OS Syslog BSD+subtype positional CSV, nested strict JSON for Trellix EDR/ePO and Trend Vision One.
- Typed semantic mapping of source/destination IP and port; some user, URL and event.action fields; missing/unknown values are not treated as verified.
- Exact source byte-span provenance, unparsed-range accounting, fail-closed duplicate/unsafe JSON keys and malformed KV/CSV; API metadata/pagination records retained as STRUCTURED_UNMAPPED instead of silently dropped.
- Very simple residual fingerprint grouping is included as an exploratory baseline; **it is NOT actual Drain3, LLM grammar synthesis, JSONata mapping, learned vendor fingerprints, or a Stellar Ruby/CONF compiler**.

## Commands — run immediately on dev-atlas

```bash
cd /home/aella/parser-studio-engine-poc-20261013

# Verify exact local source/gold SHA256 and 256 input row alignment.
python3 poc/vendor_engine/corpus.py

# Run 13 independent Python tests, including source/negative/CSV/Unicode
# and public gold comparison tests when the local .cache is available.
python3 -m unittest discover -s poc/vendor_engine -p 'test_*.py' -v

# Reproduce current isolated Python engine gold-field evaluation.
python3 poc/vendor_engine/evaluate.py

# Run ACTUAL legacy browser Auto Parser preview against the SAME raw records,
# to preserve separate baseline counts; requires npm deps for the existing UI.
./node_modules/.bin/vitest run --config poc/vendor_engine/vitest.config.ts --reporter=verbose
```

If node_modules is not present on a fresh checkout, install the repo's pinned npm dependencies with `npm ci`. **Do not modify the original dirty UI checkout**.

## First verified findings (not a generalization benchmark)

- All **256** input records accounted from 8 source datasets. Reference expected outputs align with all 256 records, including goldless metadata/control rows.
- Current `createDraft()+preview()` *event-level* browser baseline on those rows: **80 extracted** and **59 normalized**. This is an unconfigured default, not its best manually tuned performance.
- This POC's **field-level micro average across six specified ECS-style roles**: 1,145 exact TP, 0 FP, 23 FN; precision **100%**, recall **98.03%**, F1 **99.01%**.
- Same-fixture last-half subset: 571 TP, 0 FP, 5 FN. **This is NOT a genuinely unseen vendor/product/version holdout**; do not call it independent evidence of learning or generalization.
- The profile algorithms were handwritten after inspecting these exact publicly documented formats; vendor pipelines' own expected JSON served as the gold source. Reported micro scores must not be interpreted as automatically invented parser success.
- No Ruby/Fluentd native verification, actual Stellar parser import, DP write, sensor IO, external AI, real Drain3 clustering, or JSONata execution in this PoC.
- Non-security response metadata is counted separately; `LOCAL_EXTRACTED` is browser/PoC-level typed extraction, not a claim of deployed semantics or a complete parser.

Aggregate **value-free** per-fixture and per-field checkpoint: `benchmark-summary.json`. Full local-only details, no original logs in Git: ignored `poc/vendor_engine/.cache/engine_result.json` and `current_baseline.json`.

## NEXT CHAT — FIRST UNFINISHED WORK (P0 ENGINE POC ONLY)

1. In the first tool action, inspect **this branch's exact HEAD**, `git status -sb`, the POC README, `manifest.json`, `engine.py`, `evaluate.py`, benchmark summary, and the latest Issue #1 PoC NEXT_CHAT_START. Preserve the protected dirty UI worktrees and Draft backend PR #4. Do NOT start an unrelated UI project or repeat broad GitHub research.
2. Build a **fair apples-to-apples field-level baseline** for existing Auto Parser, recording which six gold roles it finds and which it normalizes; keep separate from the unconfigured `80/256` extract-events metric. Avoid inventing a percent-improvement number.
3. **Critical experiment:** build a true *train/holdout-separated* syntax/field inference sublayer. First train on a limited, explicitly specified subset of public examples, then test unseen subtype/source variants, including negative cross-vendor cases, WITHOUT looking up gold during candidate generation. Record the exact train/test split and rule provenance. Existing hand-coded profiles must remain an explicit upper-control baseline.
4. Add a deterministic quote-aware/residual learner (e.g., string alignment and optional Drain3 after legal dependency review). Probe PBE rule synthesis on one wrong-span counterexample; preserve original bytes and never mark a raw catchall as fully parsed. Avoid pretending the current residual mask is Drain3.
5. Check discovery/qualification paths for more actual vendor families (e.g. Cisco ASA, Check Point, SentinelOne, CrowdStrike) **after** the rigorous initial 4-manufacturer evaluation. Respect fixture copyright/redistribution and gold alignment.
6. Finish with isolated RED→GREEN tests, exact pinned fixture digest checks, report aggregate precision/recall/false-positive/unknown, and commit/push the *PoC branch*. Update Issue #1 and its Draft PR with measured limitations. Keep all actual target/LLM/production/merge/release gates intact.

**This PoC is an exploration, not a requirement to replace the existing supported Ruby/CONF compiler.** The long-term typed IR v0.3 and JSONata mapping remain proposed design until independently verified.
