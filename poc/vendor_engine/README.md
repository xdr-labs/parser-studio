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
- Very simple residual fingerprint grouping is included as an exploratory baseline; **it is NOT actual Drain3, LLM grammar synthesis, JSONata mapping, or a Stellar Ruby/CONF compiler**. A separate train-only experimental supervised grammar learner is implemented in `learn.py`, below.

## Commands — run immediately on dev-atlas

```bash
cd /home/aella/parser-studio-engine-poc-20261013

# Verify exact local source/gold SHA256 and 256 input row alignment.
python3 poc/vendor_engine/corpus.py

# Run 24 independent Python tests, including source/negative/CSV/Unicode
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

Aggregate **value-free** per-fixture and per-field checkpoint: `benchmark-summary.json`. Full local-only details, no original logs in Git: ignored `poc/vendor_engine/.cache/engine_result.json`, `current_baseline.json`, `isolated_train.json`, `split_index.json`, `frozen_grammar.json`, and `learned_result.json`.

## P0 experimental comparison — implemented, isolated PoC only

`compare-current.test.ts` invokes the **actual unmodified** `src/parser.ts`
`preview(createDraft())` against all 256 identical pinned source records and reads
the same six upstream gold roles used by `evaluate.py`. The 1,168 gold-role
occurrences are scored separately for (a) exact ECS-role extraction directly
in browser source fields and (b) normalization to those roles. Both are 0 TP /
0 FP / 1,168 FN with the default `custom.*` mappings. A third diagnostic
finds 282 occurrences of matching **unassigned raw values**; these are **not**
proof of correct source/destination semantics. The older `80/256` extracted
and `59/256` normalized *event* counts are NOT field-level metrics or an
apples-to-apples tuned-parser comparison.

`learn.py` uses three explicit, separate stages:

```bash
# Run from repo root. Raw/gold .cache files must first pass corpus.py.
python3 poc/vendor_engine/corpus.py
python3 poc/vendor_engine/learn.py prepare  # indexed split; train labels ONLY
python3 poc/vendor_engine/learn.py fit      # cannot read upstream gold
python3 poc/vendor_engine/learn.py evaluate # verify frozen SHA, THEN read holdout gold
python3 poc/vendor_engine/report.py         # publish COUNTERS ONLY
python3 -m unittest discover -s poc/vendor_engine -p 'test_*.py' -v
./node_modules/.bin/vitest run --config poc/vendor_engine/vitest.config.ts --reporter=verbose
```

`prepare` deterministically partitions fixtures by a SHA256 sort within
vendor/subtype strata. The existing hand-written recognizer is used only to
form split strata, **never to train** the grammar. Rare singleton subtypes
are sometimes entirely withheld. `fit` receives only the isolated
`.cache/isolated_train.json` with train labels, infers syntax-sensitive
guard features, source paths, transformations, categorical action translation,
and source spans; it writes a digest-frozen grammar. `evaluate` checks the
candidate/split/train digests before loading any holdout reference outputs.
No external AI service, Drain3, dependency installation, native export,
deployment, or network traffic is involved. All interim raw/learned rules
remain ignored under `.cache/`.

### Measured reproducible results — same upstream files, NOT new releases

| Six-role comparison | Records | Gold-role values | TP / FP / FN | F1 |
| --- | ---: | ---: | --- | ---: |
| Current browser default, ECS normalized | 256 | 1,168 | 0 / 0 / 1,168 | 0.00% |
| **Auto-learned, exploratory value agreement, frozen holdout** | **100** | **446** | **433 / 0 / 13** | **98.52%** |
| Auto-learned, **strict unique-path + supported-role gate** | 100 | 446 | 299 / 0 / 147 | 80.27% |
| Manual fixture-profile upper-control, **same holdout** | 100 | 446 | 436 / 0 / 10 | 98.87% |

Training: **156** rows, holdout: **100** rows, eight syntax/role grammar profiles.
On the holdout, 98 records routed to their own learned grammar; 2
abstained, 0 cross-fixture/other-vendor grammar activations, 0 ambiguous
simultaneous routes. Zero-shot subtype field checks remain part of the
holdout, not evidence of new product/version generalization. The Trellix
EDR set has **one record**, so it provides NO independent holdout evidence.

**Critical ambiguity:** 134 tentative field observations agree by VALUE with
holdout gold but have indistinguishable training source aliases (e.g.
original vs translated/NAT destination IP). They are never certified in
strict mode. Exact match on a particular holdout is not semantic proof.
The strict gate also suppresses source-role rules supported by only one
training example. Prior manually profiled 1,145 / 0 / 23 across all 256
remains an in-sample upper-control, NOT learned performance.

`test_learn.py` covers train-only fitting, signed rule integrity, real
disjoint splitting, wrong-vendor negatives, unseen subtype action abstention,
synthetic PBE disambiguation of a NAT decoy, invalid IP/port, malformed
quotes, and precise source accounting. `test_report.py` verifies aggregate
allowlisting without redistributing licensed raw logs or learned literal
lookup tables. `benchmark-summary.json` contains **only value-free
aggregates**, while all exact samples, gold and profile data remain local
and ignored. No browser code or backend product behavior was changed.

## Train-only span-feedback probe (synthetic, not a product UI)

`span_feedback.py` accepts a **source-index-bound training record**, one
explicit positive source path with exact UTF-8 byte offsets, and every
competing negative source path with its own byte offsets. It verifies the
original train-data digest, frozen grammar digest, role allowlist, gold
agreement on the **training row only**, unique matching grammar, and full
exclusion of the tied alternatives. A successful operation creates a new
immutable digest-bound candidate and changes only the corrected role.
Wrong byte offsets, duplicate/contradictory negatives, unsupported roles,
non-training record indices, and corrupted frozen rules fail closed.
Three additional synthetic unit tests prove the intended behavior,
including Unicode byte-span handling and preservation of the original rule.

This is a **human-feedback contract experiment**. No genuine owner-provided
span corrections have been collected or applied to the pinned vendor train
set; the held-out metrics remain unchanged. A synthetic positive/negative
assertion is NOT evidence that a NAT alias has the real-world correct role.

## Remaining research-only gaps (in priority order)

1. Improve **strict** accuracy using separately approved/confirmed real
   positive and negative source-span corrections when two train paths are
   value-equivalent. The bounded synthetic feedback mechanism is built,
   but it cannot invent missing semantic ground truth. Never treat a raw
   `<*>` template or inferred positional alias as an identified role.
2. Secure separate, license-reviewed **new upstream fixture revisions** and
   rare subtypes; evaluate entire unseen source versions with frozen grammar
   rules rather than claiming a same-fixture split is universal coverage.
3. Only if a residual text cluster demonstrably benefits, add a deterministic
   token-alignment/span grammar learner with held-out counterexamples.
   Residual template grouping remains just a grouping, **not Drain3**.
4. Profile latency, memory and malicious-input limits, then separately
   assess supported export/compiler feasibility. Native Ruby/CONF or Stellar
   DP/sensor testing remains out of scope and unverified.

**Preservation:** Stay on isolated PoC branch and worktree. Do not overwrite
UI/backend worktrees, redistribute copyrighted fixtures, activate external
providers, merge PRs, upload to DP, transmit to sensors, or release.
This exploratory engine is not a production replacement for the existing
Ruby/CONF compiler.
