# Independent LEEF 1.0/2.0 byte-accurate source evidence (2026-10-17)

## Scope and provenance

This is a **separate isolated PoC** stacked on **Draft PR #47** exact HEAD `6a7ac861ed8b0398624798d52cd886cc47af0781`, itself stacked on PR #46 `ceb048f92b905a70b874ac40650ba54f7ede512b`. The product worktree at `da94aa9177c6b652eee47768efb98a9d47df8c5e`, main, other PRs and worktrees are unchanged. None of this source-only observer is product or native Stellar/Fluentd parser implementation.

The goal is not a manufacturer patch. It is a **generic source-layer grammar** for LEEF 1.0 fixed TAB and LEEF 2.0 explicitly declared delimiters, following existing bounded envelope/body/source-span/negative evidence principles. Every output remains lexical review, conservative abstention or original raw. There is **no automatic source-complete or native success**.

### Before-candidate-score sealed independent publisher sources

- **Two independently authored MIT-licensed projects with independently asserted positive values:** `cwccie/slogparse@6da59de84d4684a9dacb0c31f3263d3e2f7b0095` (fixture inputs plus explicit LEEF 1.0/2.0 header and extension assertions) and `aipd506/syslog-siem-correlator@a2ef7f177f7296990eb58ba9ba699d8cb8fe908f` (LEEF 2.0 caret-delimited original plus asserted field values).
- **Independent negative evidence:** `marirs/leef2hashmap-rs@bb806946312eeb96d46a52d14129ee7526a3c244` Rust tests, MIT.
- All **four original publisher test files / 15,929 bytes** pinned by commit/path/SHA-256 **before** generating goldens or inspecting any parser output. Source manifest SHA-256 `5a7643ebd377ae6f3d73fd3553bf7007bc7435528be2088a88580a5c9347d02d`. Public metadata in `scripts/poc/independentLeefSources.pinned.json`.
- Python reference parsed *only* pinned original fixtures and publisher-authored literal assertions, independently assigning original UTF-8 source byte positions and separately freezing a SHA-256 reference **before comparing PR #47 or the new adapter**. Golden SHA-256 `7c66600785630316ec29ae936048a78119def5060cceadb4276aa9cecbf41aff`. Public denominator/count metadata in `scripts/poc/independentLeefOracle.v1.pinned.json`.
- Originals, asserted field values, source replay oracles and raw messages remain private at `~/.local/state/parserstudio-independent-leef-20261017/` (0700 directories, 0600 files). **No raw test log, source field/value golden or private original is committed to Git or uploaded to GitHub.**

The **fixed denominator is three authentic publisher test originals and 23 independently asserted source name/value/UTF-8 byte triples**. There are **three separately asserted invalid controls**. All 23 goldens are *partial explicit publisher assertions* and do not include every possible source field in each event. Header/version/delimiter or unasserted extension values outside those expectations are **UNSCORED, not false TP**.

## Exact same-denominator accuracy

| Independently pinned source | Scorable original events | Expected triples | Preceding #47 observer TP | New LEEF observer TP | New FP / FN |
| --- | ---: | ---: | ---: | ---: | ---: |
| `cwccie/slogparse`: LEEF 1.0 TAB + 2.0 hex-TAB | 2 | 17 | 0 | **17** | 0 / 0 |
| `aipd506/syslog-siem-correlator`: LEEF 2.0 caret separator | 1 | 6 | 0 | **6** | 0 / 0 |
| **Total** | **3** | **23** | **0** | **23** | **0 / 0** |

The previous #47 source observer scored **0 TP / 0 FP / 23 FN**, zero exact original events; this new LEEF lexical observer scored **23 TP / 0 FP / 0 FN**, 3/3 exact **on the asserted subsets only**. The score improvement is restricted to a tiny new independently authored sample, and **does not demonstrate a broad previously unseen-device generalization rate or actual native parse correctness**.

The three externally asserted invalid originals remain **0 erroneous lexical REVIEW** in both stages. No automatically promoted results, no raw loss, and no branch bound violations were observed. Source-value byte slices are replayed on every claimed field. The product's existing parse-preview path was capable of returning a preview on the three originals, but does not expose comparable independently verified byte offsets here; it is **not counted in source TP nor claimed to improve**.

All **eight extra new candidate source claims without independently asserted expected values** remain explicitly UNSCORED. The chosen grammar does not infer device/profile mappings, decode unspecified escapes, promote stringified integer semantics, or interpret arbitrary unstructured bodies.

## Generic source mechanics and nonregression

The new pure `src/poc/independentLeefSource.ts` is a structurally bounded stage that delegates **every non-LEEF input** to the exact preceding CEF/Syslog/JSON arbiter without mutation. LEEF 1.0 accepts only its standard TAB-separated named body; LEEF 2.0 uses an explicit bounded delimiter declaration (hex-TAB or supported safe single-character delimiters). It independently observes original header names, lexical extension key/values, source byte ranges and repeated-field occurrence paths. Original producer vocabulary and bytes remain untouched.

Partial/malformed header, unsafe control characters, invalid delimiter declaration, ambiguous unknown quoting/escaping, oversized source and incomplete body all fail closed to source-raw preservation or header-only review with `bodyReviewEvidence=NOT_PROVEN`. A caller-supplied positive profile assertion can never promote source or native success; negative independent profile/source VETO is inherited unchanged and stops the lexical stage.

Safety-only replay (not reused as new source-accuracy holdouts):
- **1,361 previously pinned source originals + 2,892 historic invalid mutations:** zero newly reviewable invalid cases, zero newly reviewable original cases, zero source-byte drift, zero invalid veto bypass, zero auto promotions and zero attempts beyond 8.
- **Previously independently scored non-LEEF CEF/Syslog originals:** all **19** source events yield byte-for-byte identical observer results to PR #47; no reclassification or new evidence claims.
- **197 / 2,892 historical malformed lexical REVIEW proposals from earlier stages remain unresolved**; the new LEEF stage did not eliminate or falsely certify them.
- Local focused typecheck/unit tests, complete Vitest/build and **GitHub Actions exact pushed HEAD** including Chromium user paths and real loopback backend HTTP integration are necessary before calling any new Draft PR validated.

## Reproduction (original private source oracles required)

```bash
python3 scripts/poc/pinIndependentLeefSources.py
python3 scripts/poc/freezeIndependentLeefOracle.py
node_modules/.bin/vite-node scripts/poc/scoreIndependentLeefSource.ts
node_modules/.bin/vite-node scripts/poc/runIndependentLeefSafetyReplay.ts
node_modules/.bin/vitest run src/poc/independentLeefSource.test.ts src/poc/independentNonJsonStructural.test.ts src/language-policy.test.ts
npm run typecheck
npm test
npm run build
```

The independent oracle is **not** generated from candidate outputs, and private original sources are not transmitted through CI. CI separately verifies deterministic tests, TypeScript/build, real Chromium and pinned localhost HTTP paths.

## Limitations and remaining runnable generalization

Three independently authored originals are not a statistically meaningful cross-device sample. CEF escaped-value semantics, LEEF exporter-specific wire profiles, arbitrary quoted KV delimiters, unlabeled/quoted CSV, multirecord transport framing, malformed-message review false-positive risk, and actual Stellar/Fluentd execution remain **NOT_CERTIFIED / NOT_VERIFIED**. Later PoCs must first pin new legal third-party **original + separately authored expected values** for quoted KV/CSV/mixed-envelope edge cases, and explicitly retain UNSCORABLE for all absent or ambiguous source truth. Do not tailor an escape-rule patch to individual manufacturers or rewrite pre-existing expected values to make a candidate pass.

Product **R1–R4 remains strictly handoff-only**: Juniper residual/Defender compiler/Umbrella quoted CSV, beginner progress, owner visual Review → Map → Create acceptance/mobile, and exact-head release E2E/owner gate. None of those tasks was implemented or authorized through this PoC. No main, product, DP/sensor, deploy, credentials, release or merge.
