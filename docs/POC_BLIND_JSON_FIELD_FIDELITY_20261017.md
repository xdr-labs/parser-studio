# Frozen Public JSON Field Fidelity Holdout — Independent Oracle (2026-10-17)

## Question and strict scoring scope

Can the **unchanged, already-qualified** Parser Studio extraction pipeline
preserve each original field path and scalar value from a **separately frozen
set of public JSON security logs**?

This is field **source extraction**, not Stellar normalized field mapping,
native Ruby/Fluentd parser execution, DP import, or future-vendor performance.
This PoC adds test/oracle/scorer code, not a new parser acceptance fallback.

## Source identity and independence

- Public source: Elastic Integrations, commit
  `ee918d03f4a90dacd32673546c64a633308796ef`.
- Nine previously unused public fixture files from six source families;
  separate frozen event corpus SHA-256:
  `153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32`.
- **222 total logical events**. Existing parser baseline structurally accepted
  **217/222** with original event raw preserved **217/217**.
- A strict independent **Python `json` oracle**, not derived from the
  TypeScript parser's extracted fields, identified exactly **22 JSON-object
  events** from Zscaler ZIA (7), Suricata (14), and AWS (1).
- All JSON source events are pinned to their exact original SHA-256. Python
  rejects duplicate source JSON object members, unsafe keys, nonfinite values,
  oversized integers outside JavaScript's exact range, empty source leaf sets
  and excessive depth. JSON Pointer escapes preserve literal nested names.
- Original logs, source leaf maps, raw source fields, and independent
  per-event results remain exclusively in the permission-restricted
  `~/.local/state/parserstudio-lossless-blind-20261017/` directory.
  **No raw logs or independent expected values are committed.**

The Python independent-source oracle was created *after* the source file
selection was frozen but independently of the parser extraction result.
The source families were already known to the parser. Therefore this is a
**file-held-out, in-family test**, not an unbiased sample of entirely
unknown future vendors or firmware versions.

## Definitions — no inflated partial success

Each scalar leaf has an exact escaped JSON Pointer and its original value
including the primitive **type** (`string`, finite `number`, `boolean`,
or `null`). The separately implemented TypeScript comparator evaluates:

- **True positive:** the source path and original scalar type/value agree.
- **Missing:** a source path is not emitted.
- **Mismatched:** an existing path has a different type or value; counts as a
  **false positive and a false negative** for exact-value Precision/Recall.
- **Unexpected:** output has a path absent from the source.
- **Whole-structure equality:** object nesting, arrays and empty containers
  are identical. This separately closes any blind spot where no scalar leaf
  represents an empty object or empty array.

Precision denominator = all emitted scalar leaves;
recall denominator = all independently identified source scalar leaves.
Failed or invalid JSON parsers cannot score as correct by abstention: a
missing output yields zero true positives for all source leaves.

The remaining **200 non-JSON events have no independently verified source
field-value oracle in this test**, and are excluded from both field denominators.
They are not considered accurate or inaccurate by this JSON-only measurement.

## Actual result

| Source family | JSON documents | Original leaf fields | Exact path/type/value matches |
| --- | ---: | ---: | ---: |
| Zscaler ZIA | 7 | 508 | 508 |
| Suricata | 14 | 349 | 349 |
| AWS | 1 | 25 | 25 |
| **Total** | **22** | **882** | **882** |

- Source-field Precision: **882/882 = 100%** within this scored subset.
- Source-field Recall: **882/882 = 100%** within this scored subset.
- Full original JSON object structure: **22/22 exact**.
- Incorrect original values: **0**; missing paths: **0**;
  extra emitted paths: **0**.
- The 222-event baseline remains **217 structurally accepted**, all **217
  source raws preserved**.
- **No new automatic parser acceptances**, no semantic normalized mappings
  certified and **no native/target runtime verification**.

This is a strong **exact JSON source extraction** result for the frozen
published files. It is not a blanket 100% Auto Parser accuracy statement
across general security logs, non-JSON families, or Stellar runtime output.

## Reproduce from the isolated PoC worktree

```sh
python3 scripts/poc/fetchLosslessBlindCorpus.py
python3 scripts/poc/createBlindJsonFieldOracle.py
python3 scripts/poc/testBlindJsonFieldOracle.py
npx vite-node scripts/poc/runBlindJsonFieldFidelity.ts
npx vitest run src/poc/jsonFieldFidelity.poc.test.ts
npm test
npm run typecheck
npm run build
```

Oracle files are immutable once frozen: any SHA or expected sample count
change must fail closed rather than overwrite existing independently
sourced reference data. No credentials, production logs, target DP,
authorized sensor, or live parser execution are involved.

## Next accuracy milestone

Independently source-certify the **non-JSON** event dialects, not merely
increase permissive fallback success: require original field/value oracles,
negative mutations, unknown-source safe abstentions and field-level
Precision/Recall on new vendor/firmware fixtures. Explicitly separate
structural identification, raw extraction, typed component decomposition,
semantic Stellar dictionary mapping and native parser execution.

Any product integration requires opt-in bounded Multi-Pass acceptance and
separate browser/native Full User E2E on the same exact HEAD.
