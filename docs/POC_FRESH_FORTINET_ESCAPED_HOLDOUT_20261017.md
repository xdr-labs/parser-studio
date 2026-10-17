# Unseen Fortinet Original Escaped-KV Source Holdout — October 17, 2026

**Status:** independent third-party source-only validation; **NOT** manufacturer semantics, native/parser target qualification, product implementation or release.

## Pinned provenance / privacy

A previously unused public input fixture and its accompanying upstream expected output were pinned before the unchanged product and PoC lexer were evaluated:

- Repository: `elastic/integrations`, exact revision `ee918d03f4a90dacd32673546c64a633308796ef`.
- Upstream source: `packages/fortinet_fortigate/data_stream/log/_dev/test/pipeline/test-fortinet-fix.log`. SHA256 `4194fdcd7d83df764eadb04e436c3a23247405c8a5995a473f9a57290cb31cef`.
- Upstream expected output: `test-fortinet-fix.log-expected.json`. SHA256 `14c1d87ce96b764019c0acff98165f17a6c134487a9ec39cbdc1a41d4d0284ae`.
- Original logs, upstream JSON expectations, and frozen independent Python original field/value Oracle remain private with mode0600 under `~/.local/state/parserstudio-fortinet-escape-source-discovery-20261017/`. No original field names/values, customer data or log bytes are committed or printed.

There are **4 distinct physical original records**; each aligns to its upstream expected event by **4/4 event.original SHA**. Original record SHA overlaps with previous frozen Elastic 222, third-party Fortinet 1,002, SonicWall 61, and versioned Fortinet 113 are **zero**.

The independent bounded Python source KV grammar, frozen *before* product/candidate output scoring, qualified **3/4 original records**, **125 original source KV name/value tokens**, including **one** field containing a source backslash. The fourth event is **UNSCORABLE**; never infer its expected field boundaries or count its product candidate as exact. The source-only Python Oracle refuses unsupported prose, duplicate keys, unsafe/malformed quotes, and control-containing originals.

## Strict actual product vs proposed PoC source equality

| Independently qualified original-source metric | Candidate PoC lexer | Existing Fortinet source-contract path | Existing generic KV path (separate, not fallback) |
| --- | ---: | ---: | ---: |
| Expected source fields | 125 | 125 | 125 |
| Exact original name+value TP | **125** | **125** | 0 |
| Wrong name/value FP | **0** | **0** | 0 |
| Missing original FN | **0** | **0** | 125 |
| Full exact original events | **3/3** | **3/3** | 0/3 |
| Exact qualified source value with backslash | **1/1** | **1/1** | 0/1 |

The existing Fortinet product projection and the candidate are both **source exact** on this *new* set. That is **non-regression evidence**, not evidence of a product change or additional recovery gain. The unrelated original Elastic 7.2 source escaped-punctuation mismatch (**FP1/FN1 in current product**) remains unresolved in product code; the candidate improvement there is previously studied evidence.

The upstream normalized `fortinet.firewall` vendor field map **does not contain the new escaped source key**, so its intended semantic value cannot be independently validated against manufacturer or upstream normalized field results. Exact lexical source preservation alone must **not** be promoted to manufacturer semantics, complete native compatibility, Stellar Dictionary approval, or generalized accuracy. The source has been pre-inspected for backslash presence to select this targeted test; it is not a randomized vendor-production holdout.

The fourth excluded original is rejected by both the conservative candidate and current parser. Malformed quoting and in-event form-feed negative controls remain fail-closed.

## Reproduction and gates

```bash
python3 -m unittest discover -s scripts/poc -p 'testFreshFortinetEscapeOracle.py' -v
python3 scripts/poc/createFreshFortinetEscapeOracle.py
node_modules/.bin/vite-node scripts/poc/runFreshFortinetEscapeHoldout.ts
npm run typecheck
npm test
npm run build
```

Tests reuse exact pinned source/expected-output SHA, full original record count, explicit scored/unscored denominator, and independent source-vs-parser name/string-value equality. Never use model-generated expected values or normalize source keys into a false complete.

**Next qualification:** independently sourced and manufacturer-format-specific *unknown escaped punctuation* with a verified expected original source-value reference, then all previously required 571/790, Juniper/Sophos and adversarial gates if the actual product parser is ever changed. Keep this PoC stacked and Draft; no product/main/DP/sensor/deployment changes.
