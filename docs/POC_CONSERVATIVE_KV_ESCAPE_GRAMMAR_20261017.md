# Conservative KV Quoted-Escape Grammar — Independent PoC (2026-10-17)

**Status:** SOURCE-ONLY ISOLATED POC / **NOT PRODUCT QUALIFIED**. Branch based on Draft PR #37; no modifications to the existing product `strictKeyValues`, `parseSecurityInput`, Multi-Pass Funnel, main, product branches, native adapters, DP, sensors, deployments or UI.

## Root cause and evidence

The existing general-purpose `strictKeyValues` unconditionally removes a backslash preceding **any** following character. A previously frozen Elastic Fortinet original source field inside a double-quoted string retains a backslash before an unrecognized punctuation escape according to the independent lexical Oracle; the existing decoder removes it. This is the **one** previous source field mismatch (FP 1 + FN 1) across the 185 qualified non-JSON Elastic records.

A separate upstream expected-output reference exists for the exact same seven Elastic original records:

- Upstream public source: `elastic/integrations@ee918d03f4a90dacd32673546c64a633308796ef`
- Expected reference path: `packages/fortinet_fortigate/data_stream/log/_dev/test/pipeline/test-fortinet-7-2.log-expected.json`
- SHA-256: `bb6b797f98987db075899ad4eeea5adc3e7a884b959820aa7082ebcaf3eaef36`
- Seven expected events align to the seven original input records by **7/7 exact `event.original` SHA-256**, with no raw bytes printed. All 99 source key names also retained in upstream `fortinet.firewall` have **99/99 exact values** versus independent Python Oracle. The **one disputed quoted-escape value** matches the Python Oracle and differs from the current product decoder.

This improves confidence in the root cause. The upstream reference is **maintainer-authored expected output, not a manufacturer-certified escaped-value protocol**; it is not a new blind holdout (the same seven records were previously studied).

## Candidate design

A separate bounded lexer `conservativeKvFields` supports only independently recognizable PRI+KV, yearless RFC3164+KV, and bare-KV sources. It uses source key identity directly and never performs Stellar semantic mapping or native output generation.

- **Double-quoted values:** Decode only recognized escaped quote and backslash characters. Preserve unknown backslash sequences literally instead of stripping the backslash.
- **Single-quoted values:** Treat string content literally; refuse embedded backslash ambiguity rather than guessing.
- **Unquoted values:** Retain already-qualified lexical escape behavior (backslash escapes next character), with strict token boundaries.
- Preserve original key case; reject canonical key collisions, duplicates, unsafe keys, fused quote/unquoted fragments, malformed PRI or yearless headers, unkeyed prose, invalid control characters, oversized values, excessive tokens and oversized input.
- No first-match-wins or vendor-specific regex patch. No timestamp year/timezone synthesis. Never reinterpret source semantic fields.

## Frozen independent comparison (same known corpus, *not a fresh escape holdout*)

| Cohort | Original fields | Existing exact | PoC candidate exact | Candidate wrong/missing/extra |
| --- | ---: | ---: | ---: | ---: |
| Previous Elastic SonicWall | 3,869 | 3,869 | 3,869 | 0 |
| Previous Elastic Fortinet | 291 | 290 | **291** | 0 |
| New third-party Fortinet bare KV | 11,848 | 11,848 | 11,848 | 0 |
| New third-party SonicWall original RFC3164 | 759 | 759 | 759 | 0 |
| **All independently qualified source fields** | **16,767** | **16,766** | **16,767** | **0** |

- **Original complete source KV events:** current parser **1,245/1,246**, candidate **1,246/1,246**.
- **Candidate field FP/FN:** both **0**, versus previous 1 FP / 1 FN.
- **Two SonicWall source-ambiguous originals remain unscored; candidate rejects both.** They are not silently converted to exact successes.
- **Candidate rejects 0/1,246 qualified originals.** Current product engine remains unchanged; no additional target semantics inferred.
- **New synthetic adversarial tests: 12/12 PASS**, including unknown escape preservation, recognized quote/backslash decoding, duplicate/colliding names, malformed quotations and bounded resource behavior.

**Decision:** Evidence supports this generic lexical rule as a *promising improvement*, but **not yet approved for product integration**. The existing dataset has been previously reviewed, and the new 1,002-event Fortinet fixture includes only two ordered key schemas and no escaped source values. A genuinely **new manufacturer-format/transport-specific escaped-string holdout** and independent correct-value oracle are required to qualify the change. Afterwards, check mandatory old 571/790 original source holdouts and Juniper/Sophos negative/regression gates on any implementation branch before promotion. Semantic/Stellar/native acceptance remains a separate gate.

## Additional pinned, previously unused FortiOS 6.2 / 7.4 version-source qualification

After freezing the first comparison, an additional **version-targeted source set** was obtained from separate files in the same pinned public Elastic repository revision. These were not part of the 222-event original blind corpus nor the previously assessed 1,002 new Fortinet bare-KV originals, but are **not a randomized new escaped-value holdout**.

- Original upstream files pinned to `ee918d03f4a90dacd32673546c64a633308796ef`:
  - `test-fortinet-7-4.log` SHA-256 `ef04aa4d229c924ee2a0fd44923cbe412392ea40a37b083ba756857d7a671d97`.
  - `test-fortinet-6-2.log` SHA-256 `6bc2d9721c7b386ce2c499ab3bb50e08845625b78ae0076730a02ca6929ed8e6`.
  - `test-fortinet-unsanitized.log` SHA-256 `9d7aad944899837bd88872f8a7449d44c3b2816e4f7c0a1fc7900bca863a2108`.
- Source records are **141 physical**, then **28 SHA-identical originals shared across version files are excluded**, resulting in **113 distinct originals**. Exact overlap with the previous independent datasets: **0**.
- Independent Python source lexical qualification: **64/113 events**, **2,077 original key/value fields** (47 events / 1,491 fields from 7.4; 17 events / 586 fields after deduplication from 6.2). **49 original events remain UNSCORABLE**, not inferred or included in correctness denominators. Distinct source field-key layouts: 36 in the 7.4 file and 14 in the deduplicated 6.2 subset.
- **Candidate source lexical result: 2,077/2,077 name+value exact**, FP 0, FN 0, 64/64 complete source KV events. The previous generic and Fortinet fixed-contract paths are measured **separately**, never post-hoc selected/unioned as a success metric. Structural acceptance of 45 independently unscorable originals by the candidate does **not** mean their source-field values were verified.
- The unsanitized file contains form-feed controls inside physically distinct logs. Python's broad `str.splitlines()` would incorrectly split **2 physical records into 4 pseudo-records**. The new private Oracle instead uses **only CRLF/LF/CR** boundaries and rejects unsupported embedded source controls before qualification. The preliminary pseudo-line Oracle was **not used for scoring**; its private bytes were preserved for audit, and the corrected reference is frozen separately as `oracle-versioned-fortinet-kv-physical.json` (mode 0600).
- The additional version fixtures do not independently settle the exact manufacturer's unknown escaped-punctuation semantics. No native/Stellar or product acceptance is granted.

After deduplicating across only the **independently qualified** source data sets, the PoC candidate has **18,844/18,844 original lexical source field matches** across **1,310 qualified events**. These are constrained source-corpus accounting metrics, **not** a general parser success-rate claim; the separate 2+49 unscorable original events remain explicitly excluded.

New reproduction steps (private pinned originals must exist and match their SHA-256 values):

```bash
python3 -m unittest discover -s scripts/poc -p 'testVersionedFortinetKvOracle.py' -v
python3 scripts/poc/createVersionedFortinetKvOracle.py
node_modules/.bin/vite-node scripts/poc/runVersionedFortinetCandidateHoldout.ts
```

## References and reproduction

Fortinet distinguishes FGT and RFC5424 forwarding; its FortiAnalyzer advisory describes additional backslash escaping in newer forwarding modes. This is **not** proof all log bodies follow one universal escaping grammar.

- https://docs.fortinet.com/document/fortianalyzer/7.6.1/cli-reference/859805/log-forward
- https://community.fortinet.com/fortianalyzer-6/troubleshooting-tip-fortianalyzer-log-forwarding-issue-with-syslog-format-causing-parsing-errors-216136
- https://docs.fortinet.com/document/fortigate/7.4.3/fortios-log-message-reference/357866/log-message-fields

Re-run the isolated source oracle comparison on dev-atlas; all raw source files and expected field/value references remain in private mode-0600 paths outside Git:

```bash
node_modules/.bin/vitest run src/poc/conservativeKvGrammar.test.ts
node_modules/.bin/vite-node scripts/poc/runConservativeEscapeCandidate.ts
npm run typecheck
npm test
npm run build
```

All displayed/reportable results are aggregate counters, source hashes, qualifications and repository paths only. No customer data, raw source value, vendor-specific field example from the private fixtures, credentials, or private oracle is exposed.
