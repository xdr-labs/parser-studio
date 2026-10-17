# Independent RFC3164/RFC5424 source-fidelity generalization PoC

Date: 2026-10-17. Scope: isolated evidence only, stacked on Draft PR #44 (base HEAD 25e0c8cab14b1fd5f98b865f58d7d32780936ab8). The qualified Multi-Pass, Generic Structural and bounded Funnel engine remains unchanged. No product, main, DP, sensor, credentials, deployment, native target, release or PR merge.

## Independent upstream sources frozen before parser scoring

The source selection and original-file SHA-256 were fixed before either baseline or candidate scoring. See scripts/poc/syslogConformanceSources.pinned.json.

- influxdata/go-syslog commit 66067a10754ae90b9540d5312989ae685413c4fe (MIT), RFC3164 and RFC5424 test inputs WITH upstream expected parsed fields, development-only.
- open-telemetry/opentelemetry-collector-contrib commit 7c913688e177b4f76270b9a04f5eef3f48e5008f (Apache-2.0), independently authored Syslog inputs and expected output fields, sealed cross-repository holdout.

Original 3 source files, 79,146 bytes, SHA manifest 13292cc6d04f0f80f9a377ac0948c06f07c31703e97b99a94391f92e31dc02a2.

An independent Python tokenizer extracts only static original Go byte literals, their independently authored upstream expected field names/values, and source-exact half-open UTF-8 byte ranges. No Parser Studio candidate output is used to generate expected values. Dynamic inputs, ambiguous byte encodings, or missing complete independently comparable source truth are marked UNSCORABLE. Invalid Go-conformance records have their own NEGATIVE_ONLY denominator.

Pre-candidate oracle qualification v1 could not decode Go backtick literals; v2 missed Go chained expected-field builder methods. Both exploratory private snapshots are preserved. The corrected v3 oracle was pinned BEFORE baseline and candidate measurement; private v3 oracle SHA d801716c40a437f9789b8562b8cf14d5954772f915a1ff441618d3541ded1413. Only the corrected v3 public summary is approved: scripts/poc/syslogConformanceOracle.v3.pinned.json.

| Group | Total cases | Scorable valid | Source fields | Upstream invalid | UNSCORABLE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Influx RFC3164 development | 8 | 8 | 57 | 0 | 0 |
| Influx RFC5424 development | 178 | 31 | 204 | 79 | 68 |
| OpenTelemetry sealed | 18 | 2 | 18 | 0 | 16 |
| Total | 204 | 41 | 279 | 79 | 84 |

Independent public parser-conformance evidence is NOT a genuine vendor firmware/config/packet capture or Stellar/Fluentd compatibility certification. Exact raw source bytes, independently expected names and values, and frozen reference records are retained off-Git under ~/.local/state/parserstudio-syslog-conformance-20261017 (directory 0700, data 0600). No raw logs or private reference values are committed.

## Reusable general mechanism

New separate source-only module: src/poc/generalSyslogEnvelopeSpans.ts (not used by the product).

1. Bounded RFC3164/RFC5424 PRI, timestamp, hostname, tag, procid, msgid, structured-data and MSG envelope/body separation, without vendor-name rules.
2. Every accepted native source field is indexed by its exact original UTF-8 byte half-open range and independently replayed. Enforces non-overlapping source spans.
3. RFC5424 valid MSG linefeeds are preserved as part of the same source event; a possible second PRI-prefixed physical record is rejected as ambiguous.
4. Unescaped right bracket inside quoted RFC5424 SD-PARAM, duplicate source identifiers, ambiguous unknown escape interpretation, invalid timestamps or Unicode are conservatively abstained. No global vendor backslash decode is introduced; known RFC5424 escaped quote/backslash/right bracket remain source-preserved.
5. Source size at most 8192 bytes, two grammar branch attempts, no unbounded scanning, and no auto-promotion. Results are REVIEW_ONLY, ABSTAIN_UNSAFE or RAW_ONLY; never SOURCE_PARSED/native VERIFIED.

## Same-denominator independent results

| Original-source metric | Unchanged baseline | New isolated candidate |
| --- | ---: | ---: |
| Development exact normal events | 38/39 | 39/39 |
| Development name + source value | 257 TP / 0 FP / 4 FN | 261 TP / 0 FP / 0 FN |
| Development original UTF-8 span triples | No baseline span contract | 261/261 exact, 0 FP/0 FN |
| Upstream known-invalid RFC5424 messages accepted as strict parse | 4/79 | 0/79 |
| Additional baseline partial PRI-only accepts | 5/79 | 0/79 source candidates |
| Automatic source/native success promotions | N/A | 0 |

The prior four false strict-positive RFC5424 messages share SD-PARAM escaped-boundary handling. The one source-positive baseline miss is a valid RFC5424 MSG with an internal linefeed. They are generic grammar classes, not vendor/version regex patches.

Independent sealed candidate SHA 823ed184a49ea60ef77e5e85d0e27ebbd15eb677158aacbfaaffb9a975c502cb was frozen before OpenTelemetry scoring. Sealed result: 2/2 independently scorable events, 18/18 original source name/value/UTF-8 span triples, zero FP/FN, exact source events 2/2. The baseline already had correct field values on this split but no byte span contract. Other 16 external cases remain UNSCORABLE. Two held-out events do NOT support broad generalization or universal parsing accuracy claims.

The full existing product parseSecurityInput path reported structural ok on 23/39 scorable development and 2/2 sealed messages; the candidate's 39/39 is SOURCE ENVELOPE REVIEW_ONLY, not product parser execution or complete vendor/native success.

## Negative controls, abstention and limitations

- Newly authored deterministic tests cover RFC3164 tagless/tagged, RFC5424 SD-PARAM and valid multiline MSG, original multibyte offsets, duplicated parameters, unsafe escapes, timestamps, multi-record ambiguity and size bounds.
- An independent Python test suite verifies original source hashes, Go upstream expected-field extraction, exact original byte spans, data permissions, and v3 frozen denominators.
- Historical SHA-pinned affected-stage safety replay (NOT fresh accuracy evidence): 1,361 prior originals and 2,892 invalid mutations. Source byte replay: 800 fields among 92 historical original REVIEW_ONLY suggestions; 26/2,892 malformed mutant logs still have structurally recognizable Syslog ENVELOPES and remain REVIEW_ONLY, never complete/vendor-certified parsed success. All 4,253 record originals preserved exactly; zero auto-promotions, zero byte-position drift, at most 2 branches. No invented source truth for the 26; they remain explicit negative/residual risks for body-level adjudication.
- Manufacturer escape rules and relay path semantics NOT CERTIFIED; native Stellar/Fluentd execution NOT VERIFIED; unsupported body extraction and unknown semantic mapping are not counted as extraction TP.

## Reproduction and acceptance boundary

1. python3 scripts/poc/pinSyslogConformanceSources.py
2. python3 scripts/poc/freezeSyslogConformanceOracle.py
3. python3 -m unittest discover -s scripts/poc -p testSyslogConformanceOracle.py -v
4. node_modules/.bin/vitest run src/poc/generalSyslogEnvelopeSpans.test.ts src/language-policy.test.ts
5. node_modules/.bin/vite-node scripts/poc/runSyslogConformanceBaseline.ts development
6. node_modules/.bin/vite-node scripts/poc/runSyslogConformanceCandidate.ts development
7. node_modules/.bin/vite-node scripts/poc/runGeneralSyslogSafetyReplay.ts
8. python3 scripts/poc/freezeSyslogConformanceCandidate.py
9. node_modules/.bin/vite-node scripts/poc/runSyslogConformanceBaseline.ts sealed
10. node_modules/.bin/vite-node scripts/poc/runSyslogConformanceCandidate.ts sealed
11. npm run typecheck && npm test && npm run build

Original source and candidate SHA freeze files are immutable. A materially changed candidate requires NEW sealed evidence, not post-hoc reuse of the current small holdout. Local unit/type/build, Git exact-head CI, Chromium browser and loopback HTTP each require actual results before qualification.

Remaining isolated work: increase truly independent nonJSON holdout denominators across source families, add source/body conflict adjudication so syntax-only valid headers do not become full event success, and compare field FP/FN without weakening abstention. Product backlog R1 (Juniper/Defender/Umbrella), R2 beginner progress, R3 mapping/UI mobile acceptance and R4 same-head owner E2E/approval remain HANDOFF ONLY.
