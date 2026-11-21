# Takeover of PR #316: prototype-key source fields, mapping recall, exact-HEAD evidence (2026-11-21)

Scope: continuation of the Codex accuracy branch `experiment/codex-accuracy-lab-20261117` (PR #316, Issue #315).
No merge, no deployment, no change of an approval constant. The Development Preview (main `af7de35`) was used
read-only as the "before" side of the browser comparisons.

## 1. State found

| Item | Found |
|---|---|
| PR #316 head | `ee1cd73`, draft, 31 commits ahead of main `af7de35` |
| Local Codex commits `8b532cc`, `b06dd316` | not on dev-atlas and not on GitHub; their browser-test fixes were redone here |
| CI run 44700349116 at `ee1cd73` | native-isolated-synthetic PASS, ruby24-fluentd-udp-reception PASS, browser shards 3-6 PASS, shards 1-2 FAIL, web-quality FAIL, release-eligibility SKIPPED |
| Local baseline at `ee1cd73` | Vitest 2,076/2,076, Python 191/191, semantic oracle 6,288/6,288 (32/32 mutants), as reported by Codex |

## 2. Defects and root causes

| # | Defect | Root cause | Fix |
|---|---|---|---|
| 1 | web-quality stopped at the manifest step; none of its later steps ran | `20a700f` changed `grammar-generic.generated.rb.tpl` without regenerating `contracts/ruby-template-set.v1.json` | manifest regenerated (`1ec2b37`); the approval constant is untouched |
| 2 | Browser shards 1 and 2: four tests failed | the tests found a mapping row by the text of its source input and expected the display prefix `parserstudio_source.`; `608de3d`/`b79ccea` removed that prefix from the display. The mappings were correct | rows are selected by `data-source-path` (`13e89ef`) |
| 3 | Issue #315: valid tagged Syslog key=value events with a field named `toString`, `valueOf`, `hasOwnProperty` ended in "could not complete analysis" | the five key=value readers of `src/genericStructural.ts` collect repeated keys with `previous=record[key]` on a plain `{}`; the inherited function is taken for an earlier occurrence, stored as `[function, value]`, and `structuredClone` throws. The generated Ruby reads a Hash and never had the defect | records keyed by log names are created with `Object.create(null)` (`0cb3f97`); the generated Ruby is byte-identical |
| 4 | Official fields of a mixed sample stayed vendor fields (`srcport`, `dstport`, `url` of FortiGate traffic + web filter + system records) | a candidate was approved only when every event carried the source | a source named exactly as the official field is approved for the endpoint fields and `url` although some events lack it (`cbc3324`) |
| 5 | Zeek `conn.log` endpoints unmapped | no alias for `id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`; `proto` holding names was proposed as the numeric field | aliases in the shared semantic policy; `proto` with documented names is proposed as `proto_name` |
| 6 | Junos structured data read by the Generic Structural route lost `srcip`/`dstip`; the zero-filled `icmp_type` guard never fired on that route | that reader spells names with underscores; aliases and the guard knew only the hyphenated spelling | aliases `source_address`, `destination_address`, `protocol_id`; the guard reads `icmp_type` beside `protocol_id` |
| 7 | `tests/issue217-mapping-budget-e2e.spec.ts` kept a row position across an edit | an edit moves a row between the standard and the vendor section | row selected by `data-source-path` |

`constructor` and `__proto__` keep their existing fail-closed handling (RFC 5424 parameters are kept under a
reversible `param_hex_...` name; key=value readers decline or keep the message whole).

## 3. Mapping policy change to review

Before: a field present in only some events of a sample was always a "check first" proposal.
Now: it is approved when **all** of these hold: the target is one of `srcip`, `dstip`, `srcport`, `dstport`, `proto`,
`proto_name`, `url`; the source carries that official name itself (or is a fully spelled port label of
`explicitPortSourceAliases`); every value it has fits the field; the protocol gate and the NAT exclusion pass.
Aliases (`src`, `dpt`, `policyid`, ...) and other official names (`severity`, `type`, `icmp_type`, `md5`, ...) keep the
full-coverage rule. Two older tests that expected REVIEW for the five official names of a sparse sample now expect
the approval (`candidateOrderInvariant20261107`, `mappingMetamorphicOracle20261107`); their order-independence and
exact-candidate-set assertions are unchanged. The rule is one condition (`namedAsTarget`) in
`src/guided/normalizationCandidates.ts`.

Left as before, on purpose: `user`/`user_name`/`usr` (advisory aliases of `username`), composite values
(SonicWall `src=ip:port:interface`), a port beside a non-transport protocol label (Stormshield `proto=https`,
conformance corpus 2026-11-07), a conditional `action` whose values are not all dispositions.

## 4. Measurements

All "after" browser numbers: real Chromium journeys against a served snapshot of `cbc3324`, the downloaded Ruby
executed on Ruby 2.4.9p362 (digest-verified image root file system), scored by tools that do not import project code.

### 4.1 Holdout, 24 vendor-grammar samples, 175 expected Stellar meanings (declined samples stay in the denominator)

| | main `af7de35` | `ee1cd73` | after |
|---|---|---|---|
| Samples with a downloaded parser | 14 | 15 | 15 (62.5%) |
| Meanings mapped correctly (recall) | 78 (44.6%) | 83 (47.4%) | 98 (56.0%) |
| Meanings mapped wrongly | 0 | 0 | 0 |
| Kept under the vendor name / embedded in a larger value / lost | | | 20 / 8 / 0 |
| Meanings inside declined samples | | 49 | 49 |
| Error records, values of another event | 0 / 0 | | 0 / 0 |

`af7de35` values are those of the 2026-11-17 preview run; `ee1cd73` is the unit-level oracle
(`vendorHoldout20261116.test.ts`), which gives the same 98 after.

### 4.2 Golden corpus, 68 cases

| | main `af7de35` | after |
|---|---|---|
| Downloaded parsers | 43 | 43 |
| Golden Stellar fields | 137/182 (75.3%) | 154/182 (84.6%) |
| Golden source values kept | 176/179 | 176/179 (3 inside a larger value) |
| Error records / values not in their own line / values of another event / wrong name-value linkage | 0 / 0 / 0 / - | 0 / 0 / 0 / 0 of 799 |
| Emitted values checked | | 2,425 over 99 events |

### 4.3 Public vendor-format samples, 23 files

Source: test fixtures of `github.com/elastic/integrations` at `73b87f14ae8af28fff7f3ff82f051b171efa4618`, the first
eight lines of each file. They are published samples in the vendor's format, not captures taken from a device by
this project; they are kept outside the repository (`public-samples/PROVENANCE.tsv` of the evidence directory).
No public raw Trend Micro file was usable; Trend Micro is covered by vendor-grammar samples only.

| Product family | Sample | main `af7de35` | after |
|---|---|---|---|
| FortiGate 6.2 / 7.4 | traffic, UTM and event records | parsed 8/8, no official field | parsed 8/8, `srcip`, `dstip`, `srcport`, `dstport`, `proto` |
| Check Point | log exporter | parsed, `hostname` | + `proto` |
| Check Point R80 | | parsed, `hostname` | same |
| Juniper SRX flow | RT_FLOW | 7 of 8 events; no download | same |
| Juniper SRX IDP | | no download (three RFC 5424 timestamps not supported) | same |
| PAN-OS traffic / threat (no PRI) | | stops at "confirm CSV column names" | same |
| Cisco ASA (two files) | | no download (free text) | same |
| SonicWall, SonicOS 7 | | parsed; composite `src`/`dst` kept whole | same |
| WatchGuard traffic | | parsed, `hostname` | same |
| WatchGuard event | | 0 of 8 events; no download | same |
| F5 BIG-IP ASM (JSON) | | parsed, no official field | same |
| Trellix ePO, Trellix NX (JSON) | | parsed, no official field | same |
| Linux auth, secure, syslog | | no download (free text) | same |
| Snort fast | | no download (free text) | same |
| Suricata EVE | | parsed, 7 official fields | + `proto_name` |
| ModSecurity audit JSON | | no download (duplicate JSON key, declined by policy) | same |

Totals after: 11 of 23 downloaded (47.8%), 76 events, 0 error records, 0 values of another event, 2,430 emitted
values checked. 27 values are flagged "not text of the own line" on both sides: 26 Suricata strings whose `/` is
written `\/` in the JSON source, and one Check Point repeated key kept as a list. Neither is an invented value.

### 4.4 Issue #315 in the browser and on Ruby 2.4.9

| Key | main `af7de35` (preview) | after |
|---|---|---|
| `toString`, `valueOf`, `hasOwnProperty` | analysis fails, nothing to download | 2 of 2 parsed, parser downloaded, 2 records, 0 error records, 52 values each from their own line |
| `normalKey` (control) | parsed and downloaded | same |

## 5. Tests

| Suite | Result |
|---|---|
| Frontend Vitest | 2,151/2,151 (243 files) |
| Python unittest | 191/191 |
| Semantic oracle (browser TypeScript) | 6,288/6,288, 32/32 mutants |
| Semantic oracle (Python Multi-Pass), three-way comparison | PASS |
| Independent source-to-Stellar oracle and its fault tests | PASS (26 goldens) |
| Cross-consumer mapping parity (browser, backend, Python) | PASS |
| MCV2: semantic candidate mutants | 16/16 killed |
| MCV2: candidate AST census | 172 of 186 non-equivalent mutants killed (92.47%, floor 90) |
| Grammar generators, ts2rb, duplication ratchet, executable contract gate | in sync / PASS |
| Backend | 772/775: two Drain3 tests need the engine (not in the product gate), one is the owner approval of the template set |
| TypeScript, frontend build, backend build | PASS |
| Chromium catalogue, same-HEAD backend and Multi-Pass (`cbc3324`) | 419 passed, 62 skipped, 15 failed: 14 golden-vendor cases need a Ruby binary on the host (15/15 pass with Ruby 3.2.3 on PATH), 1 was defect 7 |

## 6. Gates

- **Owner approval pending.** Template-set digest of this branch:
  `400e046311f5aeeb18352a4a80483e040baae3871294af39d108e3f475c2cf44`; approved digest:
  `16824f8e1201e8c1bb2a2244baa4516db75546caa6d3fdddff8abb1575b4c7e4`. The only template change is `20a700f`
  (syslog-wrapped LEEF 2.0 with implicit TAB: one new mode in `psg_extract_generic_structural`, generated from
  the TypeScript grammar). Nothing in this takeover changes the digest. Until the approval,
  `backend/test/template-set-approval.test.ts` fails, so web-quality stops at the authoring test gate and
  release-eligibility is skipped.
- Not verified: a real Stellar Cyber 7.0 sensor or data processor (import, indexing, search), logs captured from a
  device by this project, production.

## 7. Open, not fixed here

| Finding | Cause | Class |
|---|---|---|
| PAN-OS Syslog without PRI is offered the generic CSV column confirmation although the Generic Structural reader recognises the record (`panos_traffic_csv`) | the automatic Generic Structural draft is tried only when the envelope ledger reports unsupported events; a headerless CSV reading reports none | false decline, P3 |
| One unsupported event (SRX IDP timestamp form, one RT_FLOW record) stops the automatic journey for the whole sample | the automatic path needs every event | partial-parsing limit, P3 |
| Check Point `src`/`dst`, `s_port`/`service` stay vendor fields | sparse aliases; `service` is vendor-specific | recall, by policy |
| `user`, `user_name`, `usr` are not mapped to `username` | advisory aliases | recall, by policy |
| SonicWall composite endpoints | no composite split | recall, P3 |
| Stormshield ports beside `proto=https` (`ipproto=tcp` is in the record) | only `protocol-id`, `protocol`, `proto`, `proto_name` are read as protocol evidence | recall, P3 |
| PAN-OS THREAT positional columns | no column names for the THREAT record | recall, P3 |

## 8. Evidence

`dev-atlas:/home/aella/.local/state/parserstudio-takeover-evidence-20261121/` - `journeys/` (T1 = `cbc3324`,
P0 = preview), `results/` (scores), `public-samples/` (inputs and provenance), `tools/`.
The journeys ran at `cbc3324`; the commits after it change the scope of the `icmp_type` guard, verification
scripts, one browser test and this document.
