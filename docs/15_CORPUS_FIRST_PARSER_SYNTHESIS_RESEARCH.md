# Parser Studio 2.1 — Corpus-First Parser Synthesis: GitHub Research and Architecture

**Date:** 2026-10-13 KST. **Evidence status:** Source-and-fixture survey, architecture PROPOSED. No heterogeneous vendor benchmark or redesigned native runtime is claimed.
**Owner priority:** Research fundamental log-parser construction before more Test Lab buttons or raw unit-test counts.
**Latest UX priority:** Explain exact matched/unmatched source ranges and rule provenance; user-approved correction of wrong field roles; preserve opaque residuals with PARTIAL status. See [Explainable Progressive Parsing](16_EXPLAINABLE_PROGRESSIVE_PARSING_UX_RESEARCH.md), P0-TRACE-0..3.
**Navigation invariant:** Exactly Auto Parser and ChatGPT Assisted Parser; all capabilities are contextual parts of those two paths.
**Survey scope:** Over 20 representative code, schema, benchmark, data, and vendor-integration repositories plus confirmed integration families for nine additional security vendors. Not a literal census of all GitHub projects.

## 1. Diagnosis: why complex logs are currently hard

The existing UI classifies logs into a bounded set of known formats and compiles one fixed backend project. The backend grammar supports JSON, KV, CSV, CEF, LEEF, selected RFC3164/5424 combinations, reviewed mixed families, and explicitly TCP-framed Java. It does **not** support arbitrary Regex/Grok/Dissect, a generalized positional vendor subtype dispatcher, arbitrary nested JSON array traversal, or general multiline grammars as compilable operations. Browser-only JavaScript regex preview is not Ruby/CONF native evidence. The assisted path currently allows ParserRecipe v0.2 review and only one compatible extra mapping; an unfamiliar grammar proposed by ChatGPT can still be rejected even when the prompt is improved. This is a missing **grammar and compiler vocabulary**, not primarily a test-count or prompt-quality problem.

Concrete inspected raw vendor samples:
- Fortinet FortiGate: syslog PRI immediately followed by quoted, variable-order key=value data; traffic, event and UTM subtypes vary.
- Palo Alto PAN-OS: BSD-style Syslog envelope plus long positional CSV; TRAFFIC, THREAT, GlobalProtect and other types use different column positions and semantic roles.
- Trellix EDR Cloud / ePO Cloud: event-specific nested JSON, attributes, nullable or encoded data.
- Trend Micro Vision One / Deep Security: nested JSON arrays, types, multi-event envelopes and CEF-derived records.

**Correct replacement mental model:** discover structural variants -> infer and rank typed grammar candidates -> validate against positives AND negatives -> user corrects a few ambiguous field roles -> compile only supported grammar into the exact Ruby/CONF target dialect. No source event is silently omitted.

## 2. Verified GitHub architecture and library survey

| Project | Insight | Adoption caveat |
|---|---|---|
| [Drain3](https://github.com/logpai/Drain3) | Streaming template miner, typed masks, stable clusters, inference-only matching | MIT shown in core and package; already partly available in this product. Use on **residual unstructured text**, not already typed security fields. |
| [logpai/logparser](https://github.com/logpai/logparser), [loghub-2.0](https://github.com/logpai/loghub-2.0) | Multiple parsing algorithms, large-scale template/parameter evaluation | Mostly systems/software logs; security log subtype and semantic correctness require separate benchmark. Dataset-specific license check. |
| [LogBatcher](https://github.com/LogIntelligence/LogBatcher) | Group similar events and cache LLM proposals; avoid one model call per event | MIT; customer logs must never be automatically sent to an external model. |
| [LILAC](https://github.com/logpai/LILAC) | Hierarchical representative samples plus adaptive parsing cache | Research project with API key workflow and no confirmed source-reuse license; borrow design, not code. |
| [LogPPT](https://github.com/LogIntelligence/LogPPT) | Few-shot sample selection and reusable parsing patterns | Apache-2.0; full model training is too heavy for normal user requests. |
| [LibreLog](https://github.com/zeyang919/LibreLog), [LLMParser](https://github.com/zeyang919/LLMParser) | LLM-assisted clustering and grammar hypotheses | Research/model and licensing review required; do not make opaque model parsing the primary product runtime. |
| [OpenSearch Data Prepper](https://github.com/opensearch-project/data-prepper) | Composable Grok, simpler Dissect, typed dates, conditional routing, fallback | Apache-2.0; take semantics into a safe grammar IR, not the Java runtime. |
| [Fluent Grok parser](https://github.com/fluent/fluent-plugin-grok-parser) | Ordered multiple Grok patterns, separate multiline handling, explicit failure markers | Prove actual plugin support in the proprietary Fluentd target before claiming native. |
| [Vector VRL](https://vector.dev/docs/reference/vrl/functions/) | Fallible typed parsers, parse_groks and key-value helpers | Conceptual IR only, not target-native runtime. |
| [CrowdSec Hub](https://github.com/crowdsecurity/hub) | Staged parsers, input fixtures and expected-output assertions, hubtest | MIT. Its fixture-as-contract approach is as valuable as any parser algorithm. |
| [Panther Analysis](https://github.com/panther-labs/panther-analysis) | Security vendor-specific mapping profiles and semantic field definitions | Apache-2.0 repo metadata; verify file and fixture provenance. |
| [Elastic integrations](https://github.com/elastic/integrations), [Beats](https://github.com/elastic/beats) | Rich vendor pipelines and raw-logs-plus-expected-output fixture pairs | **Research-only by default:** root licenses default integrations and Beats x-pack to Elastic License 2.0 or an equivalent Elastic license, unless file/subtree says otherwise. Do NOT transplant. |
| [OCSF schema](https://github.com/ocsf/ocsf-schema), [ECS](https://github.com/elastic/ecs) | Typed security-event roles, vendor-neutral normalization guidance | Both Apache-2.0; target Stellar custom/top/ns/vendor field contract is separate. |
| [OCSF examples](https://github.com/ocsf/examples) | Raw-to-normalized example pairs | Verify sample license and redaction first. |
| [Sumo Logic content](https://github.com/SumoLogic/sumologic-content) | Log-source/vendor taxonomy and detection context | Apache-2.0 metadata; not a Ruby parser compiler. |
| [Wazuh ruleset](https://github.com/wazuh/ruleset) | Parent/child decoders, type-specific matches | Historic wazuh-ruleset archived in 2026; older XML carries GPL notices. No blind source copy. |
| [Microsoft PROSE](https://github.com/microsoft/prose) and [PROSE benchmarks](https://github.com/microsoft/prose-benchmarks) | Programming by examples: mark values and let the tool synthesize extraction rules | The SDK stopped releasing new versions in October 2025; reuse the **UX paradigm**, not the dependency. |

**Rejected shortcuts:** one giant regex; one global schema for all vendors; Drain3 as a semantic source/destination classifier; AI-generated arbitrary Ruby; copying Elastic rules without rights; declaring success from the number of unit tests.

## 3. Heterogeneous security log corpus: confirmed raw fixture references

Inspect genuine raw-input test fixtures and their gold expected outputs; already-normalized sample_event.json is NOT raw parser input. We verified these paths and representative formats but have NOT executed the full vendor benchmark, redistributed their contents, or checked a redesigned native parser.

| Manufacturer / product / type | Source reference | Critical variation |
|---|---|---|
| Fortinet FortiGate traffic | [traffic.log](https://github.com/elastic/beats/blob/main/x-pack/filebeat/module/fortinet/firewall/test/traffic.log) | PRI, quote-aware optional/reordered KV |
| Fortinet FortiGate event | [event.log](https://github.com/elastic/beats/blob/main/x-pack/filebeat/module/fortinet/firewall/test/event.log) | Subtype fields, actor/action |
| Fortinet FortiGate UTM | [utm.log](https://github.com/elastic/beats/blob/main/x-pack/filebeat/module/fortinet/firewall/test/utm.log) | Webfilter and other UTM extensions |
| Palo Alto PAN-OS traffic | [traffic.log](https://github.com/elastic/beats/blob/main/x-pack/filebeat/module/panw/panos/test/traffic.log) | BSD Syslog envelope + positional CSV |
| Palo Alto PAN-OS threat | [threat.log](https://github.com/elastic/beats/blob/main/x-pack/filebeat/module/panw/panos/test/threat.log) | A distinct subtype-dependent CSV layout |
| Palo Alto PAN-OS multiple types | [PAN-OS raw fixture directory](https://github.com/elastic/integrations/tree/main/packages/panw/data_stream/panos/_dev/test/pipeline) | Traffic, threat, globalprotect, system, config, etc. |
| Trellix EDR Cloud | [test-event.log](https://github.com/elastic/integrations/blob/main/packages/trellix_edr_cloud/data_stream/event/_dev/test/pipeline/test-event.log) | Nested EDR JSON and optional payload |
| Trellix ePO Cloud | [test-pipeline-event.log](https://github.com/elastic/integrations/blob/main/packages/trellix_epo_cloud/data_stream/event/_dev/test/pipeline/test-pipeline-event.log) | JSON API envelope with nested attributes |
| Trend Micro Vision One detection | [test-pipeline-detection.log](https://github.com/elastic/integrations/blob/main/packages/trend_micro_vision_one/data_stream/detection/_dev/test/pipeline/test-pipeline-detection.log) | Arrays, nested JSON, many optional fields |
| Trend Micro Deep Security | [test-trendmicro.json](https://github.com/elastic/integrations/blob/main/packages/trendmicro/data_stream/deep_security/_dev/test/pipeline/test-trendmicro.json) | JSON event batch and CEF-derived representations |

Next expansion: [Cisco ASA](https://github.com/elastic/integrations/tree/main/packages/cisco_asa), [Check Point](https://github.com/elastic/integrations/tree/main/packages/checkpoint), [Sophos](https://github.com/elastic/integrations/tree/main/packages/sophos_central), [SentinelOne](https://github.com/elastic/integrations/tree/main/packages/sentinel_one), [CrowdStrike](https://github.com/elastic/integrations/tree/main/packages/crowdstrike), [Zscaler](https://github.com/elastic/integrations/tree/main/packages/zscaler_zia), [Microsoft Defender](https://github.com/elastic/integrations/tree/main/packages/microsoft_defender_endpoint), [Okta](https://github.com/elastic/integrations/tree/main/packages/okta), [Cloudflare](https://github.com/elastic/integrations/tree/main/packages/cloudflare). Integration directories confirmed; choose raw/gold fixtures case by case.

Before importing into CI: verify exact file license, redact private identifiers, preserve semantic gold roles, record vendor/product/type/version, framing, optional fields and negative cases. Merely counting 1,000 imported lines is not proof of parser quality.

## 4. Proposed v0.3 grammar-learning architecture

1. **Evidence intake:** immutable corpus reference, local-only sensitive data handling, full event accounting and approval-aware redaction.
2. **Envelope/framing detection:** separate Syslog PRI/BSD/RFC5424, TCP/multiline/batch/CEF/LEEF wrappers from payload BEFORE classifying body.
3. **Offline vendor and subtype retrieval:** rank evidence-backed product/type/version profiles; support UNKNOWN rather than invent a parser.
4. **Typed lexers:** quote-aware order-independent KV, positional subtype-specific CSV with empty columns, JSON object/array/path, typed IP/port/user/URL/timestamp.
5. **Residual text templating:** use Drain3 or bounded Dissect/Grok only on the remaining free-text structure, with source-specific templates.
6. **Candidate grammar synthesis:** versioned declarative AST with explicit route predicate, grammar branch priority, typed capture, optional field, alias, time cast, canonical field meaning, fallback and counterexamples. A user can mark two source values to guide program synthesis.
7. **Semantic mapping:** distinguish source vs destination vs NAT from documented key/position, not the value merely looking like an IP. Map to actual Stellar source fields; ECS/OCSF may inform names but cannot replace the vendor target contract.
8. **Counterexample repair:** positive/negative fixtures, reordered keys, missing options, quoted values, decoy IPs, timestamp variants and independent holdouts. Show per subtype which records failed or remained unknown.
9. **Native compilation:** only operators with independent backend Ruby/CONF implementation, native Fluentd tests, exact SHA receipts and identity checks can generate deployable DRAFT. JavaScript preview is not native proof. LLM-proposed regex is UNTRUSTED DRAFT until bounded syntax, safe regex dialect, negative cases and native parity pass.
10. **Optional target lifecycle:** after independently verified pair, separately authorized real DP registration, bounded synthetic sensor tests, explicit Stop and genuinely checked target Interflow; never egress by default.

Example: FortiGate TRAFFIC and UTM should share one quote-aware KV lexer and two subtype-specific semantic mappings. PAN-OS TRAFFIC and THREAT should share an envelope decoder but use **different positional CSV grammars**. Trellix and Trend Micro must navigate nested arrays/objects without regex over JSON.

**Owner latest explicit UX input:** Begin synthesis from a user-dragged original-text span and its typed/semantic meaning, not one whole-log regex. See [Selection-first parsing](16_EXPLAINABLE_PROGRESSIVE_PARSING_UX_RESEARCH.md#4a-selection-first-parsing--the-user-reduces-the-problem). Local rule synthesis must be visually distinct from manual external ChatGPT/Claude/Gemini consultation and any future directly connected LLM.

## 5. User workflow: two paths only

**Auto Parser:** Paste logs -> show recognized manufacturer/type variants and field coverage -> user clicks and labels ambiguous values -> system creates candidate grammars and shows unknown cases -> full positive/negative/holdout validation -> native-verified Ruby and CONF if grammar supported. Never ask beginners to select CEF/KV/regex.

**ChatGPT Assisted Parser:** Select ChatGPT / Claude / Gemini for **manual, provider-neutral copy-and-paste**. Request reviewed redacted representative examples and desired fields; generated prompt asks for 1–3 declarative grammar alternatives, optional bounded Grok/Dissect/regex patterns, field semantics, explicit unsupported assumptions and adversarial test cases. User pastes the model response; Studio validates AST, sample identity, source-to-target field roles, negative/holdout tests and compiler capability. Unsupported proposed operator = REVIEW_ONLY with actionable reason; no arbitrary AI Ruby execution, no automatic model call and no raw log egress.

**After parser generation:** Real DP URL + User Scope API credential must be handled by a trusted backend with target allowlist, SSRF prevention, separate operator approval, audit and protected non-persistent session. Sensor target IP, protocol and requested duration (e.g. 1, 3, 5, 10 minutes) need a server-owned policy gate; **sensor ingress port equals generated CONF listener port** and Syslog uses >=6800. Lease, event quotas and rate must actually cover the requested duration; stopping is always reachable. The current backend sink primitive is not enabled by a browser-provided destination; success sending bytes is not proof of parsing.

## 6. Revised owner-ordered roadmap

| Priority | Development objective | Required evidence |
|---|---|---|
| **P0-SYN-0** | Rights-checked raw vendor corpus and one analytical failure prototype | First four priority vendors; distinct Fortinet and PAN-OS subtypes, Trellix EDR/ePO, Trend Vision One; gold fields, negative cases and observed current failures |
| **P0-SYN-1** | v0.3 typed grammar IR, frame/envelope decoders, robust KV/CSV/JSON lexers | Every event accounted; no silent missing/unknown records |
| **P0-SYN-2** | Offline vendor fingerprint retrieval, subtype clustering, teach-by-highlighting synthesis | Candidate grammar ranking, high-value field semantic precision, counterexamples |
| **P0-SYN-3** | Provider-neutral ChatGPT/Claude/Gemini prompt and structured grammar/regex paste review | Complex rule candidates accepted as review only or compiled with explicit capability, never misleading validation |
| **P0-SYN-4** | Ruby/CONF backend grammar compiler extensions + Native Fluentd parity | Proven compiler support, negative sample behavior, exact source/SHA evidence |
| **P0-SYN-5** | Focused heterogeneous vendor acceptance gate and quick-iteration UX | Variant coverage, field-level precision/recall, negative overmatch, unseen holdout and human correction count, NOT total unit count |
| **P0-LIVE (subsequent)** | Approved DP upload, synthetic sensor target/duration, Stop, target readback | Backend-only credentials/policy, same CONF/sensor port, approved network transmission and measured actual target outcome |
| **Separate release** | Owner target E2E and merge/release | Independent explicit approval |

Suggested quality targets **not yet measured**: 100% raw event accounting, 0 silent unknown/misroute, 0 unauthorized network egress; at least 95% supported-variant coverage and high-value source/destination/user field precision >=98% with recall >=95% on independently labeled holdout. Publish counts per vendor/subtype/version and include UNKNOWN in denominators. Do not treat these targets as present performance.

## 7. First tightly scoped experiment

Compare exactly the same rights-cleared representative Fortinet traffic/UTM, PAN-OS TRAFFIC/THREAT, Trellix EDR/ePO and Trend Vision One sources using (A) current fixed-format parser, (B) envelope+typed lexers+subtype branches, (C) B+Drain3 **residual** templates, (D) C+user-approved external LLM grammar candidate. For each record measure high-value field role accuracy, unknown/negative behavior, backend compiler reachability and operator corrective clicks. If B solves most failures, invest in grammar engineering first rather than an expensive always-on LLM.

## 8. Licensing and safety

[Elastic integrations LICENSE](https://github.com/elastic/integrations/blob/main/LICENSE.txt) explicitly defaults repository files to Elastic License 2.0 unless separately licensed. [Elastic Beats LICENSE](https://github.com/elastic/beats/blob/main/LICENSE.txt) defaults the x-pack tree to Elastic License unless overridden. Treat those vendor fixtures and pipelines as **references only** until per-file licensing and redistribution rights are confirmed. Drain3 MIT, CrowdSec Hub MIT, LogBatcher MIT, LogPPT Apache-2.0, OpenSearch Data Prepper Apache-2.0, OCSF Apache-2.0, ECS Apache-2.0 and Panther Analysis Apache-2.0 are candidates for case-by-case reuse. Research projects with unspecified licenses are not import-ready. Raw vendor examples can contain private hostnames/users/IPs; sanitize appropriately before producing local licensed test corpus and never transmit customer raw logs to external AI by default.

**What this research did NOT do:** No actual new vendor logs executed against a redesigned runtime, no benchmark score measured, no arbitrary regex compiled to verified Ruby, no real DP/sensor/Interflow network action, no source files from Elastic imported into this repository.

**Implementation discipline:** Preserve current exact-HEAD verified two-path product and compiler as the compatibility baseline. Introduce typed v0.3 grammar behind explicit capability gates. Existing independent, uncommitted complex-CEF/LEEF/Fortinet browser-recovery work on dev-atlas must be preserved; coordinate its native-grammar extension under P0-SYN instead of reimplementing it.
