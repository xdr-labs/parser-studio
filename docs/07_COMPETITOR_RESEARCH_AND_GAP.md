# 07. Competitive UI / Parser Workflow Research and Gap Analysis

**Research snapshot:** 2026-10-12. **Owner direction:** survey major alternatives before fixing the Web UI style, features and priority.
**Method:** first-party product documentation, official screenshots and public project licensing. This is a **market landscape review of 16 relevant products/platforms**, not a claim to have logged into every licensed product or enumerated every product worldwide.
Evidence key: **D** = official current workflow documentation; **S** = official published screenshot; **C** = verified repo license. Live authenticated, hands-on UX tests have **not** been performed. External URLs are reference-only. Never copy proprietary CSS, code, icons, assets, text, or trade dress.

## 1. Product / category coverage

| # | Product | Official evidence | Practical workflow pattern | Adoption / gap |
|---|---|---|---|---|
| 1 | Stellar Cyber Parser Studio (target baseline) | [Parser Studio – Parsers](https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Parser-Studio-Parsers.htm) (D) | Four-step guided Raw Log → Parser/Regex → Normalize → Enrich; tester, dictionary, upload/download, tenant routing | **Outperform:** multi-event in-context editing, portable authoring, side-by-side stages, native truth gates. Vendor legacy and modern formats are **not presumed interchangeable**. |
| 2 | Cribl Stream | [Pipeline functions](https://docs.cribl.io/stream/pipelines/) · [Data preview](https://docs.cribl.io/stream/4.5/data-preview/) (D,S) | Ordered pipelines, route/function editor, real-time data preview, input/output and diff | **Primary layout reference:** persistent 3-pane workbench; visible ordered processing; stage input/output and diagnostics. Do not replicate Cribl's assets/components. |
| 3 | New Relic Logs | [Parsing/no-code](https://docs.newrelic.com/docs/logs/ui-data/parsing/) (D,S) | Select sample substring, suggest/generate parsing pattern, live preview; code-mode escape hatch; drafts | **Top-priority interaction:** select raw value → name field → proposed rule → run across whole sample set. Keep a reversible preview rather than silently accepting a pattern. |
| 4 | IBM QRadar DSM Editor | [DSM Editor overview](https://www.ibm.com/docs/en/qradar-on-cloud?topic=qradar-dsm-editor-overview) (D); [official IBM community screenshots](https://community.ibm.com/community/user/blogs/krunal-pandit/2024/11/27/understanding-the-importance-of-qid-mapping-in-ibm) (S) | Raw workspace, match highlight, parsed custom property and event categorization | **Critical field-engineer reference:** visible token→destination association, test events, unmatched/property errors. Avoid copying legacy dialog-heavy layout. |
| 5 | Google Security Operations | [Parser extensions](https://docs.cloud.google.com/chronicle/docs/event-processing/using-parser-extensions) · [Custom parser](https://docs.cloud.google.com/chronicle/docs/event-processing/configure-custom-parsers) (D) | No-code source→UDM mapping, code editor alternative, preview/validate split | **Mapping standard:** searchable, typed target fields, coverage, error evidence, preview vs validation separated. Do **not** use UDM names as Interflow schema. |
| 6 | Datadog Logs | [Grok Parser](https://docs.datadoghq.com/logs/log_configuration/processors/grok_parser/) (D) | Multiple sample messages, parsing rule editor and explicit Match / warning / No Match results | **Test status:** each sample gets a clear match/no-match/empty-extraction classification; avoid single-sample false green. |
| 7 | Elastic Kibana | [Grok Debugger](https://www.elastic.co/docs/explore-analyze/query-filter/tools/grok-debugger) (D,S) | Sample data + Grok editor + Simulate + structured result | **Advanced mode:** direct expression editor beside one-event preview; sample patterns only as permitted by target native engine. |
| 8 | Graylog | [Pipelines](https://go2docs.graylog.org/current/making_sense_of_your_log_data/pipelines.html) · [Build rules](https://go2docs.graylog.org/current/making_sense_of_your_log_data/pipeline_usage.html) (D) | Rule builder, source editor (one-way conversion limitation), staged rules, simulator | **Avoid source/GUI data loss:** explicit rule ordering, condition→action timeline; don't promise reversible round-trip for unsupported syntax. |
| 9 | Splunk Enterprise | [Field Extractor](https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/use-the-field-extractor-in-splunk-web/field-extractor-select-method-step) (D,S) | Choose regex or delimiter from representative event; guided extraction | **Novice onramp:** suggest parser family and simple token/delimiter editors, expose advanced path. |
| 10 | Panther | [Custom log types](https://docs.panther.com/data-onboarding/custom-log-types) · [pantherlog tests](https://docs.panther.com/panther-developer-workflows/pantherlog) (D) | YAML schema editor, test against sample logs, CLI golden expected outputs | **Regression gate:** fixtures + expected normalized outputs and source-controlled provenance. |
| 11 | Microsoft Sentinel ASIM | [Parser development](https://learn.microsoft.com/en-us/azure/sentinel/isv/normalization-develop-parsers) (D) | Collect diverse logs, map mandatory schema, validate field type/value; separate variants | **Correctness:** missing required fields, duplicate/lost attributes, data-type and timezone validation before export. |
| 12 | Sumo Logic | [Field extraction rules](https://www.sumologic.com/help/docs/manage/field-extractions/) (D) | Ingest-time FERs, stored rule templates, field naming standards | **Governance:** predictable names, rule lifecycle and sample tests. Avoid coupling editing to live ingest. |
| 13 | Mezmo Telemetry Pipelines | [Demo pipeline](https://docs.mezmo.com/telemetry-pipelines/demo-pipeline-guide) (D,S) | Node pipeline, route/filter processors, pipeline taps on sample data | **Later:** processing flow visualization and branch filtering, but no need for canvas graph in MVP. |
| 14 | OpenObserve | [Pipelines](https://openobserve.ai/docs/user-guide/data-processing/pipelines/pipelines/) (D,S) | Source → transform → destination visual pipeline; real-time/scheduled flows | **Later:** optional pipeline overview; parser workbench remains primary screen. |
| 15 | Vector / VRL Playground | [Playground](https://playground.vrl.dev/) · [Remap](https://vector.dev/docs/reference/configuration/transforms/remap/) (D) | Code input + event input + live transformed output and runtime details | **Advanced transform editor:** stage-scoped source editing with execution result; not a replacement for Fluentd-native evidence. |
| 16 | Fluentd (execution baseline, not GUI rival) | [Fluentd](https://docs.fluentd.org/) · [repository](https://github.com/fluent/fluentd) (D,C) | Native parser/filter plugins and actual configuration semantics | **Runtime source of truth:** execute pinned native Fluentd in isolated runner, not JS regex compatibility guesswork. |

**Review limits:** This table describes documented capabilities and visible public screenshots, not lab-measured usability, performance, or vendor feature parity across releases. Reassess vendor documentation before implementation if it changes. Distinguish published screenshots from actual product session captures.

## 2. License / reuse constraints

| Candidate source | Observed code license / distribution | Decision |
|---|---|---|
| Cribl, Datadog, New Relic, Splunk, QRadar, Google SecOps, Panther, Sumo Logic, Mezmo, Microsoft Sentinel | Proprietary/commercial product UX references | **Workflow research only.** Do not extract, reverse engineer, copy or reuse protected source/assets. |
| Graylog server | [SSPL-1.0](https://github.com/Graylog2/graylog2-server) | Analyze public UI concepts and docs; no source reuse without explicit legal/security review. |
| OpenObserve | [AGPL-3.0](https://github.com/openobserve/openobserve) | Research public workflow, no code reuse for this independent product absent legal review. |
| Vector / VRL | [MPL-2.0](https://github.com/vectordotdev/vector) | Concept research; using source would need file-level MPL obligations and legal review, **not selected**. |
| Elastic Kibana | Commercial/Elastic licensing varies by component | Official docs only; no UI source/asset reuse. |
| Fluentd | [Apache-2.0](https://github.com/fluent/fluentd) | **Preferred native-validation dependency** subject to NOTICE/dependency/plugin compliance. Not an invitation to copy arbitrary third-party plugins. |

Source-license compatibility is not itself a conclusion on trademark, patents, distribution obligations or a third-party dependency graph. No source copied in this review. Browser code in this repository is original.

## 3. Combined design decision

**Design thesis:** Security-focused parser *laboratory*, not a pipeline management dashboard and not a 4-page wizard. The screen stays task-centric around selected raw evidence; users see exactly what changed and why.

### Primary workflow, designed from the strongest distinct patterns

1. Open draft or create parser; **paste/upload a varied set of logs** (Cribl + Panther).
2. Inspect detected families, match status and precise event source (Datadog).
3. **Highlight a raw value, choose Create Field**, review the inferred pattern and type on the same screen (New Relic + QRadar).
4. Edit ordered extraction stages; create branch/fallback only where needed (Cribl + Graylog).
5. **Map extracted source → evidence-backed Stellar target field** with typing and unmapped preservation; no fake schema labels (Google SecOps + Sentinel).
6. View **RAW → EXTRACTED → NORMALIZED + per-rule trace** for any event without changing pages (Cribl + Graylog).
7. Run entire fixture suite; inspect failures, diagnostics and candidate/baseline diffs (Datadog + Panther).
8. Save a draft. Export Fluentd or Stellar artifacts **only** when native and target evidence gates pass (Fluentd + Stellar). No production mutation in Studio.

### Information architecture

- **Workbench** (default, 3 continuously-visible panes): Samples (30%), ordered rules/mapping (35%), live input/output/trace (35%). Resizable in later enhancement; smaller viewports use stacked panels/tabs. A sticky bottom strip shows true event denominators and runner identity.
- **Test Lab**: fixture groups → test matrix → failed examples → stage/field diagnostics → baseline/current diff.
- **Parser Library**: name/vendor/product, draft vs tested/verified distinction, sample privacy status, revision provenance and capability labels.
- **Export & History**: adapter matrix (Fluentd, vendor legacy/modern profiles), blocked and verified states, hashes, manifests, source/IR loss reports.
- **Schema Explorer**: only the confirmed destination field dictionary; list source, field type, optional/required, examples and catalog revision.

### Original visual language

**Style:** enterprise technical workbench, high legibility and density. Deep midnight vertical navigation and masthead; off-white canvas and neutral raised panes; restrained sea-glass teal for active selections; amber for warnings; red for actual failures. Avoid full-screen dark raw-log panels outside syntax/output windows. Typography: clear compact sans UI + monospaced log/regex/code; WCAG-friendly focus rings, never color-only statuses; responsive without hiding error evidence. Screen ratio targets: at 1440px keep all three panes visible, at narrow widths stack/tabs.

**Non-negotiable display contract:** each green status states *which* test passed, with runner, fixtures and revision. A browser preview cannot turn the Fluentd or Stellar badge green.

## 4. Current implementation gap (branch feat/r2-web-workbench at study time)

Legend: **DONE-LOCAL** = locally implemented, test verification must be reported separately; **PARTIAL** = narrowed preview behavior; **PENDING** = not implemented.

| ID | Capability | Current state | Competitor-derived target / priority |
|---|---|---|---|
| UX-01 | Three-pane workspace with event list, rules and preview | DONE-LOCAL | Cribl-like persistent in-context editing (P0) |
| UX-02 | Multi-line paste, UTF-8 text upload and sample list | PARTIAL | Multiline event boundary options, family filters (P0) |
| UX-03 | Format hints and per-event stage status | PARTIAL | Tunable format override, match/no-match/empty-extract (P0) |
| UX-04 | Raw selection → create field → pattern editor | PENDING | New Relic/QRadar selection-based field authoring (P0-next) |
| UX-05 | Typed mapper and source-preservation visibility | PARTIAL | Official Interflow schema (evidence dependent), collision/required checks (P0) |
| UX-06 | Regex/JSON/KV/CSV/Syslog extraction | PARTIAL | Complex routing, CEF/LEEF, nested extraction, multiline, native syntax (P0) |
| UX-07 | RAW / EXTRACTED / NORMALIZED / DIFF | PARTIAL | Real selected-stage IN/OUT revision diffs, highlight spans (P0) |
| UX-08 | Explicit suite with counters, trace and failures | PARTIAL | Golden fixtures, grouped errors, history regression diffs (P0) |
| UX-09 | Local draft saved/reopened without raw data | DONE-LOCAL | Versioned, reproducible project storage when backend contract defined (P0/P1) |
| UX-10 | Native Fluentd sandbox and parser runner | PENDING | Runtime version/plugin manifest, pinned containment, native equivalence (P0) |
| UX-11 | Actual .conf + matching parser artifact importer/exporter | PENDING | Owner real pair, loss report, actual target test (P0) |
| UX-12 | Internationalization, accessibility and responsiveness | PARTIAL | English-only labels, keyboard traversal and real browser checks (P1) |
| UX-13 | AI-assist and general node graph | PENDING | **DEFER** until core correctness and privacy proven (P2) |

## 5. Decision matrix & selection rationale

Weighted design criteria (for our product, **not** vendor score claims):
- Parsing accuracy, runtime truth and failure explanation — **30%**
- Time-to-working-field for inexperienced field SE — **25%**
- Target normalization correctness — **20%**
- Handling of sample diversity and regression confidence — **15%**
- Visual density/accessibility and maintenance friction — **10%**

**Chosen blend:** Cribl (layout + pipeline stages) + New Relic (select-to-field) + QRadar (highlight/diagnosis) + Google SecOps (typed mapping) + Datadog/Panther (multi-sample validation).

**Reject:** One-event-only wizard, unexplained automatic regex, decorative graph canvas, unqualified "100% success", fake Stellar standard field names, unverified export buttons, product-version selector in the authoring model, preemptive AI dependency.

## 6. Executable prioritized backlog

1. **R2-UX-A (now):** original high-contrast 3-pane shell; sample list/filter; stage tabs; typed mappings; local worker; no-false-green banners. Unit, build and UI smoke.
2. **R2-UX-B (immediately after A):** selected raw value → structured field proposal, editable rule, event-level match highlight; regex safety/regression tests.
3. **R2-PARSER-C:** physical/logical event boundary, variant routing and fallback order, CEF/LEEF candidates, typed extraction; test each family.
4. **R2-SCHEMA-D:** official field dictionary from concrete vendor evidence, required-field rules and normalized output coverage.
5. **R3-NATIVE-E:** pinned Fluentd runner, sandbox/timeout limits, plugin manifest and failure trace, fixture baseline/compare.
6. **R3-EXPORT-F:** test owner real .conf + matching parser pair; evidence-backed import/IR/export; hashes; refuse unsupported constructs and avoid leaking samples.
7. **R4-USABILITY-G:** accessibility/language/resizable panes, template library, optional visual stage map and opt-in suggestions.

### E2E success scenarios

- **One-field authoring:** paste an event → select src_ip value → propose named field → inspect pattern → map typed IP → see result; no off-screen wizard.
- **Variant coverage:** input 20 events with 3 real families → 20 visible statuses, all failed outliers identifiable and explainable; no invented score.
- **Wrong type:** invalid IPv4 or port is reported at exact source field and event, without generating a Verified artifact.
- **Existing parser:** import actual pair → modify one field → compare output → native Fluentd pass → export exact matching pair; pending fixture and adapter verification.
- **Privacy:** uploaded logs remain local/private, without default sending to telemetry, GitHub or external AI.

## 7. Next evidence and execution boundaries

- Owner's /opt/td-agent/etc/td-agent/customized_parser *.conf plus corresponding parser implementation on rickmodular is the target file pair. Direct content access was refused by platform safety check on 2026-10-12; **do not assume the paired file format or ownership**, and don't bypass. Public vendor docs provide only *documented* modular JSON examples, not proof of owner-specific legacy behavior.
- Owner raw customer samples remain uncommitted until privacy-screened, synthetic representative fixtures can be tested.
- Future competitor analysis may use licensed source only after explicit license clearance; workflow / official UI review needs no code reuse.
- This file is a study & gap contract, not a claim that all the roadmap items are completed.
