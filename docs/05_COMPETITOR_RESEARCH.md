# 05. Competitor Research — Adopt Interactions, Not Proprietary Code

Research basis: public official vendor documentation, checked 2026-10-11. This is a **target UX synthesis**, not a claim of license to reuse source, assets or brand styling.

| Product | Verified interaction/function | Design adaptation | Source |
| --- | --- | --- | --- |
| Cribl Stream | Pipeline functions with continuous IN/OUT preview, event/table/diff diagnostics and saved sample datasets | Three-pane live editing, IN/OUT + stage trace, reusable fixture suites | https://docs.cribl.io/stream/data-preview/ |
| Datadog | Up to ten UI log samples; Tap to Parse; Match / Match with warning / No Match; per-sample preview | Guided sample selection, explicit partial extraction and failure states | https://docs.datadoghq.com/logs/log_configuration/processors/grok_parser/ |
| Graylog | Visual when/then rule builder and source rule editor | Rule builder for routine transforms; explicit source editor for advanced users | https://go2docs.graylog.org/current/making_sense_of_your_log_data/pipeline_usage.html |
| Google SecOps | No-code source→UDM mapping and code-snippet extensions, type and mapping semantics | Fast source→Interflow map, searchable schema dictionary, semantic warnings | https://docs.cloud.google.com/chronicle/docs/event-processing/using-parser-extensions |
| Stellar Cyber native Parser Studio | Raw Log, Parser/Regex, Normalization and Enrichment steps; modular upload/download and metadata dictionary | Preserve important Interflow concepts, but replace page-by-page authoring and single-sample limitations with richer workbench | https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Parser-Studio-Parsers.htm |
| Fluentd | Formal parser configuration, regexp/JSON/other format parsing and timestamp parameters | Treat its parser syntax and native execution as real technical compatibility constraints | https://docs.fluentd.org/configuration/parse-section |

## What we will build

**A single workbench, not an imitation of any one product.**

- Adopt Cribl-like visual feedback but with a first-class Interflow mapping panel.
- Adopt Datadog's high-quality per-sample result language but run arbitrary fixture sets rather than relying on ten samples.
- Adopt Graylog's GUI/advanced approach with explicit semantic-preservation warnings.
- Adopt Google SecOps-style no-code mapping but target Stellar Interflow, not UDM.
- Design for native Fluentd tests and vendor-specific export capability checks, rather than assuming every parse language is interchangeable.

## Competitive gap we are targeting

1. Single-log rule tuning masks event-family failures: solve with multi-sample coverage and variant routing.
2. Regex match falsely treated as end-to-end correctness: solve with extraction, type, mapping and runtime gates.
3. Vendor UI coupled to release and artifact specifics: solve with portable project IR and verified adapters.
4. Debugging one stage at a time is expensive: solve with per-record stage trace, diff and exact failure context.
5. Hand-built parsers difficult to maintain: solve with fixtures, revision history and reproducible export manifests.

## Licensing and safeguards

- Competitor documentation/screenshots support **functional research only**. Do not copy commercial source, images, trademarks, text layouts pixel-for-pixel, or embed protected assets.
- Fluentd's source/license and every runtime/plugin dependency require separate license inventory before redistribution.
- Open-source code integration requires verifying **exact package, version, license, notice and redistribution terms**; a permissively licensed project name alone does not license its full UI/assets.
- REA / reverse engineering is out of this phase; any future binary analysis requires a separately documented right-to-analyze and license/security review.

## What remains to be validated hands-on

Actual UI testing, detailed side-by-side screenshots and any component reuse/license review will be captured in a later design-evidence revision if it materially changes the accepted UI. The official docs above support the initial workbench design.
