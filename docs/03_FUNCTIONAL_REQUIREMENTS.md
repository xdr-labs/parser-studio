# 03. Functional Requirements and Priority

Each feature below needs deterministic tests and a visible user flow. **P0** is the first usable product; **P1/P2** extend it after validated MVP behavior.

| ID | Priority | Capability | Observable definition of done |
| --- | --- | --- | --- |
| F01 | P0 | Parser projects and drafts | Create, rename, save and reopen without losing ordered rules |
| F02 | P0 | Sample collection | Paste/upload many events, inspect line/event boundaries and preserve fixture identities |
| F03 | P0 | Event family / routing | Same sample set supports conditional variants with visible per-event selected branch |
| F03A | P0 | User-named log-type inputs | A novice can add individually named, editable and uploadable source log types from one product, inspect per-type parsing and field coverage, save/restore them in browser-local versions, and qualify an optional single parser only with independent source-backed routing evidence; preserve existing physical record separators and validate legacy local-version checksum snapshots without changing original type samples |
| F04 | P0 | Format recognition | User sees candidate format and confidence, can override and retest |
| F05 | P0 | Extractors | JSON, KV, CSV, Syslog header and regex extraction run against sample set |
| F06 | P0 | Multi-line event breaking | Physical line grouping generates stable logical events with error trace |
| F07 | P0 | Visual field selection | Selected source value creates editable extraction rule; all matches highlighted |
| F08 | P0 | Fluentd engine validation | Supported config executes in actual Fluentd sandbox; browser preview is labeled approximate where relevant |
| F09 | P0 | Typed transforms | Timestamp, IP, integer, boolean, string, rename and conditional transforms have positive/negative tests |
| F10 | P0 | Interflow mapping | Searchable destination field catalog, collision/type warnings and explicit unmapped handling |
| F11 | P0 | Live triple preview | Raw, extracted and normalized per-event views plus before/after diff |
| F12 | P0 | Test Lab | Aggregate counts, filtering by error class, per-stage trace and exact failing records |
| F13 | P0 | Revision/regression | Baseline and candidate compare using identical fixtures; reproducible suite output |
| F14 | P0 | Fluentd export | Generate only supported syntax and prove with native-engine roundtrip test |
| F15 | P0 | Export safety | Capability check, warnings, manifest, checksums and no unverified compatibility badges |
| F16 | P0 | Security/privacy | Upload limits, safe parsing execution, sensitive field controls and no default external transfer |
| F17 | P1 | Import existing parser | Read supported vendor/Fluentd artifacts; report unknown constructs rather than dropping them |
| F18 | P1 | Stellar parser export adapters | Validated legacy/modular artifact profiles after real samples and target import tests |
| F19 | P1 | Parser library/templates | Named vendor families, tags, clone, browse and revision history |
| F20 | P1 | Smart mapping/field suggestion | Explain confidence; user can override and evidence supports recommendation |
| F21 | P1 | Advanced editor | Source-level expressions and supported GUI↔source equivalence checks |
| F22 | P1 | Multitenant workspace roles | Optional viewer/editor/admin after authentication/security design |
| F23 | P1 | Optional AI assist | Explicit user opt-in; protect raw logs; AI output always passes deterministic runner |
| F24 | P2 | Extended transforms/plugins | Capability-gated Grok, LEEF/CEF edge cases, lookups and custom enrichment |
| F25 | P2 | Lab/test-system integration | Optional connector to an isolated Stellar Cyber instance, never production by default |
| F26 | P2 | Team review workflow | Approval evidence, revision comments, immutable test reports |

## Functional notes

### Parsing semantics
- Avoid reducing format support to one universal regex. Auto-detection proposes a parser, but actual routing/selection and errors remain inspectable.
- Distinguish **match** (expression matched) from **extraction** (fields emitted), **normalization** (typed output valid), and **export compatibility** (runtime/import validated).
- Support multiple candidate variants without a global catch-all that masks failures.
- An empty dataset, missing required field or disabled runner cannot yield Verified.
- Keep original raw event accessible in project-local storage according to privacy configuration, without exposing it through redacted report exports.

### Timestamp and field correctness
- Preserve timezone, timestamp input unit, event time vs ingest time, and invalid/missing time policies.
- Ports must be numeric within valid range; IP addresses must parse properly. Avoid implicit coercion to success.
- Record mapping precedence and behavior when multiple raw fields target one normalized field.
- The exact Stellar dictionary and mandatory metadata contract must be grounded by official documentation and supplied parser samples; do not assume unchanged across deployments.

### Engine and compatibility
- Fluentd-compatible means a declared version/profile is exercised by an actual Fluentd process with pinned plugins, isolated from the host and with no unrestricted network/filesystem access.
- Vendor runtime behavior may differ. A passing Fluentd test is necessary for Fluentd export but insufficient to mark proprietary Stellar imports Verified.
- The common parser project file must survive editing/import/export even when target-specific output is not available.

### Reporting
Test report contains:
- project/revision, fixture set and hash;
- runner and plugins/capability profile;
- selected rules and mapping catalog revision;
- total records, matched, extracted, normalized, failed, skipped;
- per-event failure class and stage;
- target export compatibility classification;
- execution time and result checksum.

## Non-functional requirements

- Deterministic fixtures/test runner; reproducible results from the same inputs and dependency versions.
- Backpressure, input-size/rate limits, timeouts, regex DoS protections and isolated parser execution.
- Do not put customer raw logs in telemetry, browser console, public bug report or GitHub.
- Original UI, accessibility and responsive behavior as specified in 02.
- Operational health, backup/migrations and tenant isolation contracts are defined before persistent/multi-user deployment.
- Deployment/release requires separate owner approval and applicable Engineering System gates.
