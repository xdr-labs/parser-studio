# 08 — User-first, No-code Parser Studio: Product UI Contract

**Priority: P0, accepted product direction.** The principal user is a field SE, partner, customer administrator or analyst who knows the logs but **does not write Ruby, Regex or Fluentd configurations**. The application replaces the external parser developer's authoring and debugging labor. The developer is an exception persona, not the default user.

## North-star acceptance

> Given real raw logs and a device identity, a first-time user can configure extraction, Stellar Cyber normalization, event classification, transport and tests, then generate a matched pair of files — **`customized_<slug>.conf` and `customized_<slug>`** — without entering code. The files must be checked against a native isolated parser runner and presented with precise compatibility limits and deployment instructions.

**Never conflate:** A generated legacy host reference pair, a legacy portal upload pair, and the newer Stellar Cyber modular JSON configuration are distinct export adapters until end-to-end equivalence is proven. Authoring never requires selecting a Stellar version.

## Why this changes the prior prototype

The existing three-pane Workbench is useful for technical debugging but cannot be the primary entry flow for nondevelopers. Keep it as an **Expert / Detail View** behind the default **Guided Builder**, with task-oriented labels instead of source-code jargon. The user should not need to understand `parse(text)`, `@parser_rule_set`, `<source>`, `stellar_log_index`, Ruby or regex. Advanced editing is optional and always followed by native tests.

## Primary navigation

1. **My Parsers** — create, clone, import an existing legacy pair, list saved drafts, edit, version compare, templates.
2. **Create / Edit Parser** — a continuous six-step Guided Builder with persistent progress and visible test state.
3. **Test & Debug** — failed examples and changed-output comparison; one-click return to the rule or field responsible.
4. **Generated Files** — pair download, manifest, validation evidence, upload guide and compatibility status.
5. **Reference Library** — vendor/product starter templates, anonymized pattern library, searchable Stellar field dictionary.

Advanced settings (templates, runtime profiles, privacy, schema update) are not surfaced in the first-time creation flow.

## Six-step guided creation flow

| Step | User question | Non-code UI capabilities | Generated backend concepts | PASS evidence |
| --- | --- | --- | --- | --- |
| 1. Add logs | "Which logs do you want to support?" | Paste/upload many entries; drag files; sample sets by event type; distinguish physical lines vs logical events; detect Syslog/JSON/KV/CSV/CEF/LEEF/multiline; preview malformed encodings and timestamps; redact sensitive values | Fixture set, event breaker, format family and feature candidates | No missing/unreported sample records |
| 2. Extract fields | "What information is in this log?" | Highlight raw string and click **Create Field**; auto-extract Syslog header, quoted KV, nested JSON, CEF/LEEF; rename fields; mark optional/required; conditionally select variants; inspect per-example match ranges | Ordered extraction graph, named captures, parsers, conditionals | Each field has evidence across every relevant event variant |
| 3. Map & enrich | "How should Stellar Cyber interpret it?" | Searchable recommended destination fields; source→target drag/select; top-level/namespace/vendor tabs; type conversions (IP, port, date, integer, boolean, MAC), timezone/unit selection; ignore-value set; constant/derived fields and safe lookup templates; origin vendor/product metadata | `top_fields`, `ns_fields`, `vendor_fields`, transform/enrichment rules, `msg_origin` | No hidden type or field collisions; output is well typed |
| 4. Classify & receive | "How will logs arrive, and where should each event go?" | UDP/TCP/HTTP, receiving port and bind, message length, TCP delimiter/frame policy; labels and tag routing; category presets **Session / Threat / Syslog / Winlogevent** and explicit conditions; detect active-target port conflicts | Two-file config receiver/source, transport directives, `stellar_log_index` and rewrite-tag rules | Every selected event has an explained classification and a valid supported transport config |
| 5. Test and repair | "Does the parser work for all sample logs?" | Run entire fixture suite; side-by-side original/extracted/normalized; per-stage explainable trace; identify failures with reason and exact field; click-to-fix; golden expected output, revision diff, count of unmatched/skipped; never mark no-tests green | Sandboxed native engine, golden fixtures, regression report, hashes, capability evidence | Native runner and output checks PASS for declared target; unknowns remain explicit |
| 6. Generate & use | "Which files do I need?" | One-click **Generate Parser Files**; validate parser/CONF name pair; list file contents and metadata; download two files and ZIP; attach redacted report and manifest; guided vendor UI upload, tenant selection and test checklist; optional alternate modular JSON export when proven | Artifact compiler/renderers, syntax lints, manifest, export profile | Checked generated pair; no automatically deployed changes |

Default top CTA: **Continue** / **Run Test** / **Generate Parser**. Never default to **Edit Ruby** or require **Enter Regex**.

## Mandatory interactions and error prevention

- **One-click field extraction:** selecting a token in the original log highlights matching occurrences in all events; preview alternative safe patterns; persist the selected rule only after explicit confirmation.
- **Rule inspection, not code requirements:** show plain-language summaries ("extract the source IP after src=", "treat this as a timestamp in UTC") with optional Advanced panel revealing the actual pattern.
- **Multiple log types from one source:** branch by signatures and test all known variants, including outliers, before the parser can be marked ready.
- **Mapping UX:** auto-suggest `src_ip → srcip`, `dst_ip → dstip`, `src_port → srcport`; never silently invent vendor schema semantics. Clear warnings for missing fields, duplicate destination, unsupported types, invalid IP/port and timezone mistakes.
- **Classification UX:** event types are expressed as if/then conditions, not raw `rewrite_tag_filter` rules. Show exactly why an event became Threat, Session, Syslog or another supported type.
- **Receiver UX:** choose transport and port; validate permitted ranges according to the selected **export capability profile** and check collisions against **active configurations**. Stored sample assets sharing a port do not alone prove a live conflict.
- **Two-file integrity:** the generated `customized_<slug>.conf` and `customized_<slug>` must reference the same identifier; no separate free-text name is required for routine use.
- **Errors in context:** malformed regex, unmatched header, incomplete conversion, missing tenant, export loss, runner unavailable and incompatible upload adapter show actionable explanations; no green badge if untested.
- **Real-time feedback:** browser suggestions are labeled provisional; use a native isolated runner for verified results.
- **User privacy:** real log content and vendor parser source stay in private runtime storage by default. No automatic AI request, analytics payload or public Git commit of customer artifacts.
- **Accessible UX:** Korean-first / English-ready labels, keyboard operation, contrast, autosave and meaningful progress indicators. Desktop first; small-screen results readable.

## Advanced mode (optional)

Expert Workbench displays raw logs | extraction/transformation rules | JSON/Interflow output as the already-defined three-pane layout. It may allow direct regex, Ruby source, multiline rules, AST diagnostics, JSON field mapping and export diff. Any unsupported manual Ruby feature is an **opaque advanced block** and cannot be claimed safely GUI-round-trippable.

## Import / clone requirements

- Open paired legacy artifacts from the private host reference path, or from uploaded two files, as **read-only originals**, then copy into an editable project.
- Identify known sections and embedded mappings; preserve unknown/custom Ruby without silent rewriting.
- If parsed custom code cannot be represented by the GUI, display `Advanced code: read-only / explicit expert edit required` and keep the original intact.
- Support **Start from scratch**, **Clone a similar parser**, and **Import an existing parser pair**. A novice never needs to browse a 9,000-line Ruby file.

## Screens and required UI states

| Screen | Essential controls | Clear state |
| --- | --- | --- |
| My Parsers | New, clone, import, search, dataset status, last test, last export | Draft / Tested / Export Verified (different) |
| Guided Builder | Six-stage stepper, sample selection, next action, save, explanations | Incomplete stages visible without blocking unrelated edits |
| Raw Sample Analyzer | Dropzone, multiline toggle, detected format, sample family, sensitive fields | 0 samples is NOT PASS |
| Visual Field Extractor | Highlight span, extraction menu, field chips, preview matching across samples | Matched / Partial / Failed with actual denominators |
| Normalization Mapper | Target schema search, source/target/type, preview, suggestions | Warnings with exact field and remedy |
| Receive & Route | Protocol/port, frame rules, category builder, route preview | Distinguish hypothetical and active port conflicts |
| Test Lab | Per-event trace, error groups, before/after diff, regression suite | Browser preview vs isolated native engine vs target import |
| Download & Guide | Two filenames, contents, ZIP, hashes, config warnings and upload steps | Verified only for exact supported adapter/runtime |
| Expert Workbench | Three resizable panes, advanced code tab, lint, compare | Unsupported round-trip segments clearly preserved |

## UX acceptance scenarios (must eventually be Full User E2E)

1. A nondeveloper inputs 20 mixed events, uses no Ruby/regex input, generates an internally consistent two-file pair.
2. A selected source value can become a field and be mapped to a typed destination in at most a few obvious actions.
3. A badly formatted timestamp causes a visible error identifying the event, input field and conversion policy.
4. A minority log variant with no match remains visible; it is never silently dropped from the completion score.
5. Same-port separate saved templates are warnings, but a demonstrated live active-target collision blocks export/deploy where required.
6. A novice configures UDP+TCP and chooses Session/Threat/Syslog classification without writing Fluentd configuration.
7. The user downloads exactly the intended two files with matching names and verifiable hashes; confidential raw data is not included unintentionally.
8. A parser file that passes only `ruby -c` is **not** shown as end-to-end PASS without fixture/engine evidence.
9. An imported unknown Ruby branch can be viewed and preserved without false GUI support.
10. Neither local preview nor an export button can publish or install anything on a running sensor.
11. The export screen distinguishes the host reference pair, legacy portal upload, and modular JSON and explains support evidence without requiring a Stellar release selector during editing.

## Canonical scope and dependencies

This specification supersedes any earlier emphasis on Expert Workbench as the *primary* experience. Technical implementation guidance is in [09_BACKEND_PAIRED_ARTIFACT_DESIGN.md](09_BACKEND_PAIRED_ARTIFACT_DESIGN.md). Adopt official vendor document behavior as external context, but never assume a proprietary Ruby snippet is already a valid vendor portal upload file.
