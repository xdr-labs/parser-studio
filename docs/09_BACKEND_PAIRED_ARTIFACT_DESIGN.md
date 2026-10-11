# 09 — Backend Design for Real Stellar Custom Parser Pairs

**Status:** Evidence-backed backend target based on authorized read-only SSH analysis of `rickmodular` and official vendor documentation. NO live server mutation, no deployment, no customer raw logs copied or committed. File format compatibility at the actual vendor upload boundary still requires isolated import tests.

## 1. Product output contract

The requested primary output is one matched asset pair from the reference directory:

```text
customized_<slug>.conf  # Fluentd receiver and routing
customized_<slug>       # Ruby code fragment containing parser behavior
```

**Nondeveloper authoring is the product.** No developer is required to manually edit Ruby or Fluentd config for baseline use cases; the backend compiles a version-neutral declarative project into both artifacts, with truthful syntax/native behavior diagnostics.

The target reference directory is:

```text
/opt/td-agent/etc/td-agent/customized_parser
```

This is a **reference asset directory**, **not** an automatically writable deployment target. Do not ever issue `cp`, `mv`, service reload/restart or overwrite against it from the builder. The user downloads files and follows an explicitly selected, authorized deployment path.

## 2. Measured inventory — 2026-10-12 (SSH via frp-e2e-client)

- Remote hostname verified: `rickmodular`; user `aella`; `td-agent` was running at the time of inspection.
- 454 `*.conf` files, each matched by a same-basename extensionless file; 455 extensionless files, with one unmatched `customized_ubika_waf`.
- All 455 extensionless files are Ruby-like source fragments, **not standalone JSON files**. `# STELLAR_INIT_BEGIN/END` and `# STELLAR_PARSE_BEGIN/END` delimit the generator-managed initialization and parse sections; 454 have the expected four-marker sequence and one has an extra INIT_BEGIN occurrence.
- A typical fragment defines `initialize`, `parse(text)`, extraction and normalization methods; 454/455 contain an explicit `def parse(...)`. `parse(text)` normally yields event time + parsed record through a Fluentd-style callback, but many product-specific variations exist.
- 429 fragments embed `@parser_rule_set = JSON.parse(...)` and 16 contain `@default_parser_rule_set = JSON.parse(...)` (not necessarily mutually exclusive). Counts are presence, not normalized distinct products.
- A structural extraction of embedded JSON found maps in 404 fragments for each of `top_fields`, `ns_fields`, `vendor_fields`. Aggregate mapping entry counts: 2,653 top, 3,914 namespace and 6,985 vendor (the presence of wildcard rules may contribute).
- Common field mapping attributes: `normalized_name` (6,259), `data_type` (3,501), `time_format` (81), `timezone` (23); field type values include integer, date, ip, object, mac, string, list, port. One observed typo `obejct` illustrates why an enum-based schema check matters.
- Across all `.conf` files, 434 had UDP source, 433 TCP source, 14 HTTP source, 453 rewrite-tag filter and 9 parser filters; 432 had two source blocks, 22 had one. 450 had `@type customized_<same-name>` directly; four exceptions use another input/parse/filter style. Do not force all 454 into a single template.
- 395 distinct ports appear; 32 port values are shared by more than one **stored** reference .conf. Such reuse is not proof of a live conflict.
- Example read-only structure analysis: `customized_ahnlab_edr`, `customized_aliyun`, `customized_cef`, `customized_a10_vthunder_adc`. `/opt/td-agent/embedded/bin/ruby -c` returned **Syntax OK** for ahnlab_edr, aliyun, cef and ubika_waf — **syntax only**, no runtime execution or test log evidence.
- `/etc/td-agent/td-agent.conf` includes `/etc/td-agent/include.conf`; that include list did not refer directly to `customized_parser`. Installed parser plugins under `/etc/td-agent/plugin/parser_*.rb` and active configs are distinct assets from the extensionless source snippets. **The conversion/registration path from an uploaded snippet to live plugin is not yet established.** Do not equate reference presence with active deployment.

All findings here are derived from aggregate patterns and sanitized structural inspection, **not a redistribution of vendor source code**.

## 3. Two reference file responsibilities

### `customized_<slug>.conf` — receiver + route compiler

The observed shape can contain:
- One or more `<source>` blocks with `@type udp`, `@type tcp` or `@type http`.
- `port`, `bind`, `tag`, `message_length_limit`, `delimiter`, framing behavior and transport-specific `@include` directives.
- Optional `<parse>` selecting `@type customized_<slug>`, or exceptional inline filter/record modifier styles.
- `<match customized_<slug>.**>` using `rewrite_tag_filter`; `<rule>` maps normalized `stellar_log_index` to Session, Threat, Syslog, Winlogevent and other supported event tags (with optional invert).
- Some legacy examples route from another field instead of `stellar_log_index`. The IR must model this rather than silently rewrite it.

### `customized_<slug>` — Ruby fragment compiler

The observed shape can contain:
- Two marked generator zones: `STELLAR_INIT_BEGIN/END` and `STELLAR_PARSE_BEGIN/END`.
- Constants and initialized regular expressions, parsing rule sets serialized as embedded JSON.
- A `parse(text)` entry point with error handling, yielding the event time and record.
- A raw-log preprocessing / tokenizing stage, optional JSON/CEF/KV/Syslog-specific work.
- Normalization and enrichment handling, including `top_fields`, `ns_fields`, `vendor_fields`, timestamp handling and origin metadata.
- Event class assignment into `stellar_log_index` and optional privacy/raw-log-capture handling.
- Helper methods and product-specific branches that may be unsuitable for a no-code IR. Preserve as opaque sections when importing, never quietly drop them.

**Renderer invariant:** both files share the identical identifier; parser registration/assembly is **not** invented. Instead, each export profile owns a tested wrapper/loader contract and emits only formats proven valid for that path.

## 4. Difference between host reference pairs and official portal upload formats

Official documentation distinguishes materially different surfaces:

- **6.4 legacy custom log parser workflow:** the developer supplies **parser file + config file**; portal asks for name, tenant and both uploads; names must match and a `#YYYY/MM/DD` date on line 1 or 2 controls displayed version; loading a parser may activate it immediately. Source: https://docs.stellarcyber.ai/6.4.xs/Configure/LogParser/Custom-Log-Parser.htm
- **6.5 modular Parser Studio upload:** the provided page specifically describes an upload of **one JSON** configuration for the Modular Parser; `cust_id` matches tenant, port constraints documented as 7000–8000 on that page; this is not the same as a Ruby-fragment pair. Source: https://docs.stellarcyber.ai/6.5.x/Configure/LogParser/Custom-Log-Parser.htm
- **7.0 documentation:** legacy upload is described as parser `.json` + `.conf`, modular upload as one JSON; modular port handling differs. Source: https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Custom-Log-Parser.htm

Therefore the **required initial export adapter is `host-customized-pair`** (`.conf` + extensionless Ruby fragment matching the sampled asset structure). The separate `portal-legacy-pair` and `modular-json` adapters are conditional; the extensionless Ruby snippet cannot automatically be passed off as the documented `.json` portal upload parser. A cross-version compatibility claim requires demonstrated runtime/import behavior **for that exact adapter**, not a generic statement that every version reads the same file.

The editor stays version-neutral; the **Download** panel asks for destination/workflow rather than selecting a Stellar version in the main editor.

## 5. Internal stable model — Parser Project IR v0.1

```text
ParserProject {
  id, revision, slug, vendor, product, sourceCategory,
  receiver: {
    protocols: [udp|tcp|http], port, bindPolicy,
    messageLimit, framing, delimiter, tlsProfileRef?
  },
  inputs: {
    logFormatFamilies, eventBoundaryPolicies, sampleSetRefs,
    headerProfile, multilineProfile?
  },
  extraction: [
    { id, inputPath, operator: syslog|cef|leef|json|kv|csv|regex,
      options, captures, when, priority, onFailure }
  ],
  normalization: {
    msgOrigin, topFields, namespaceFields, vendorFields,
    ignoreValues, typedConversions, timezonePolicies
  },
  enrichment: [ { operator, inputs, outputs, condition, options } ],
  classification: [
    { when, index: session|threat|syslog|winlogevent|other, order }
  ],
  expectedResults: [{ sampleRef, expectedFields, expectedIndex, policy }],
  unsupportedOpaqueBlocks: [{ sourceFileRef, spans, hashes, reason }],
  exportProfiles: [ { id, capabilities, evidenceRef } ],
  schemaRevision, testEvidenceRefs, manifestRef
}
```

*The representation is conceptual; finalized JSON Schema and server API validators are implementation deliverables.* Avoid embedding Ruby source as the primary editable state. Fields are typed and nested; transformations and classifications preserve order, constraints and failure behavior. The no-code UI operates on this declarative model.

## 6. Backend components and interfaces

```text
Web Guided Builder
       |
       v
Parser API / Project Service -- private versioned project/fixture store
       |
       +--> Import Analyzer -- .conf AST + marked Ruby section scanner
       |                    -- classify known / opaque legacy behaviors
       |
       +--> Rule Model Validator -- typed mappings, semantic schema, route checks
       |
       +--> Preview Engine -- best-effort structural hints ONLY (not PASS)
       |
       +--> Generator/Compiler
       |       +--> Fluent Config Renderer (*.conf)
       |       +--> Ruby Fragment Renderer (extensionless)
       |       +--> Optional future portal legacy JSON adapter
       |       +--> Optional future modular JSON adapter
       |
       +--> Isolated Runtime Test Worker
       |       +--> nonexecuting Ruby syntax check
       |       +--> selected Fluentd/plugin runtime fixture tests
       |       +--> strict stage trace and normalized output comparisons
       |
       +--> Artifact Packager -- pair, SHA-256, manifest, redacted test report
```

### Proposed API (subject to contract tests)

| API | Purpose | Output / invariant |
| --- | --- | --- |
| `POST /api/projects` | Create version-neutral project | project UUID, initial revision |
| `POST /api/projects/:id/samples` | Import private sample set | sample IDs, detected candidate formats; no public raw logs |
| `POST /api/projects/:id/analyze` | Field/format/route suggestions | confidence+reason per suggestion; no invented success |
| `PUT /api/projects/:id/draft` | Update IR with optimistic revision | validated project + structured diagnostics |
| `POST /api/projects/:id/import-pair` | Read supported pair and map known constructs | IR+opaque loss/unsupported report, original artifact hashes |
| `POST /api/projects/:id/preview` | Fast editor hints | explicitly provisional, bounded results |
| `POST /api/projects/:id/tests` | Run native fixture suite asynchronously | test job ID and pinned profile |
| `GET /api/projects/:id/tests/:runId` | Status/results with stage failures | truthful status + fixture hash, runner and stdout redacted |
| `POST /api/projects/:id/exports` | Compile target-specific bundle | required adapter, validation states, no production writes |
| `GET /api/projects/:id/exports/:exportId` | Download bundle | two matching files, manifest, hashes, evidence |

Include strict size limits, session authentication before multi-user service deployment, optimistic locking, controlled file names, request ownership and audit trail for created artifacts. No arbitrary path parameter may become a host filesystem write location.

## 7. Generation contract / valid templates

1. Validate unique `slug` against an allowlisted name regex; derive both file names deterministically.
2. Validate receiver configuration, protocol-specific capabilities, bind and framing, port range according to export adapter and **active target** reference data (not only stored example file ports).
3. Validate extraction order, rule branches and named field collisions. Show unmapped fields, lossy conversions and unsupported operators.
4. Validate normalization: `top_fields`, `ns_fields`, `vendor_fields`, `normalized_name`, `data_type`, `time_format`, `timezone`, origin metadata and ignore values. Explicit type values are enum checked; invalid spellings such as `obejct` cannot silently enter output.
5. Compile known operators with reviewed, supported renderer templates. Escape regex, JSON and Ruby contexts separately; interpolation must not evaluate arbitrary user code.
6. Keep generated `.conf` source/parser type/tag matching internally consistent. Support known alternate patterns via explicit capabilities rather than forced simple template.
7. Generate declared INIT/PARSE Ruby sections from portable IR; do not redistribute private/vendor source templates without verifying redistribution rights.
8. Run isolated syntax and **behavior** tests. A `ruby -c Syntax OK` is only a limited lint outcome; sample correctness, error handling, routing, enrichment and target wrapper/loader must be validated separately.
9. Package `customized_<slug>` and `customized_<slug>.conf` plus a manifest. Do not append `.rb` or `.json` to the required extensionless host reference file without an adapter contract.
10. Export status is one of `DRAFT`, `SYNTAX_VALID`, `ENGINE_TESTED`, `TARGET_IMPORT_VERIFIED`, `PARTIAL`, `UNSUPPORTED`, `PENDING_EVIDENCE`. Never rename syntactic success to compatibility PASS.

The generated artifacts use Stellar-specific conventions only to the extent proven through the authorized reference and target validation. Do not promise byte-for-byte reproduction of the proprietary implementation.

## 8. Testing / fixture contract

Use anonymized *synthetic* events derived from source **structure**, and owner-authorized real logs only in private fixture storage:
- Standard Syslog header and malformed header; JSON and nested JSON; CEF/LEEF; KV quoted/unquoted.
- Multiple log families from one product, event classification Session/Threat/Syslog, unknown/unmatched family.
- IPv4/IPv6 edge cases, port 0/65535/invalid, integer overflow, null/empty values and missing type mappings.
- ISO/RFC timezones and malformed timestamps, multiline and frame boundary policy.
- UDP and TCP configuration, mismatched tag/parse type, reserved and conflicting active ports.
- Regex no-match, backtracking/timeouts, encoding problems, Ruby syntax errors and dangerous interpolation cases.
- Regression: same fixture ID/rules/runtime hash must produce identical normalized event outcomes and rerun evidence.

**Test gates:** IR schema tests → generator snapshot/lint → sandboxed Ruby parser/native Fluentd fixture runs → browser user journey → isolated target import if available → production approval separately. No tests on the running `rickmodular` td-agent. A temporary runner in a separate machine/container is preferred.

## 9. Security and permission boundaries

Reference `rickmodular` is read-only in this research. Production or active parser deployment is separate high-risk, approval-gated work. Never edit /opt/td-agent, /etc/td-agent, user authentication, plugins, running service or port bindings from this product unless separately authorized.

No remote Ruby code, raw logs, mappings or proprietary parser body are committed to a public Git repo. The GitHub documents include only counts, file roles, known public configuration concepts, and safely transformed structural observations. Regex execution is bounded; arbitrary Ruby execution is prohibited outside a locked-down disposable runner. No automatic external AI upload of confidential data.

## 10. Immediate next milestone — P0

1. Freeze this pair-centric IR and define formal schemas with deterministic validations for filename, receiver, normalization and `stellar_log_index` routing.
2. Build testable no-code **Generate Pair** service for a small supported pattern family; create synthetic fixtures and RED tests before implementation.
3. Extend current three-pane local scaffold into the nondeveloper six-step Guided Builder; keep Workbench optional.
4. Verify first generated pair with a **sandboxed**, pinned native Ruby/Fluentd test runner, then inspect whether the target upload surface accepts that **specific** artifact format.
5. Mark anything requiring unavailable private loader rules or upload contract `PENDING_EVIDENCE`, do not guess.
6. Continue the roadmap without modifying live `rickmodular` configuration or copying proprietary source.
