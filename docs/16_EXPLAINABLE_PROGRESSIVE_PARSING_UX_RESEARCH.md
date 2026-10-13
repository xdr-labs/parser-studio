# Parser Studio 2.1 — Explainable Progressive Parsing and AI Repair

**Date:** 2026-10-13 KST. **Status:** Design research and planned requirements, NOT implemented or native qualified.
**Owner priority:** Users must see exactly which original log segments Auto Parser parsed, which rule captured them, which portions are not parsed, and how to correct wrong captures, optionally with ChatGPT/Claude/Gemini. Preserve unknown sections in a clearly labeled opaque field when target-supported instead of forcing an all-or-nothing regex.
**Navigation:** Exactly two creation methods, Auto Parser and ChatGPT Assisted Parser. This is an in-place result inspector, NOT a third workbench.
**Background:** [Corpus-first Parser Synthesis](15_CORPUS_FIRST_PARSER_SYNTHESIS_RESEARCH.md).

## 1. Open-source and published UX findings

| Inspected source | Demonstrated feature | Recommended adaptation |
|---|---|---|
| [Splunk Field Extractor](https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.4/use-the-field-extractor-in-splunk-web/field-extractor-select-fields-step) and [Validate Fields](https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/9.3/use-the-field-extractor-in-splunk-web/field-extractor-validate-step) | Highlight values in sample, choose field name, mark wrong captures as counterexamples, improve extraction using another example, optional manual regex editor | Click a wrong IP/field and state what it *should* mean; test regenerated candidate on all events |
| [CrowdSec explain](https://docs.crowdsec.net/u/user_guides/cscli_explain/) | Per-stage/eligible-parser outcome and exact transformation path | Explain which parsing stage succeeded or failed, not one generic error |
| [Wazuh decoders](https://github.com/wazuh/wazuh-documentation/blob/main/source/user-manual/ruleset/ruleset-xml-syntax/decoders.rst) | Predecode syslog envelope then parent/child decoders | Keep envelope vs body separate; display vendor subtype rule |
| [Cribl Regex Extract](https://docs.cribl.io/stream/regex-extract-function/) and [Parser](https://docs.cribl.io/stream/parser-function/) | Named captures, parse another field, ordered regexes and data-preview diff | Reparse selected troublesome substring only; preserve prior correct fields |
| [Logstash Dissect](https://github.com/logstash-plugins/logstash-filter-dissect) + [Grok](https://github.com/logstash-plugins/logstash-filter-grok) | Simple delimiter extraction of stable prefix followed by Grok for variable remainder | Structural extraction first, regex only where needed |
| [OpenTelemetry stanza regex_parser](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/pkg/stanza/docs/operators/regex_parser.md) and [on_error](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/pkg/stanza/docs/types/on_error.md) | Parse a selected field with named captures; send original downstream on failure | Partial parsing and no silent source discard |
| [Elasticsearch Grok trace_match](https://www.elastic.co/docs/reference/ingest-processor/grok-processor) | Reports which pattern index actually matched | Show rule identity and which variant took the branch |
| [Datadog Grok](https://docs.datadoghq.com/logs/log_configuration/processors/grok_parser/) | Example-based automatic rules; Match / Match with warning / No Match | Syntactic regex matching and semantically useful extraction are different statuses |
| [Drain3](https://github.com/logpai/Drain3) | Learn templates and masks from recurring variable free text | Apply only to the leftover unstructured body; never let it infer source/destination IP meaning |
| [RegExr](https://github.com/gskinner/regexr/) and [regex101 capture docs](https://docs.regex101.com/editor/groups/) | Real-time match highlighting and capture explanations | UI reference; RegExr is GPL-3.0, and JS/PCRE preview cannot prove Ruby target parity |
| [GrokConstructor](https://github.com/stoerr/GrokConstructor) | Incremental Grok pattern construction over multiple samples | Design inspiration; source GPL-3.0, no copying |
| [Google RE2](https://github.com/google/re2) | Resource-bounded, linear-time untrusted regex subset | Candidate sandbox inspiration only; native Ruby/Fluentd dialect can differ |
| [grex](https://github.com/pemistahl/grex) | Generates regex candidates from user-provided positive string examples | Apache-2.0. Good local candidate engine input, but selected strings alone cannot establish surrounding anchors or source/destination semantics; add contextual negatives. |
| [REGEL](https://github.com/utopia-group/regel) | Synthesizes regex candidates from natural language and examples with interactive positive/negative refinements | MIT. Research implementation, not immediately a Ruby-compatible native parser; explore algorithmic approach behind limited sandbox. |
| [Vector VRL](https://vector.dev/docs/reference/configuration/transforms/remap/) | Fallible parsing and explicit error/abort policy | Fail closed on target export and retain originals in preview |

**REA availability:** No connected REA-specific tool/plugin or REA executable was exposed in this session or on dev-atlas. Direct REA UI inspection was not performed. Instead, actual open-source modules and public interaction documentation were compared; later use REA only on authorized screens when it is connected.

## 2. Current Parser Studio capabilities vs missing parts

Already present and should be reused:
- browserRuleTrace reports rule-index statuses such as MAPPED, SOURCE_MISSING and TYPE_FAILED, with NO original source span positions.
- fieldHighlights uses ECMAScript match indices for one manually proposed field pattern; this is not a complete parse trace.
- Auto Parser has whole-sample event accounting, field mapping suggestions, targeted repairs, candidate regression and optional private Drain3.
- Concurrent, uncommitted complexLogRecovery work explores difficult CEF/LEEF/Fortinet *browser-only* recovery. It must be preserved and its results must not be called native parse success.
- ChatGPT Assisted generates a copyable redacted prompt and accepts limited v0.2 recipe changes, but currently does NOT compile arbitrary suggested regex/grammar.

Missing: a full per-stage, per-field, per-source-range trace; negative user feedback for incorrect semantic roles; explicit leftover capture as a target-safe field; user-understandable stage-specific repair; actual native operator semantics for supported declarative grammar candidates.

## 3. Top-down view in the existing Auto Parser result

Begin with a per-subtype table (e.g., Fortinet traffic 7, Fortinet UTM 3, Unknown 2) and a FULL/PARTIAL/RAW_ONLY summary; never aggregate unknown into silent success. Clicking an event presents:

    ORIGINAL EVENT (immutable)
      [SYSLOG HEADER] [VENDOR & SUBTYPE] [RECOGNIZED FIELDS] [UNPARSED REMAINDER]

    STAGE TRACE
      1. Framing       PASS — original input accounted
      2. Syslog header PASS — priority/time
      3. Type routing  PASS — Fortinet/UTM selected by exact type/subtype
      4. Body parsing  PARTIAL — two fields recognized, one field unknown
      5. Mapping       REVIEW — source/destination role ambiguous
      6. Ruby compiler NOT VERIFIED — some operators unsupported

This text schematic is a proposed user flow, not a real screenshot or test measurement.

For a highlighted selection, the contextual panel offers:
- **Correct field:** user points to the real source IP and names its role; current incorrect selection becomes a negative example.
- **Improve rule:** deterministic candidate first, optionally copy redacted example to ChatGPT, Claude or Gemini; show up to 3 candidate rules, affected events and risks.
- **Keep as one field:** preserve a stable difficult chunk as an opaque string, only when backend/schema allow it; FULL is not claimed.
- **Fix type routing:** a Palo Alto PAN-OS THREAT message should not reuse TRAFFIC positional CSV indices.
- **Keep original:** no change, but retain source and explicit PARTIAL/RAW_ONLY status. There is no user-approved silent drop.

A contextual **Advanced Rule Inspector** shows pattern ID, branch, parser stage, named capture, byte range, raw and normalized output, and whether that pattern is JS-preview-only or native verified. It is not a new parser-creation method.

## 4. Source-span ParseTrace contract, designed before UI code

Define a new versioned, local-private ParseTrace tied to the original source SHA and grammar revision. Each original event has:
- unique event identity and exact original UTF-8 byte length;
- ordered stages {stage_id, input_field, operator, rule_id, match_status, outputs, verification_level, failure_reason};
- spans {source_begin_utf8, source_end_utf8, browser_begin_utf16, browser_end_utf16, role, field, capture_name, rule_id, stage_id};
- sorted structured ranges, syntax/delimiters, opaque/unparsed ranges, overlaps, and any dropped ranges (which MUST be empty for an accepted candidate);
- user-approved positive and negative semantic assertions on exact ranges and field values;
- independent counters for FULL, PARTIAL, RAW_ONLY, invalid and native-not-verified events.

All ranges are half-open [start,end). Keep UTF-8-byte offsets and browser UTF-16 indices **both**, because repeated substrings, non-ASCII and Ruby vs JavaScript indexing can make naïve string searches highlight the wrong occurrence. Track transformation provenance from normalized field back to original span; no patch may claim a source substring it did not consume.

Never confuse **byte accounting** or "regex matched" with **correct semantic field extraction**. A single catch-all group might account for every byte while extracting none of the important fields. Show separate event accounting, mandatory field semantic coverage, optional capture coverage, and native-qualified variant count. Users must see that FULL is a semantic+runtime status, not simply a whole-line regex match.

## 4A. Selection-first parsing — the user reduces the problem

**New explicit owner clarification (2026-10-13):** Long and unfamiliar log records may be too ambiguous for a single parser or regex to infer. Let the human **drag/select a meaningful subspan**, tell Parser Studio what it means or where a sub-parser should work, and apply search/grammar synthesis only inside that scope. This is **programming by example** with human-provided boundaries, not merely an expert regex editor.

### One selection, four context-sensitive intentions

1. **Extract selected value as a field:** user highlights just an IPv4 address, URL, username, timestamp, status or arbitrary text and assigns the intended semantic field. The selected range is one positive example, *not* automatically a general-purpose regex.
2. **Parse inside this block:** user highlights a larger quoted message, JSON fragment or vendor extension and declares it a nested sub-parser input. The engine preserves already-approved surrounding fields and proposes a quote-aware KV, JSON-path, delimiter/Dissect or bounded regex subrule only for that exact region.
3. **Use this as a boundary/anchor:** user selects stable text such as a field prefix, separator or vendor subtype discriminator. The system infers where a substring starts/stops before matching its variable value. Disambiguate repeated copies of the same text by their precise original byte ranges, not substring searching.
4. **Keep the whole selection as a single opaque field:** user prefers source preservation over unreliable detailed extraction. This is PARTIAL or RAW_ONLY until true required fields and native support are independently verified; the complete original event remains retained.

On desktop: mouse drag in a read-only, copyable text view. On mobile: native text selection plus a visible contextual toolbar. Never block normal copy/paste or require a fixed-length selection. UTF-8/UTF-16 source offsets, empty/all-whitespace spans, overlap with prior fields, repeated identical values, overlong selections and line-framing boundaries require explicit validation.

### Concrete interaction example

Original event (documentation-only fictional address):

~~~text
<189>date=2026-10-13 action=deny srcip=192.0.2.10 dstip=198.51.100.20 msg="Rule blocked GET /a?token=REDACTED"
~~~

The user drags only the first IP string and labels it Source IP. The system records:
- exact selected source range, current envelope/body variant and adjacent literal context such as srcip=;
- a positive assertion that this *specific* source span belongs to Source IP;
- a negative assertion that the destination IP and other IP-shaped values must NOT map to Source IP;
- a **ranked rule candidate**, first prefer the existing typed KV lexer + source key, not a regex merely matching any IP address;
- an equivalent scoped regex/Grok/Dissect explanation in an optional Rule Inspector **only when one can be represented safely**, labeled Browser Preview or Native Compilable honestly.

When the user highlights the quoted msg value and chooses **Parse inside**, the system proposes a nested rule applying only to msg. If that grammar cannot be proven across other events, Keep as one field retains it under a target-supported vendor field without losing the already extracted action and IP fields. This does NOT mark the entire log FULL.

### Proposed UI disclosure inside Auto Parser

After source paste, present a variant summary and the intact source, colored by extraction role and opaque/unmatched spans. A drag selection opens a **small inline toolbar**, not a third authoring method:

~~~text
[Selected text: "192.0.2.10"]
[Extract as field] [Parse this part] [Use as boundary] [Keep as one field]
             [Suggest rule locally] [Ask ChatGPT / Claude / Gemini]

Candidate 1: quoted-KV key "srcip" -> typed IPv4 -> source.ip
Candidate 2: bounded anchored rule -> named capture source.ip (browser only)
Coverage: 9/10 records for same vendor subtype; 1 excluded/unknown
Negative examples: destination.ip unchanged; no wrong-role matching
Native compiler: check / NOT VERIFIED; target: NOT VERIFIED
[Compare original vs candidate] [Approve rule] [Cancel]
~~~

The numbers above are illustrative placeholders, **not benchmark results**. The exact true coverage must be computed from selected positive, negative, sibling subtype and holdout samples before presenting an acceptance button.

### Candidate generation strategy, local first

- Detect the selected value's plausible types but do not choose its security meaning from appearance alone (two IPs may have different roles).
- Identify stable **prefix/suffix boundaries**, quote/escape context and existing typed tokens; infer simplest deterministic rules first.
- Propose a scoped candidate AST with operator, anchor, source span, field role, source subtype and matching dialect.
- Evaluate up to three alternatives on all current variants, held-out unseen events and explicit wrong-match counterexamples; measure true field values, not just regex matched/not-matched.
- Prefer a simple key-based or positional parser to a regex if it is more stable. Use a bounded regex only for genuinely variable free text.
- Show the actual candidate rule and capture-highlight spans for *every* matching event and mark wrong/overlapping matches visibly.
- Require user approval and native Ruby/CONF lowering and parity before production-ready export; if operator unsupported, retain a REVIEW_ONLY suggestion rather than fabricating success.

A single dragged value often has many compatible expressions. **At least one additional variation or user-marked negative** should be sought for meaningful generalization. If the user supplies only one example, show Low Evidence, not a false accuracy percentage.

With several selected chunks, build a small **hierarchical parse plan** (stable prefix -> variant discriminator -> bounded sub-parser for the selected message), rather than concatenating every learned capture into one enormous regex. Each sub-parser has its own input span, fallback and evidence; reusing the same successful prefix rule across variants cannot silently reuse incompatible subtype positional CSV schemas.

### What "Improve with AI" really means

The design must label three distinct operations honestly:
- **Suggest rule locally:** deterministic grammar inference in Parser Studio, no real LLM or third-party request.
- **Ask an AI model (manual copy/paste):** generate a user-reviewed, redacted provider-neutral prompt, the user opens their chosen ChatGPT/Claude/Gemini and pastes back its proposed structured grammar. This uses a **real external LLM only when the user intentionally sends that prompt**; Parser Studio itself does not invoke it.
- **Connected LLM (future opt-in):** directly call a real model only after separate provider connection, explicit approval of each transmitted sample, backend-held credentials, egress audit, tenant security and strict response validation. This is NOT implemented today and must not share the local button's label or appear as already connected.

The suggested grammar is **untrusted output regardless of provider**. Never execute copied Ruby, shell commands or arbitrary regex in the native target simply because ChatGPT proposed them. Report regex dialect limitations (JavaScript/RE2/Oniguruma/Fluentd) alongside evidence and compiler reachability.

### First acceptance tests for selection-driven synthesis

- Selecting identical IP text twice in one event identifies the correct occurrence by offset; wrong-role captures become negatives.
- Selecting a quoted message containing spaces, escaped delimiters or equal signs does not corrupt previously accepted header/field spans.
- One user selection must not silently apply to unrelated vendor subtypes; preview displays explicit no-match/unknown cases.
- User selection plus an independent negative changes candidate ranking; field-role false positives must remain zero on curated examples.
- Partial opaque retention cannot overwrite approved fields, must maintain exact original bytes, and cannot claim FULL/native if unsupported.
- Prompt generation exports only user-reviewed redacted span/context and never automatically sends customer raw logs.
- Native export from a new syntax is blocked until backend actually implements and validates that operator.

**Priority decision:** Treat the drag-to-teach selector as part of P0-TRACE-1 and P0-TRACE-2, immediately after P0-TRACE-0 source-range provenance. Do not create a third "AI mode" or a separate regex-heavy wizard.

## 5. Opaque fallback instead of all-or-nothing

Propose a declarative operation capture_opaque(field, exact_source_range, origin_rule), NOT unbounded dot-star regex. Preserve complete immutable original event and a separate validated opaque tail. A chunk may be kept as a single vendor/custom field if:
- original framing and boundaries are known;
- ranges do not silently overlap approved structured captures;
- target field name, size, encoding, privacy, escaping and Ruby/CONF loader support are actually verified;
- mandatory fields (time, classification, useful security source/destination roles) are explicitly reported missing if absent.

Opaque bytes count as PRESERVED but NOT correctly parsed. If native lowering is unavailable, show a browser-only PARTIAL preview; do not export a misleadingly verified parser. Retaining only the original message is RAW_ONLY, not an achieved field parser. Control privacy and payload size; no automatic third-party AI transfer.

## 6. Progressive repair and test gate

User correction becomes a structured positive/negative test, not just a different regular expression string:

    user clicks a wrong match
      -> select expected field role or mark "not a match"
      -> record variant-scoped assertion and original byte span
      -> rank structural/typed/Dissect/Grok/regex grammar candidates
      -> replay old positives + new counterexample + sibling variants
      -> independent holdout
      -> show precise changed spans and before/after normalized field diff
      -> user confirms one candidate
      -> native Ruby/CONF compiler and Fluentd parity must PASS before export

Prefer high-value field precision and avoiding false positives over maximizing total matched text. An incorrect source IP is worse than an explicitly unknown tail.

AI prompts remain **manual provider-neutral copy/paste**, containing only user-approved redacted examples, expected fields, stage errors, uncovered ranges, current capability matrix, and negative examples. The pasted result is untrusted candidate grammar AST data; regex is REVIEW_ONLY until a bounded sanitizer, matching-dialect check, counterexample regression and actual native compiler parity pass. Do not execute arbitrary LLM Ruby/JS/JSONata. Unavailable operators must show an actionable reason such as "The proposed Grok operation is not yet supported by the native target compiler."

## 7. Owner-prioritized development batches

| Order | Task | Acceptance |
|---|---|---|
| P0-TRACE-0 FIRST | ParseTrace contract with exact original spans, rule provenance and status taxonomy | Every input record accounted; Unicode/multiple-identical-token range tests; no silent omissions |
| P0-TRACE-1 | Original-log overlay, mouse/touch drag-to-teach selector, context toolbar, rule-click inspector and stage-specific guidance inside Auto Parser | User sees original matched/unmatched substrings and selected candidate regex/typed rule with capture spans; no regex knowledge required |
| P0-TRACE-2 | User-selected positive/negative assertions, subtype-scoped candidate ranking and explicit opaque unmatched ranges | Wrong capture feedback changes tested rules; selected multi-chunk parse plan stays scoped; PARTIAL vs FULL and native capability guard |
| P0-SYN-1/2 | Vendor/subtype envelope/typed grammar and candidate ranking | Fortinet/PAN-OS/Trellix/Trend Micro with negative source/destination cases |
| P0-TRACE-3 / P0-SYN-3 | ChatGPT/Claude/Gemini structured candidate rule/regex review | Up to three bounded hypotheses, new positive/negative checks, zero raw external transfer |
| P0-SYN-4 | Actual native Ruby/CONF lowering for selected safe v0.3 operators | Same sample and holdout native Fluentd parity, SHA check, no unapproved operator |
| P0-SYN-5 | Real vendor corpus and user E2E qualification | Field-role correctness, subtype coverage, false-match rate and operator correction clicks |
| GATED P0-LIVE | Owner-authenticated DP Apply + exact same CONF/sensor port + timed synthetic replay | Explicit separate authorization and true target readback; do not claim sensor receipt from socket writes |

The above P0-TRACE steps are the **first part of the existing P0-SYN roadmap**, not a parallel competing roadmap. First use previously sanitized synthetic complexLogRecovery examples without altering its dirty original worktree. Add published manufacturer raw fixtures only after rights and redaction review. No additional Test Lab UI until core parser explainability is credible.

## 8. Safety, licensing and what remains unproven

- RegExr and GrokConstructor are GPL-3.0 UX references; avoid source copying. Elastic integrations / Beats x-pack default to Elastic License 2.0 unless file-specific overrides. All vendor fixtures require per-file license and sanitization checks.
- RE2 preview semantics cannot prove Ruby Oniguruma/Fluentd compatibility.
- Not implemented today: full ParseTrace, opaque native lowering, generalized regex/Grok compiler, interactive counterexample synthesizer, REA run, or real DP/sensor E2E. This file records proposed product behavior, not test PASS.
