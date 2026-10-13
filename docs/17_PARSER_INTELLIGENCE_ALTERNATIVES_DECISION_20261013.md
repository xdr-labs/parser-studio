# Parser Studio 2.2 — Architecture Decision: Retrieve, Decompose, Ask, Repair, Verify

**Research date:** 2026-10-13. **State:** Decision proposal supported by external source review, not an implemented feature or measured performance improvement. **User question:** Is drag-to-select/AI regex synthesis the best way to build easy, reliable heterogeneous security log parsers? **Answer:** No, not as the default. It is valuable as an exception-handling interaction within a more capable automatic engine.
**Scope:** Keep exactly Auto Parser and ChatGPT Assisted Parser. Continue using Draft UI PR #7 as verified baseline and Draft documentation PR #12 for design. Preserve all concurrent uncommitted development work.
**Related research:** [Corpus-first synthesis](15_CORPUS_FIRST_PARSER_SYNTHESIS_RESEARCH.md) and [Explainable parsing with drag-to-teach](16_EXPLAINABLE_PROGRESSIVE_PARSING_UX_RESEARCH.md).

## Decision

Use **retrieval-augmented, typed, progressive parser synthesis with active human feedback and optional LLM assistance**:

1. REUSE: Match vendor, product, variant and software version to a legally reusable and runtime-compatible existing parser/schema/field map BEFORE inventing new regex.
2. DECOMPOSE: Separate transport boundaries, syslog header, vendor subtype, structured body and optional unstructured tail. Apply deterministic JSON/KV/CSV/CEF/LEEF/native parser operators to each suitable subregion.
3. EXPLAIN: Maintain an immutable original event and a source-span ParseTrace: precisely what rule/field/variant succeeded, failed or remained opaque. Make extracted field *semantics* distinct from syntactic match status.
4. ASK: When multiple plausible grammars disagree about a high-value source/destination IP, timestamp, user, action, event type or source boundary, present the **single shortest discriminating question** with already highlighted alternatives. Do not demand that novice users know how to drag or write regex before anything works.
5. TEACH: Provide optional mouse/touch drag-to-select only for unexplained/wrong regions or when suggested choices are insufficient. User can label a field, reject an incorrect match, mark a stable anchor, parse within a block or explicitly retain a difficult block intact.
6. REPAIR: Generate 1–3 bounded, typed declarative grammar candidates; rank against positive, negative, variant sibling and independent holdout evidence. A real LLM is consulted only through explicit reviewed-redacted manual prompt exchange (or a separately authorized future connector).
7. VERIFY: Compile only implemented AST operators into a version-compatible **specific target dialect**; run actual native Ruby/Fluentd differential tests, exact SHA checks, semantic field assertions and gated owner E2E. Unsupported candidates remain REVIEW_ONLY, NEVER deployable.

This supersedes treating P0-TRACE-1 drag-to-teach as the primary data-entry method. It remains an important optional recovery affordance; retrieval, decomposition and discriminating questions make it significantly easier.

## Survey evidence beyond the prior research

| Method/reference | Independent observation | Product design consequence |
|---|---|---|
| [Google SecOps custom parser](https://docs.cloud.google.com/chronicle/docs/event-processing/configure-custom-parsers), [parser extension](https://docs.cloud.google.com/chronicle/docs/event-processing/using-parser-extensions), [self-service options](https://docs.cloud.google.com/chronicle/docs/event-processing/self-service-parser-options) | Supports building custom parsers from existing parsers and minimally extending a working base; auto extraction for structured data; complex Grok/logic reserved for harder cases. Extensions cannot fix errors in a broken base parser. | Catalog/profile reuse FIRST. Only use extension semantics when the base is correct and target-native support exists. Don't assume every existing parser can safely be augmented. |
| [Google SecOps important fields policy](https://docs.cloud.google.com/chronicle/docs/ingestion/standard-parser-support-policy) | Normalizing most important security fields is prioritized over every available field. | Explicit per-source **security semantic contract**: event time, event type, source/destination IP & port, action, user, product, optional raw tail. Correct high-value roles matter more than consuming 100% of bytes. |
| [Stellar Cyber Parser Studio, version-specific](https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Parser-Studio-Parsers.htm) | Some versions support clone a prebuilt modular parser and adapt it. Legacy Ruby/CONF, legacy JSON/CONF and modular JSON are distinct contracts/version paths. | Support runtime-specific template discovery/capability. NEVER silently upload generated Ruby/CONF as modular JSON or claim cloning is possible for every target/version. Owner-based authorization remains required. |
| [Splunk Field Extractor validation](https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/9.3/use-the-field-extractor-in-splunk-web/field-extractor-validate-step) | User marks an incorrect capture as a negative counterexample and extraction may be improved. | Keep drag selection or existing highlighted-capture correction as OPTIONAL negative feedback, not mandatory initial parsing. |
| [Interactive Log Parsing via Light-weight User Feedback, WWW 2023](https://arxiv.org/abs/2301.12225) | Framework demonstrates that limited lightweight feedback can improve template mining across multiple benchmark methods. This is *template mining*, not a fully verified vendor security field compiler. | Active learning question prioritization: ask one meaningful source/type/field question when candidates disagree, then regenerate only affected variant. |
| [SCOPE, ICPC 2026](https://arxiv.org/abs/2603.27247), [scopeLog code](https://github.com/Fan-Dongyi/scopeLog) | Hybrid syntactic/semantic online template parser uses bidirectional trees and selective LLM fallback, reducing dependence on frequent model calls. | Cache successful grammar branches and query LLM only for genuinely novel/ambiguous residuals. Published paper figures are NOT proof of Stellar normalized-field correctness. |
| [SCULP 2026](https://github.com/lezhang-thu/SCULP), [LibreLog](https://github.com/zeyang919/LibreLog), [LUNAR](https://github.com/logpai/LUNAR), [LILAC](https://github.com/logpai/LILAC), [LogBatcher](https://github.com/LogIntelligence/LogBatcher) | LLM parsing research explores unsupervised prompts, self-correction, caching and batching; implementations and model APIs vary. | Borrow an offline cache and candidate self-check loop; no per-log LLM dependency, no assumption LLM-generated template maps correct source/destination semantics. Confirm project-specific code licensing before reuse. |
| [SemParser, ICSE 2023](https://github.com/YintongHuo/SemParser), [variable-aware abstraction study](https://arxiv.org/abs/2304.11391) | Separating structure and variable meaning is an explicit research theme; generic log template algorithms mask values without necessarily extracting their security roles. | Maintain **semantic correctness assertions** separately from template grouping/regex coverage. A source IP, destination IP and NAT IP all satisfy the same generic IP regex. |
| [Loghub-2.0 benchmark](https://github.com/logpai/loghub-2.0) and [ISSTA evaluation](https://arxiv.org/abs/2308.10828) | Millions of labeled log lines and rare templates expose limitations of evaluation on only small or frequent samples. | Don't benchmark only happy-path fixtures; score holdout/unseen subtype and rare errors, with separate event routing, template, typed field precision and native parity metrics. Loghub-2.0 is mainly **system logs**, not directly a security-vendor field map benchmark. |
| [Cribl Regex Extract](https://docs.cribl.io/stream/regex-extract-function/), [Cribl Parser](https://docs.cribl.io/stream/parser-function/) | Named captures target a specific source field, with ordered functions and before/after data preview. | Implement scoped sub-parsers and rule provenance, not a giant whole-record expression. |
| [grex](https://github.com/pemistahl/grex), [REGEL](https://github.com/utopia-group/regel) | Positive examples and program synthesis can generate regular expressions. | Useful **candidate generators**, not an automatic semantic field or exact Ruby compiler. Plain grex output can overgeneralize absent negative examples and its regex dialect is not Ruby. |
| [Snorkel](https://github.com/snorkel-team/snorkel), [OCSF schema](https://github.com/ocsf/ocsf-schema) | Weak labeling patterns and typed normalized event schemas can guide field-role mapping. | Consider reusable **field synonym/semantic hints**; do not add a full model training pipeline as a P0 prerequisite. |
| [CrowdSec hub](https://github.com/crowdsecurity/hub), [OpenTelemetry stanza](https://github.com/open-telemetry/opentelemetry-collector-contrib) | Modular parser stages, fixture-first tests and explicit fail/retain/route behavior. | Operator-level traces, native capability checks and raw-tail preservation with honest partial status. |

**License and deployment caveat:** The Elastic integrations and Beats x-pack vendor references typically default to Elastic License rather than Apache-2.0, and some academic repos have no clearly reusable code license. Read-only review is not permission to distribute their input fixtures or copy their parsers. The local vendor reference inventory may be queried only under owner permissions and with tenant isolation.

## Options evaluation (qualitative design judgment, NOT experimental scores)

| Candidate default architecture | Beginner effort | Semantic correctness control | Unknown/vendor variance | Real Ruby/CONF compatibility | Decision |
|---|---|---|---|---|---|
| A. Regex editor with user drag-to-teach | High, user must supply boundaries/labels | Medium only if negative examples | Weak–medium | New compiler still needed | **Reject as default. Keep optional** |
| B. Give whole log to LLM and execute regex/Ruby | Low in UI; high hidden rework | Low without trustworthy verifier | Medium/high for a few samples, unstable for drift | Unsafe/unproven | **Reject** |
| C. Drain3/SCOPE template mining alone | Low | Low for security field meaning | Good at similar text clusters | No direct vendor parser codegen | **Use only as discovery and residual clusters** |
| D. Vendor parser catalog, clone or extension only | Low for known variants | High with verified reference semantics | Weak for completely new families/versions | High if specific native target profile proven | **Make primary first pass** |
| E. Catalog + typed grammar decomposition + small user questions + optional drag/LLM + native verifier | Low for known inputs; asks help only on ambiguity | Best controllable design under explicit tests | Strongest credible coverage strategy | Enforced by capability-lowering gates | **Choose as product direction; engineering hypothesis until benchmarked** |

Accuracy and ease of use have NOT been measured on the product. The table ranks feasibility/operational risk, not observed empirical superiority.

## User journey (exactly two creation methods)

### Auto Parser

1. User pastes raw vendor logs; without choosing CEF/JSON/CSV, system automatically groups families, identifies source variants and looks for a compatible pre-validated profile.
2. It decomposes what is confidently structured, then shows a concise result such as: **Recognized 8 Fortinet traffic, 2 Fortinet UTM; 1 unknown**; separate fields: correct/ambiguous/missing; **native status not proven**.
3. If a necessary high-value field has two possible answers, the UI asks a **single choice**: "Which highlighted value is the actual destination IP?" rather than asking the user to manipulate regex.
4. A context-sensitive Advanced view makes original spans and exact parser operators visible. The user may drag the wrong region to label positive/negative examples, parse inside that block, mark an anchor or preserve an opaque chunk.
5. System generates at most three ranked typed grammar proposals, displays before/after field roles, affected event types, counterexamples, independent holdout and native compiler support. One controlled approval only.
6. Result retains original and honest FULL/PARTIAL/RAW_ONLY status. Ruby/CONF generation occurs only when its actual subset is supported and native tested. No extra Wizard or Workbench.

### ChatGPT Assisted Parser

For unknown or low-confidence variants, build a manual, provider-neutral, user-redacted prompt containing *representative sampled subtypes*, current deterministic parse tree, unsupported operations, proposed field roles, positive/negative examples, and required native capabilities. The user deliberately copies to ChatGPT/Claude/Gemini, then pastes one structured candidate. It is **REVIEW_ONLY** until same independent tests/native compiler pass. A connected model is a later separately authorized privacy/audit workflow and is not presently implemented.

### What not to ask beginners

- "Choose Grok or JSONata or regex dialect" before sample analysis;
- "Select every field in the raw event" before generating a working partial result;
- "Improve with AI" when no real LLM call has been made;
- "100% parsed" when all bytes were merely placed into an opaque raw field.

## Technical core: typed grammar AST and active learning

Proposed versioned IR operators: Envelope(syslog/CEF/LEEF/framing), Route(vendor,type,subtype,version), Parse(JSON paths/arrays, quote-aware KV, positional CSV, controlled Dissect/Grok), Capture(field,type,source_span), Normalize(Stellar target field), Opaque(source_range,max_bytes,provenance), Fallback(original), and Negatives(required_missing/wrong_field/other_variant). Every operator must have a source-span explanation, browser/native runtime support flag and a bounded test fixture.

**Active learning heuristic:** Present a user question only when (a) a required field is missing or at risk of being assigned to the wrong semantic role, (b) multiple supported grammar candidates disagree on that decision, or (c) an unknown subtype would otherwise be silently misrouted. Choose the sample/field pair that most separates candidate rules. Do not invent numerical probabilities until calibrated on a labeled corpus; labels may be "reviewed", "insufficient evidence", "native-supported", "unknown".

**Right-to-left matching:** SCOPE's bidirectional prefix/suffix heuristic is an optional fingerprint-clustering tactic for repeated/free-text structure, not a substitute for a quote-aware CSV/KV lexer. **Semantic grounding** is primarily data keys, subtype specification and user-approved examples, not raw IP shape or an LLM guess.

**Versioned reference catalog:** Store profile ID, source, license, product, logtype, version, exact raw signature, expected high-value semantic roles, native target dialect, fixture SHA, negative cases, trust status, and usage consent. Apply a profile only after route and fixture evidence; otherwise generate a new candidate. Do NOT silently transplant parser code between tenants, target versions or license regimes.

## Native compatibility and approval conditions

Stellar Cyber version-specific product docs differ materially: 6.5-era upload may use modular JSON with a tenant-specific routing port, while 7.0-era UI also provides cloning and legacy/modular selections. Our current developer backend's paired extensionless Ruby + CONF format is **not automatically convertible** to vendor modular JSON, or every vendor legacy JSON pair. A parser "valid" in the local JS simulator cannot be called valid on the owner's proprietary DP. Maintain separate exact adapter/target version evidence and existing agreed syslog port >=6800 plus actual target-specific allowable ranges and conflict inventory; the sensor receiver port is the exact CONF source listener port.

No real DP/sensor writes, automatic external model call, PR merge or production release without separate owner authorization. A preview-only opaque fallback must never be labeled deployable if the backend cannot lower it to valid Ruby/CONF.

## Revised implementation sequence — replaces manual-drag-first priority

| New priority | Deliverable | Owner-visible outcome and proof |
|---|---|---|
| **P0-ADAPT-0 FIRST** | Evidence-backed reference profile inventory and **target dialect/operator capability matrix**; identify existing permitted compatible parsers before generative work | Known source reuses a profile or confidently says "No verified profile"; semantic required fields and supported source/port contract visible |
| **P0-ADAPT-1** | Event family and subtype routing plus typed envelope/body decomposer; integrate existing complexLogRecovery WIP without overwriting it | Accurate Fortinet vs PAN-OS variants, JSON nested, quote-aware KV, positional CSV, all inputs accounted, unsupported flags explicit |
| **P0-TRACE-0/1** | Source-byte/stage/rule provenance; show auto-proposed highlights, matched+unmatched exact spans and field correctness | User sees what really happened without dragging anything; browser vs native distinct |
| **P0-ASK-0** | Minimal discriminating question, preselected candidate field roles and optional drag-to-teach positive/negative constraints | Fewer operator actions than mandatory-drag prototype; no wrong source/dest field after correction |
| **P0-TRACE-2 + P0-ADAPT-2** | Typed scoped repair, optional opaque remainder and per-variant counterexample/holdout | Same successful prefix retained, failed body doesn't abort all cases; PARTIAL vs FULL accurate |
| **P0-AI-0** | Offline provider-neutral ChatGPT/Claude/Gemini candidate grammar prompt and paste validation, only novel/ambiguous cases | Actual AI only user-directed; no unapproved egress or unverified regex execution |
| **P0-NATIVE-0** | Native Ruby/CONF operator lowering/differential tests, version-specific target adapters | Real native parity, correct field semantics and exact output hashes; unsupported operators cannot export |
| **P0-QUAL-0** | Four-vendor mixed-subtype real/sanitized licensed benchmark + novice interaction study | Event accounting, rare subtype routing, required field precision/recall, overmatch, false source/dest mapping, operator corrective actions, native hit rate |
| **GATED** | Independently approved DP upload, continuous bounded sensor replay, Interflow verification and release | Real target approval and proof, not synthetic-only claims |

**First A/B proof before committing to the full rewrite:** On the same rights-cleared small corpus compare baseline (current bounded engine), retrieval+typed decomposition, retrieval+decomposition+automatic minimal questions, and the same pipeline with optional user drag and human-reviewed LLM candidate. Count correct high-value fields and false positives, rare subtype misses, native-compilable samples and human interactions. If the third variant outperforms mandatory-drag on these observed measures, implement it as default. If not, change the design instead of relying on this document's ranking.

## Research integrity

- This is an evidence-based hypothesis and risk comparison. No comparative performance figures for Parser Studio 2.2 have been measured.
- Loghub-2.0/SCOPE/SCULP/Drain3 are principally **template grouping** evaluations; those scores are not proof of normalized Stellar source_ip/destination_ip or parser deployability.
- All competitor approaches are compared from publicly accessible docs/code/papers; not a literal census of every GitHub repository and not a claim of live authenticated competitor UI testing.
- REA integration/executable was not available in this session; no REA experiment claimed.
- Existing current two-method UI PR #7 and original dirty worktrees must not be overwritten by this documentation proposal.
