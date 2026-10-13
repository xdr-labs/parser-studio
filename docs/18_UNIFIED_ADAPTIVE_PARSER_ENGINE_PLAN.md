# Parser Studio 2.1 — Unified Adaptive Parser Engine: Product and Technical Plan

**Decision status:** OWNER-REQUESTED PLANNING PROPOSAL (2026-10-13 KST), NOT IMPLEMENTED, NOT A RELEASE OR TARGET DEPLOYMENT APPROVAL.
**Product scope:** Stellar Cyber user-created parsers; exactly two creation choices: **Auto Parser** and **ChatGPT Assisted Parser**. Keep the retired six-step Wizard and three-pane Workbench removed.
**Existing code baseline:** UI Draft PR #7 and backend Draft PR #4; preserve current synthetic/native tests, independent dirty trees, runtime permission and deployment gates. This document is a proposed *next architecture*, not a claim that source code was modified.
**Source integration:** Issue #1 [Two Deep Research PDFs assessment](https://github.com/xdr-labs/parser-studio/issues/1#issuecomment-6146640284), [corpus-first review](15_CORPUS_FIRST_PARSER_SYNTHESIS_RESEARCH.md), [explainable parsing and drag-to-teach](16_EXPLAINABLE_PROGRESSIVE_PARSING_UX_RESEARCH.md), and [retrieval-first decision comparison](17_PARSER_INTELLIGENCE_ALTERNATIVES_DECISION_20261013.md).

## 1. Product decision in one sentence

**Build an evidence-driven adaptive parser compiler that reuses known valid parser profiles, decomposes heterogeneous raw logs into typed source spans, learns only genuinely novel residual grammars, asks for minimal human/AI feedback when ambiguity remains, and compiles the resulting verified declarative rules into an actual target-supported parser pair.**

The parser should not require the user to know whether input is JSON, CEF, LEEF, CSV, KV or Syslog; should not default to a whole-line regex; should not call an LLM for every log event; and should not pretend saving the whole record as raw is semantically complete parsing.

## 2. Decisions from BOTH research reports and Issue #1

| Evidence/design idea | Adopt? | Exact role / qualification |
|---|---|---|
| Standard syntax before LLM (JSON, KV, Syslog, CEF/LEEF, CSV) | YES, highest | Actual parsers plus framing/envelope separation, including quoted/escaped values and subtype branches; native target dialect support checked separately |
| Existing manufacturer/version profile search or safe clone/extension | YES, first reusable candidate | Profile carries provenance, license, target dialect, expected field semantics, fixtures and version; no copying proprietary/Elastic-licensed code into public code by default |
| Drain3 / Spell-style template clustering | YES, *residual only* | Segment still-unparsed free text after deterministic structured islands; template masks are discovery signals, NEVER proof that captured fields have correct names/types |
| LILAC adaptive cache, SCOPE bidirectional matching | YES, conceptually | Cache verified grammar by product, subtype, schema/compiler version and fixture digest; use prefix/suffix fingerprints and invalidate on drift or failed tests |
| Matryoshka nested decomposition and variable-specific anchored regex | YES, DESIGN ONLY | Make each named variable capture span, type, role and negative proof explicit; prevent wildcard over-capture; do not copy GPL-3.0 research source |
| Dense vs sparse cluster dispatch / LogBatcher | YES | Dense variants: deterministic alignment/statistics first; sparse or contradictory: queue limited model/manual grammar hypotheses. No LLM dependency at runtime |
| AdaParser/CEGIS correction + PBE drag + active question | YES, after trace | Use user positive and negative span assertions to repair only failing stage, never silently rewrite already proven header or sibling subtypes |
| JSON Intermediate Representation + JSONata | YES, *mapping* lane only | Typed extracted fields and source provenance become intermediate JSON; a **bounded allowlisted JSONata subset** can propose projection/rename/coalesce/cast/map normalization, not parse arbitrary raw text or directly run on the Stellar sensor |
| Fully arbitrary AI-generated Ruby, unrestricted regex/JSONata, automatic external log upload | NO | Untrusted candidate-only; sandbox analysis, allowlisted AST lowering, holdout/native tests, explicit privacy approval |
| Metamorphic security-log variants | YES, as additive tests | Alter documented IP, port, username, URL, timestamps, quoting, key order, optional fields and subtype negatives; does not replace genuine held-out vendor fixtures |
| Real DP Apply / sensor live replay | Later, separately gated | Independent target access authorization, API key protection, same generated CONF and sensor receiving port, Syslog >=6800, bounded lease/Stop and actual Interflow evidence |

**Evidence caution:** The first 8-page paper is a broad technique landscape and sometimes places LLM too early. The second 17-page paper and Issue #1 correctly distinguish template GA/FTA from semantically correct field extraction. Published LILAC/LUNAR/Matryoshka numbers do not measure our actual Stellar Ruby/CONF field accuracy.

## 3. Architectural contract: compile then execute

The actual **runtime** is compiled Ruby/CONF under the verified target profile, not a hosted LLM, JSONata interpreter, Python miner, arbitrary model-generated code or JavaScript browser preview.

    Raw events
       ↓  record boundary/framing (line / validated multiline / message)
    Source fingerprints + trusted profile retrieval (vendor, product, type, version)
       ↓
    Deterministic envelope and typed body parsers
       ├── Syslog header, CEF/LEEF, quoted KV, JSON paths/arrays,
       │   positional CSV per subtype, Java exception islands
       └── exact original source-span provenance and UNPARSED ranges
       ↓
    Residual router
       ├── verified cached grammar → use
       ├── dense template cluster → local alignment/typed rule candidates
       └── sparse/ambiguous cluster → user question / reviewed LLM prompt
       ↓
    ParserGrammar IR v0.3
       ├── versioned variant routes, anchored variable captures,
       │   scoped parse operators, field types and negative assertions
       ├── optional preserve-opaque remainder (honest PARTIAL)
       └── source-linked intermediate JSON with precise coverage map
       ↓
    Semantic mapping to Stellar target fields
       ├── existing verified profile aliases and typed projection
       ├── allowlisted JSONata-style mapping AST for eligible transforms
       └── optional AI-proposed mapping candidate, user-reviewed
       ↓
    Counterexample-guided validation: positives + negatives + holdout
       ├── original byte accounting, typed role precision, no intrusion
       ├── metamorphic and source-family regression, resource bounds
       └── capability check and exact native Ruby/Fluentd execution
       ↓
    SHA-verified extensionless Ruby parser + corresponding .conf
       └── separate (not assumed equivalent) target-version adapters
       ↓
    Optional owner-approved DP upload + sensor replay + Interflow verification

**Separation of concerns:** Template clustering says which logs *look structurally alike*. Exact anchored captures say which source bytes were consumed. Semantic mapping says whether the captured IP is source, destination or NAT. Compilation says whether Stellar will execute those operations. These four verdicts cannot be combined into one unqualified "Parsed 100%" score.

## 4. Canonical intermediate JSON (a private parsed representation)

For each event, the engine maintains an immutable raw-source identity and a typed structure such as:

    {
      "eventId": "event-1",
      "family": {"vendor":"Fortinet","type":"traffic","route":"profile-id-or-unknown"},
      "source": {"sha256":"...","originalUtf8Length":123},
      "fields": {
        "srcip": {
          "value":"192.0.2.10","type":"ip",
          "sourceSpan":{"startByte":44,"endByte":54},
          "ruleId":"quoted-kv-v1","role":"source_ip","verified":"LOCAL_TESTED"
        }
      },
      "unparsed": [{"startByte":84,"endByte":121,"reason":"UNKNOWN_BODY"}],
      "status": {"fieldExtraction":"PARTIAL","native":"NOT_VERIFIED","target":"NOT_VERIFIED"}
    }

This is a **contract illustration**, not actual source byte offsets or current backend schema. Precise UTF-8-byte offsets plus browser UTF-16 selections are essential for quoted Unicode text and repeated identical IP addresses. Every byte is either structured field, recognized syntax/delimiter or retained unparsed original; *byte accounting is not correctness*.

## 5. JSONata decision: useful as a constrained semantic mapping accelerator

**Accept** the recent JSONata idea, but NOT as a universal first-stage raw-log parser.

- Step 1: deterministic extraction or verified grammar proposal produces intermediate JSON with source provenance.
- Step 2: map fields to semantic source roles, normalize desired names and optional object/array structures. If a profile already supplies a trusted semantic mapping, reuse it and avoid JSONata.
- Step 3: a manual ChatGPT/Claude/Gemini prompt may propose JSONata or a neutral mapping plan to fix **mapping errors** (not missing raw syntax). A missing source capture needs a body grammar, not JSONata.
- Step 4: parse the suggested expression as **untrusted data**, allow only known safe projection, path lookup, rename, coalesce/default, typed conversions and explicitly implemented bounded array transformations. No user-defined functions, recursion, dynamic eval, unbounded regexes, network operations or unrestricted scripts in deployable artifacts.
- Step 5: lower allowed mapping expressions into a **canonical typed Map AST** supported by the Ruby/CONF compiler and compare results with the isolated local JSONata preview. If native lowering is missing, label REVIEW_ONLY and do not create a supposedly deployable parser.
- Step 6: check the normalized result against the **verified actual Stellar mapping contract**; an ECS/OCSF-shaped JSON example is advice, not proof that Stellar recognizes the same fields.

Security: JSONata is an MIT-licensed JSON query/transform engine, but GitHub advisories in 2026 documented critical crafted-expression execution vulnerabilities in earlier 2.x versions. Use >=2.2.1 if evaluating 2.x plus a strict function/operator subset, isolated worker, CPU/memory/time/data caps, and dependency auditing. Never treat arbitrary pasted JSONata as safe merely because it is JSONata.

**Do not serialize full customer raw values into a model prompt by default.** The intermediate object should be local/private; only manually reviewed redacted representative values may leave the browser in the optional AI workflow.

## 6. Grammar generation and repair policy

A grammar candidate must include:
- source vendor/subtype evidence and exact scope;
- input framing and parent field/source span;
- route priority and typed extraction operators;
- bounded anchored named captures, exact source spans, normalization targets and field types;
- explicit fallback/opaque remainder behavior;
- provenance of a known verified profile, local deterministic synthesis, user label or model proposal;
- positive assertions, negative examples and unsupported target operations;
- immutable grammar version and source/holdout fixture digests.

**Scoring/ranking** (heuristic until ground-truth calibration): safety of high-value semantic roles > zero cross-subtype capture > unseen holdout validity > native compiler support > source-span field coverage > complexity/user effort. One large ".*" capture must score lower than correct source/destination and honest opaque remainder. Prefer deterministic typed operators to regex if they have equivalent coverage.

**CEGIS loop:** generate max 3 candidates → evaluate every positive and negative → find a failing event/span → attempt a *local* grammar repair (up to bounded iterations) → rerun sibling variants and independent holdout → user approves; otherwise retain baseline and identify exact reason. No silent auto-acceptance of a candidate whose confidence is only an LLM estimate.

**Dense/sparse routing:** cache hit and syntactic structured cases use zero LLM calls. Dense unknown text groups can use cheap deterministic alignment. Sparse groups or genuine semantic ambiguity may generate one user-approved redacted *offline* prompt per novel group; manual ChatGPT copy/paste is the initial real model integration. A directly connected model is future opt-in, authenticated, audited and separately gated.

## 7. Final user experience (only two public paths)

### Auto Parser

One page with three contextual sections: **Add Logs → Review Results → Test & Generate**. These are not separate creation methods or a revived Wizard.

1. User pastes mixed logs without knowing types. Parser Studio shows *events accounted*, grouped source variants, what fields are already correctly extracted and what remains unknown.
2. For supported familiar events, the app generates and validates automatically with minimal clicks.
3. On uncertainty, ask **one discriminating question**, for example: "Which highlighted address is the source IP?" or "Are these both TRAFFIC logs?" Provide pre-highlighted alternatives; user is never forced to first drag.
4. Clicking a source record reveals the original byte ranges, rule IDs and selected output fields. Optional drag actions: **Extract as field**, **Parse inside selection**, **Use as boundary**, **Preserve as one field**.
5. If no deterministic candidate works, show **Improve with AI** that truthfully means **Prepare reviewed prompt**. Copy to ChatGPT, Claude or Gemini; paste back a bounded GrammarProposal/MapProposal. A distinct future "Connected AI" action would be needed for actual API calls.
6. Before generating, show a diff of field roles, unknown/opaque ranges, before/after negatives and holdout. A retained raw section is PARTIAL or RAW_ONLY, never falsely FULL.
7. Compile only covered operations and download the SHA-verified Ruby/CONF/ZIP revision. Native readiness and actual DP runtime acceptance remain different badges/evidence.

### ChatGPT Assisted Parser

The second existing authoring method is a deliberate external-AI workflow: local source and desired fields, user-approved redacted examples and explanatory failure trace → provider-neutral copyable prompt requesting **one to three JSON schema-valid declarative grammar and/or semantic mapping candidates** → paste result → strict recipe validation → negative/holdout regression → native backend compiler when supported. Do not restrict the *proposal* vocabulary to today's "one new mapping" forever, but never execute unsupported proposal operators.

**Product language:** All actual UI source and docs are English. In Korean product planning discussions, use short explanations. Never label a local rule heuristic as "a real ChatGPT call".

## 8. Target artifacts, APIs and safety

- Primary output remains verified matching pair: extensionless customized_... Ruby fragment and corresponding .conf.
- Syslog parser listener port must be >=6800 and **equal** to actual configured sensor destination receive port; required target inventory must be checked to prevent collision.
- Separate target adapter/capability and artifact format needed for legacy Ruby/CONF, any distinct legacy vendor API, and modular JSON. A valid JSON Intermediate Representation is NOT a vendor modular parser JSON export.
- Parser deployment UI, DP URL/API token entry, approved synthetic event mutation (current time/IP/user/URL), duration selection (e.g. 1/3/5/10 minutes) and explicit Stop belong to context-sensitive **post-generation** results, NOT a third authoring path.
- Real DP writes, live sensor packets, Interflow verification, external AI API calls, production deployment, PR merge and release all require their own independent authorization; default dev preview remains deny-by-default.
- Only the native Ruby/Fluentd qualification and actual target E2E can justify respective readiness levels. Sending UDP/TCP bytes does not prove actual parsed ingestion.

## 9. Prioritized implementation plan without discarding existing work

**Owner scheduling interpretation:** Issue #1's latest Deep Research comment is a proposal, not an unconditional implementation override. This is a *planning consolidation*: keep existing approved P0 and safely reconcile into the next owner-approved Work Packet. No speculative rewrite of current UI PR #7 or backend PR #4.

| Phase | Purpose and deliverable | Acceptance proof / dependency |
|---|---|---|
| **P0-FOUNDATION (start)** | Source-correct ParseTrace and operator capability ledger: event frames, UTF-8/UTF-16 spans, rule ID, unknown segments, mapping error categories, coverage display | Exact original/Unicode/duplicate spans, 100% input event accounting; browser/native states separate; no new target claims. Reuse existing browserRuleTrace/fieldHighlights and protected complexLogRecovery WIP |
| **P0-PROFILE** | Trust-and-license-checked candidate catalog; fingerprint ranking and typed quote-aware KV, CEF/LEEF, Syslog, per-subtype CSV, JSON path/arrays and bounded multiline | Known vendor fixtures route to correct subtype and map high-value fields, no other-subtype intrusion; unchanged backend support still passes |
| **P0-IR** | Grammar IR v0.3 + intermediate JSON + semantic type/field mapping compiler interface; first allowlisted JSONata-style Map AST preview | No raw-to-JSON hallucination, full source provenance, unsupported JSONata/mapping fail closed, exact field-role trace |
| **P0-LEARN** | Residual-only Drain3 clustering, cached grammar candidates, density-aware typed alignment, anchored variable regex generation and bounded CEGIS/negative cases | Known/structured logs trigger 0 LLM; unrecognized chunks are retained; cross-family negatives and held-out field spans/roles tested |
| **P0-ASSIST** | Optional drag correction, minimal question UX, manual ChatGPT/Claude/Gemini GrammarProposal/MapProposal import with optional structured JSONata subset | One or two human interactions for simple ambiguities is an experiment target, not a promised result; redaction opt-in and unsupported candidate REVIEW_ONLY |
| **P0-COMPILE** | Backend Ruby+CONF lowering for *proven* IR operators, target-version compatibility profiles, fixed hash/provenance and differential Native Fluentd fixture comparison | Every "Native Verified" candidate exactly matches source and target runtime; negative/wrong semantic field cases cannot be approved |
| **P0-QUAL** | Multi-vendor corpus and usability benchmark, synthetic mutations, rare-subtype drift checks and fixed-head browser/native CI | Holdout semantic field Precision/Recall/F1 by vendor/type; overcapture and source/destination reversals; percent native compilable; median corrective actions; throughput, p95/p99, cache miss, LLM calls per new grammar, time/cost |
| **GATED-LIVE** | Owner-configured DP Apply and 1/3/5/10 min sensor test with same parser source port; actual Interflow receipt and release | Independent target permissions, audit, Stop/lease, same-head real two-user E2E and release approval |

### Engineering proof-of-concept before full implementation

Run small side-by-side tests over **rights-cleared, sanitized public genuine source fixtures** for Fortinet FortiGate traffic/event/UTM, Palo Alto PAN-OS TRAFFIC/THREAT, Trellix EDR/ePO and Trend Micro Vision One detection, including malformed and negative variants. Compare:
- Baseline current fixed format v0.1/v0.2;
- profile retrieval + deterministic typed decomposition;
- prior plus residual clustering and local pattern synthesis;
- prior plus user-corrected negative case and optional LLM/JSONata mapping candidate.

Report field-level exact source-span/semantic role/type triplets, raw/partial preservation, native compiler reachability, and human effort. A publicly published research template FTA percentage cannot be pasted into this product as an observed field accuracy number. Suggested **gates**: 100% input event accounting, zero silent data loss or unauthorized external egress, zero wrong source/destination mapping within approved gold fixtures, all Ready candidates Native PASS, every user-approved changed rule protected by holdout and negatives. Accuracy thresholds for wider vendors must be calibrated after corpus curation; do not invent product pass rates.

## 10. Risks, licensing, and scope limits

1. **Native output gap is the main engineering risk.** A beautiful regex/JSONata explanation is not useful if no Ruby/CONF compiler exists for that grammar. Deliver typed AST and compiler capability checks together.
2. **False semantic extraction is worse than unknown.** Do not interpret "an IP was found" as evidence the correct field role was assigned.
3. **Licensing:** The GitHub [Matryoshka research implementation](https://github.com/julien-piet/matryoshka) is GPL-3.0; reuse concepts, do NOT copy code into commercial Parser Studio without explicit licensing/legal clearance. Elastic integrations / Beats x-pack generally have Elastic licenses; research references are not automatically redistributable. Drain3 and LogBatcher MIT in the reviewed provenance; each imported dependency and fixture requires a pinned license/security review.
4. **JSONata security:** [JSONata official overview](https://docs.jsonata.org/next/overview) describes JSON data transformations, not universal raw-event parsing. [2026 critical crafted-expression advisories](https://github.com/advisories/GHSA-2943-5xfg-gq5f) show that unrestricted evaluation is unsafe; patch and isolate **even preview** implementations.
5. **Privacy:** Raw/opaque blocks can contain customer secrets and personal data. No automatic provider requests, third-party telemetry containing raw logs or unapproved tenant transfers.
6. **Evidence:** Both attached studies, Issue #1 assessment, GitHub project code and vendor fixture availability inform this *design hypothesis*. No new real-vendor benchmark, Native parser implementation, REA UX audit or actual user DP/sensor E2E was conducted in this planning task.

**Outcome:** This one document is the proposed integrated product and technical plan. Reuse and implement the existing research in Docs 15–17 and Issue #1 rather than reopening parallel research roadmaps or inventing extra authoring modes.
