# 06. Roadmap, Gates and Next Action

## Overall

**Goal:** Independently build a dependable Parser Studio Web application, with portable authoring and evidence-backed Fluentd/Stellar output.

### R0 — Foundation and product definition (THIS INITIAL REQUEST)

- [x] Create xdr-labs/parser-studio repository, private by default because future artifacts may contain sensitive data.
- [x] Persist product outcome, scope, competitor-driven UX, workbench specification, function backlog, version-neutral architecture and ordered roadmap.
- [x] Adopt Engineering System configuration and execution instructions.
- [ ] Reconfirm exact sample-derived parser compatibility contract **after the owner supplies samples**.
- **Done criterion:** published docs in Git, check actual file presence and commit SHA; no claim that parser execution exists.

### R1 — Samples, truth contracts and model (NEXT PRIORITY)

- [ ] Receive representative raw logs and at least one actual parser artifact from owner.
- [ ] Classify artifacts: Fluentd config, Stellar legacy files, Stellar modular JSON or other.
- [ ] Identify syntax, ingestion/header rules, event families, normalization fields, timestamp policies and unsupported features.
- [ ] Define portable IR v0.1 + JSON Schema and golden fixtures; privacy-screen all fixtures before commit.
- [ ] RED tests for correct extraction, type mapping, failures and native-runtime equivalence.
- **Done:** sample-based contract and fixture expectations; unknowns explicitly recorded.

### R2 — Working web workbench / core parsing (P0)

- [ ] Create app skeleton, Workbench panes, sample upload/paste and raw event viewer.
- [ ] Event splitting, format candidates, route variants and field highlighting.
- [ ] Rule builder with regex/JSON/KV/Syslog/CSV support and transformations.
- [ ] Typed normalization mapper to evidence-backed Interflow fields.
- [ ] Live RAW/EXTRACTED/NORMALIZED stage preview with test runner integration.
- **Done:** real sample E2E from paste to normalized preview; affected unit/integration/browser tests green.

### P0-ME — Multi-Event Auto Parser: one deployable Stellar parser (owner decision 2026-10-17)

**Status:** PLANNED, not implemented. This is an R1–R4 product-roadmap handoff, **not** authorization to alter the isolated engine PoCs, existing product HEAD, native targets, main, deployment or release.

**Owner-confirmed Stellar capability:** A single Stellar Cyber parser supports multiple event families and family-specific **dynamic conditional normalization across all Stellar versions**. Do not impose a version selector, split one product into one parser per event type, or treat this platform capability as awaiting per-version proof. **Parser Studio's generated artifact and correct runtime behavior** still require native execution evidence before claiming our implementation is verified.

**Required outcome:** One security product may interleave Threat, Alert, User, Asset, Audit and additional/custom event types in the same stream. A user supplies diverse samples once and exports **one Stellar parser artifact**. Internal bounded routing/extraction/normalization variants are allowed; external one-artifact deployment and per-event correctness are mandatory. Event family names are not a hard-coded closed set.

| ID / milestone | Deliverable | Measurable acceptance |
| --- | --- | --- |
| **MEP-0 / R1 P0** | Build a **mixed-event-family source corpus and independent golden contract** with representative events from the same product, including unknown, ambiguous, missing-discriminator and malformed cases. | Per-event source bytes, family labels, extraction fields/values/UTF-8 spans and expected normalized fields are independently frozen; no self-generated oracle; denominators and UNSCORABLE recorded. |
| **MEP-1 / R2 P0** | Reuse the qualified Multi-Pass + Generic Structural + bounded Funnel for **shared envelope and body extraction** before family-specific processing. | Preserve original event/raw bytes, repeated fields, exact source values/spans and explicit unparsed regions; no forced parse success or vendor-by-vendor regex patches. |
| **MEP-F0 / R1 P0** | Freeze **paired direct-vs-forwarded original security logs** and independent expected source/relay metadata for RFC3164, RFC5424, custom prefix, JSON-wrapped payload, one-hop, multi-hop, overwritten/truncated, and mixed-family cases. | Source and transport timestamps/hosts, complete received raw UTF-8 bytes, exact internal payload source spans, hop evidence and unrecoverable original information are independently labeled before scoring. |
| **MEP-F1 / R2 P0** | Add a **bounded generic forwarder-envelope unwrapping stage** *before* event-family routing, distinguishing added transport headers from original message bodies without forwarder/vendor-specific one-off regex stripping. | Parse only independently supported wrapper boundaries; retain each hop and exact original-byte provenance. Keep relay host/receive time separate from original device/event time; unresolved prefix/body ambiguities must remain PARTIAL/REVIEW_ONLY and never silently truncate/relabel payload. |
| **MEP-F2 / R3–R5 P0** | Validate the **same one generated Stellar parser** on directly received and forwarder-prefixed/wrapped Threat, Alert, User, Asset and unknown events through actual native execution. | For intact source events, route and typed normalized fields must be equivalent with/without forwarder(s), with relay metadata retained. Report wrong-source timestamp/host attribution, FP/FN, byte drift, missing data and abstentions; do not fabricate data removed or rewritten upstream. |
| **MEP-F3 / R2–R3 P0** | Add **user-selected prefix and postfix regions** in the raw event viewer: drag/highlight exact original UTF-8 spans and choose **Mark as Prefix** / **Mark as Postfix**. Allow each selected segment to become either an explicitly confirmed exact literal or a bounded delimiter/structure-based boundary with named variable captures (e.g., relay host/time), never an unbounded generated regex. Provide operator-controlled precedence versus auto-detection. | Show highlighted prefix / actual event / postfix before and after, byte-accurate values and offsets, distinct relay metadata, and per-type plus across-sample counterexamples. Only promote a manually confirmed rule if it covers every applicable example without truncation, ambiguity, or byte drift; otherwise preserve raw logs and mark PARTIAL/REVIEW_ONLY. No silent inference of manufacturer escape semantics and no native Verified without executing the one exported parser. |
| **MEP-2 / R2 P0** | Add **deterministic event-family classification and routing** using explicit type fields/message IDs first, then independently supported structural signatures and documented precedence. | Each event shows its chosen route and evidence. Conflicting, insufficient and unknown classifications abstain or stay PARTIAL/REVIEW_ONLY; no silent first-match misroute. |
| **MEP-3 / R2 P0** | Support **one common field map plus conditional family-specific dynamic normalization**, with typed coercion, precedence, collision and manual override rules. | Threat/Alert/User/Asset/Audit samples normalize to their proper target fields within the same project; no cross-family field leakage or silent key loss; unmapped data remains visible. |
| **MEP-4 / R2–R4 P0** | Add user-named per-type sample editors (**not mandatory automatic grouping**), editable route/mapping review, and per-family RAW → EXTRACTED → NORMALIZED previews. | A beginner can identify and correct the problem family without changing already-correct families. Keep exactly **Auto Parser** and **ChatGPT Assisted Parser** authoring paths; no Wizard/Workbench revival and no automatic raw-log AI transfer. |
| **MEP-5 / R3 P0** | Compile the mixed family routing and dynamic normalization into **ONE deployable Stellar parser artifact**; no separate exported parser per family. | Native runner/import tests prove the generated single artifact actually chooses and normalizes distinct families. Keep runtime/export evidence separate from the owner-confirmed cross-version platform capability; no Stellar-version selection in authoring. |
| **MEP-6 / R3–R5 P0** | Run reproducible **single-artifact mixed-stream Full User E2E** with representative families and unknown/malformed controls. | Publish per-family route confusion/abstention, exact source-field/value/span TP/FP/FN, normalized-field accuracy, unknown/unmapped counts, raw-byte retention and false-complete results; preserve passing families when fixing one; pin candidate HEAD, fixture hashes and native artifact digest before owner acceptance. |

**Forwarder-aware source contract:** Forwarders may prepend, rewrap, rewrite or drop source metadata; recognized RFC3164/RFC5424 framing is only one variant. Model received raw bytes, ordered transport-hop metadata, original source-event body and provenance as separate concepts. Never strip an arbitrary fixed-length prefix or assign a relay's hostname/receive time as the origin without supporting evidence. Keep the **one-parser-per-product** requirement for direct and forwarded streams alike.

**Acceptance gate:** User creates, tests, reviews and exports **one parser for a mixed event stream**; all independently qualified family fixtures use the intended conditional normalization with no silent loss or false-complete. A successful browser preview or source extraction alone **does not** prove the generated native parser. The unresolved work is Parser Studio compilation/testing, **not** whether Stellar supports multi-event conditional normalization.

### P0-ME sample authoring refinement — user-named log types and per-type Union Schema (owner decision 2026-10-17)

**Status: PLANNED / PRODUCT HANDOFF ONLY.** Preserve the previous two Auto Parser / ChatGPT Assisted Parser entry paths, one generated Stellar parser for the product, owner-confirmed all-version conditional normalization, and the MEP-F0..F2 direct/forwarded-source requirements. **This supersedes the proposed mandatory automatic structural/event grouping UX**; automatic structural hints may be review aids but must never silently split into multiple separately deployed parsers. It does not authorize product/main/integration/DP/sensor changes while the independent accuracy work continues.

**Required beginner authoring interaction:** Start with one editable **log type name + sample area**. The user can click **Add another log type** to add a separately named Threat / Alert / User / Asset / arbitrary log type. Each named type accepts **up to 10 representative sample records for Union Schema inference** (several samples of the **same** type are especially valuable). Recommend different populated/missing field combinations rather than duplicate lines. User can edit/remove a type without affecting samples in other types. Show count, safe limits and a privacy notice; never auto-send source logs to external AI. Retain all original received source bytes and stable sample-to-type membership; use *every supplied test event* for regression, not only the first ten when an existing larger dataset is imported.

**Union principle:** For each **user-named type independently**, take the union of independently extracted field positions/names over its samples, showing how many examples have a value, have an explicit empty value or are missing the field. Example: two Threat samples with username and hostname populated separately must yield both as **optional fields within Threat**, not split into different event types. Never conflate missing with an empty value, shift positional columns when some CSV cells are blank, or manufacture source field names. A user-provided type label is **authoring metadata only**, not proof of a runtime event discriminator. Runtime routing must rely on inspected event-source tags/IDs or independently qualified structural predicates; ambiguous or unknown types abstain rather than being assigned by UI label.

**Manual Prefix/Postfix authoring decision (owner 2026-10-17):** Automatic relay/framing analysis remains the default. As an accuracy-first alternative, the user can **drag-select a Prefix and/or Postfix in a raw sample**, then click **Mark as Prefix / Mark as Postfix**. Marking is a proposed per-type delimiter/boundary rule, **not** permission to blindly cut text. Show a three-way preview (transport Prefix | original event | Postfix), explain exact literal vs delimiter-bounded variable text, handle direct/non-forwarded exceptions and repeated nested relay envelopes, preserve all original UTF-8 bytes, and display source vs relay metadata independently. Let the user explicitly confirm or undo the selection. Run the rule against **every supplied example from the same named type** and representative counterexamples from other types; track branch choices, false trims, FP/FN, abstention, and exact original byte spans. If the selected boundary is not unambiguous (including overlapping in-body delimiter, multibyte UTF-8, truncation and rewritten source metadata), abstain rather than declare success or fabricate removed data. Compile verified conditional boundaries as internal routes within **one Stellar parser** with native tests. Default Auto Parser, manual correction within existing two authoring paths only; no Wizard/Workbench revival.

**CSV log definition contract:** Each named log type can optionally be designated CSV/delimited and provided with an **ordered column list from the manufacturer's log definition**, with a chosen delimiter and explicit user confirmation. Support manual typed/pasted definitions, validate exact column count, safe unique field names, quoting, optional trailing empty columns, consistent positions and per-type overrides; never infer authoritative semantic names solely from numeric position or guessed values. For records such as \`2026-10-17,alice,,deny\`, an explicitly reviewed \`timestamp,username,hostname,action\` definition maps the third cell to an **empty hostname** and does not shift \`action\`. Malformed/inconsistent widths require review/abstention. The user must be able to see/edit the definition in Review Fields / Map Fields with provenance \`USER_CONFIRMED_SOURCE_DEFINITION\` rather than presenting guesses as manufacturer truth. Neither field names nor sample labels imply correct Stellar target mapping without separate normalization review.

| ID / milestone | Required product task | Acceptance |
| --- | --- | --- |
| **MEP-S0 / R1–R2 P0** | Add user-named **log type** editors, per-type raw sample input, and **Add another log type** action in the existing Auto Parser first step. | A beginner can name and edit Threat/User/Asset independently; the primary type accepts several complementary examples; up to 10 per type are used for inference; preserve all source bytes; no mandatory auto-grouping. |
| **MEP-S1 / R1–R2 P0** | Compute **per-type Union Schema** from all approved representative examples, with present/populated/empty/missing counts and explicit provenance. | Complementary username and hostname fields appear as optional within one named Threat type; no accidental propagation into User/Asset; no blind field fill, no accidental column shifts. |
| **MEP-S2 / R1–R2 P0** | Provide an ordered **manufacturer CSV field-definition** editor for each log type with delimiter, name validation and user confirmation. | CSV headerless positional values retain explicit blanks and column order; mis-sized/malformed rows abstain; no invented manufacturer fields or cross-type CSV header inheritance. |
| **MEP-S3 / R2–R3 P0** | Bind user-named authoring groups to **evidence-backed runtime family routing**, conditional normalization and **ONE** target parser compiler contract. | User type names alone cannot route an event. Unproven discriminators are review-only; one compiled artifact handles all qualified types, direct and forwarded, without cross-family mapping leakage. |
| **MEP-S5 / R2 P0** | When a user drags **Prefix** or **Postfix** in a sample, store its per-type authoring selection with **exact UTF-8 source offsets**, display **Exact text** vs **Delimited variable region**, permit undo/edit and reuse on other representative samples, and show source/relay timestamp and host separately. | One marked example is only a proposal; all other samples must be replayed with counts of confirmed, partial, ambiguous and rejected matches. A selected variable prefix/postfix is not incorrectly treated as a fixed literal, and the same single parser handles direct and forwarded events without dropping source bytes. |
| **MEP-S4 / R3–R5 P0** | Full novice Web UI / deterministic / native mixed-stream tests for complementary-field source examples, typed/empty CSV, different named types and relayed variants. | Field+value+UTF-8-span/position, optional-field counts, FP/FN, abstention, typed normalization, no false complete and **single exact-artifact** native behavior are independently checked; native compatibility is NOT VERIFIED until actually executed. |

**Implementation priority:** The isolated source-accuracy PoC remains active. Existing incomplete, uncommitted product/backend feature worktrees are preserved (no merge/promotion); implement MEP-S0..S4 only in an owner-authorized, separately gated product lane after independent PoC work. This roadmap handoff itself performs no product implementation.

### R3 — Native validation, regression and export (P0)

- [ ] Sandboxed pinned Fluentd runner with plugin capability manifest.
- [ ] Fixture suite, per-event diagnostics, error grouping, coverage and before/after diff.
- [ ] Revision storage with deterministic hashes, consistent result export.
- [ ] Fluentd output adapter, actual native-engine test, honest compatibility labels.
- [ ] Implement Stellar-specific export only for formats grounded by sample artifacts and real target evidence.
- **Done:** repeatable test report and proven artifact for each supported adapter (no unsupported success).

### R4 — Production-quality usability / supportability (P1)

- [ ] Templates/library, advanced source mode, import error/loss reports and mapping suggestions.
- [ ] Responsive/accessible UI, bilingual labels, security and large dataset behavior.
- [ ] Optional AI assistance under strict opt-in/privacy and deterministic verification.
- [ ] Document packaging, operations, recovery and deployment boundaries.
- **Done:** consistent user journeys, no unsafe feature default, review-ready artifact.

### R5 — User acceptance and release (separate gates)

- [ ] Browser scenario PASS on the actual candidate.
- [ ] Full User E2E by user/operator/admin as applicable, same exact candidate HEAD.
- [ ] Freeze HEAD, qualification/CI/provenance/public smoke as the release contract requires.
- [ ] Owner acceptance; only then release or production deployment with explicit approval.
- **Done:** actual gate evidence, not a narrative assertion.

## Execution order

R0 → R1 → R2 → R3 → R4 → R5. Implement within the current runnable milestone; do not jump to AI helpers/templates ahead of parser correctness. Preserve owner-provided samples and uncommitted work. Follow Engineering System for small deterministic RED→GREEN changes and exact-HEAD evidence.

## Cross-cutting acceptance

- Version-neutral editor can work without a running Stellar instance.
- **Single mixed-event Stellar parser:** multiple event families and conditional dynamic normalization must be authored and exported in one artifact, with native correctness demonstrated for the generated output; no Stellar version selector or one-parser-per-family requirement.
- All samples (including minority variants) yield explained statuses.
- No hidden data loss or unsupported transformations on import/export.
- Exact artifact/version support explicitly backed by runner or target-import evidence.
- Customer data is isolated and not published by default.
- No production effects in the initial development path.

## Concrete NEXT_ACTION

**Await owner sample log(s) and existing parser(s) as the only missing product-specific input; then immediately begin R1 characterization, IR/fixture contract and RED tests.** Until samples arrive, implementation may proceed only on independently specified, testable UI scaffolding without asserting Stellar export compatibility. Use this file as the single canonical roadmap and carry precise Git/CI/fixture status into future handoffs.
