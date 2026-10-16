# 04. Architecture, Version Independence and Security

**Design status:** Approved boundaries; specific import/export file schemas and target runtimes remain evidence-driven until real artifacts are supplied.

## 1. Stable conceptual pipeline

Raw log sample → event breaker → route / event-family classifier → parser / extractor → typed transformations → Interflow normalization → optional enrichment → validation → export adapter.

A draft is represented internally as a **portable parser IR (intermediate representation)** plus separate fixture sets, field dictionary revision, runtime capabilities and test evidence. It is not stored primarily as either one Stellar-specific JSON or a browser regex.

## 2. Modules and responsibility boundaries

| Module | Responsibility | Must not do |
| --- | --- | --- |
| Web Workbench | Editors, source highlights, live diffs, diagnostics | Claim runtime support from browser-only matching |
| Project API/storage | Drafts, versions, fixture references, manifests | Automatically publish raw customer samples |
| Parser IR service | Schema validation, stage ordering, deterministic transformations | Hard-code Stellar Cyber release-dependent export syntax |
| Schema catalog | Destination names, types, allowed mapping semantics | Silently invent standard fields |
| Isolated runner | Execute supported Fluentd config with pinned profile, collect traces | Execute unrestricted user code on host |
| Import adapters | Decode tested input artifact families into IR with loss report | Drop unknown directives without warning |
| Export adapters | Capability-test, serialize verified shapes and bundle manifest | Pretend proprietary import formats are universal |
| Regression engine | Fixture/golden-output comparison and reproducibility | Declare PASS when no test was actually executed |

## 3. Portable project contract (conceptual, not a finalized JSON schema)

- schema_revision: internal data model revision, independent of Stellar release.
- project_metadata: vendor/product, log family, draft revision, authoring language.
- datasets: references/hashes to private or synthetic sample sets and their labels.
- event_breakers: logical event boundaries and multiline behavior.
- route_variants: ordered predicate → extraction pipeline associations.
- stages: typed operators with explicit order, input/output names and error policies.
- mappings: source path, target semantic field ID, coercion, collision/precedence policy.
- enrichment: capability-gated transformations/lookups.
- expected_outputs: per-fixture golden normalized events (redacted where appropriate).
- target_profiles: *separate* export/runtime adapters and evidence, not intrinsic core schema.
- run_evidence: runner build digest, plugin versions, suite hash, results, export hash.

A formal JSON Schema is an M1 deliverable after inspecting owner-provided real parser samples so that round-trip semantics are not guessed.

## 4. What “works regardless of Stellar version” means

- The Web Studio edits a stable portable project, without asking users to select a Stellar version.
- Sample parsing, Interflow mapping and regression tests run independently of a Stellar instance.
- Export targets are adapters: Fluentd-standard config first; Stellar legacy/modular or custom formats only after evidence.
- An export is **Verified** only if the generated artifact passes the declared runtime test and, where applicable, real target import/behavior validation.
- A version may have a differing artifact protocol, unsupported plugin or platform restriction; such combinations remain Partial, Unsupported or Pending evidence.
- Do **not** rename an untested version-dependent output format “Universal Parser.”

## 5. Import/export and backward compatibility

1. Preserve original imported files and record SHA-256 hashes.
2. Parse known constructs to IR; attach explicit opaque/unsupported segments without silently destroying them.
3. Refuse unsafe round-trip rewrites when semantic preservation cannot be shown.
4. Generate a bundle containing parser artifact, mapping manifest, schema revision, compatibility profile and redacted test evidence.
5. Never automatically upload/configure a Stellar platform in MVP.
6. After real samples arrive, create import → IR → export → native parser comparison tests for every supported format family.

## 6. Execution design

- Browser editor may run quick suggestions, clearly labeled as a preview.
- True Fluentd compatibility uses a **sandboxed, pinned Fluentd** runtime (and explicit plugin set). Define exact OS/image and parser plugin versions in test manifests.
- Bound CPU, memory, execution time and input size; disable outbound network by default and mount sample inputs read-only.
- Reject dangerous regexp behavior on oversized inputs or timeout; log only redacted traces.
- Later Stellar validation must be done in an isolated, authorized lab with the owner's explicit target information.
- Keep deployment target/runtime distinct from the normalized event contract.

## 7. Security & operations decisions

- Repo starts PRIVATE. Real customer logs, identifiers, IP addresses, credentials and parser exports go to a private ignored location; only anonymized synthetic fixtures belong in source control.
- Preserve source-log confidentiality in UI, error reports, metrics and AI usage; provide masking/export-redaction modes.
- File upload handling must guard size, compressed bombs, path traversal, malformed encodings, multi-line exhaustion and injection.
- Do not execute arbitrary untrusted enrichment scripts in the application process; use a locked-down runner and allowlisted operations.
- Multi-user auth, persistent service storage, secrets and backups are **not** implemented now. Introduce formal contracts before enabling them.
- No application is yet deployed; initial repository is docs only. Production release requires separate approval, runtime qualification, browser acceptance and Full User E2E.

## 8. Open design choices pending evidence

- Exact Stellar parser artifact and loader contracts by format family (not by UI screenshot alone).
- Whether provided parser is raw Fluentd, proprietary legacy JSON/CONF pair or modular JSON, or another custom shape.
- Minimal plugin set, Ruby/regex engine feature subset and target deployment safety.
- Concrete Interflow mapping dictionary and precedence, including source tenant metadata.
- Persistent datastore and authentication stack, if/when collaboration becomes part of the first release.

## 9. Architecture acceptance tests

- A project file authored without a Stellar version selector can be saved/reloaded without semantic change.
- For supported Fluentd operators, emitted config matches the fixture expectations when executed by the native pinned runner.
- Unsupported operators cannot be exported with Verified status.
- Every regression result is tied to project revision, fixture hash, runtime profile and actual output.
- No user-controlled sample or regex can access host files/secrets/network outside runner permissions.


## 10. Bounded schema, family and extension layers

The accuracy-first parser path uses three separate concepts that must not be collapsed into one vendor-specific parser:

1. **Envelope/extraction layer:** Syslog and structural framing parse transport/header structure before vendor payload interpretation.
2. **Vendor schema registry:** reviewed ordered layouts can assign semantic source names only after bounded anchor checks. Later unreviewed columns remain preserved vendor fields; total column count alone is not a schema identity.
3. **Parser-set routing:** when explicitly source-parsed events identify different families, each family is handled as an exact source-accounted subset instead of widening one extractor across incompatible shapes.

A mapping-only extension is a separate overlay bound to the exact base draft SHA-256. It may add a mapping or change destination/type/group for an unchanged source field, but it cannot remove mappings, rebind source paths, change extraction structure, or imply native/target compatibility.

Browser-generated robustness variants are diagnostic fixtures, not new training data and not vendor truth. They are restricted to syntax-equivalent transformations with bounded size and compare normalized outputs while ignoring preserved raw copies. Their PASS state never changes native Fluentd or Stellar target evidence.
