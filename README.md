# Parser Studio 2.0

**Status:** English-only Parser Studio with exactly two user-facing creation methods, a strict backend-generated Ruby + CONF draft path, and independent approval gates. No proprietary Stellar target import or real DP/sensor E2E is claimed.

## Only two parser creation methods

**Auto Parser:** Paste or upload representative logs → automatically recognize supported formats → review extracted/normalized fields → optionally adjust the mappings in the same review screen → test the complete sample → generate the extensionless Ruby and CONF DRAFT files with SHA-256 verification.

**ChatGPT Assisted Parser:** Enter source logs locally and desired fields → manually redact and approve the examples for ChatGPT → copy the privacy-reviewed prompt yourself → paste the suggested ParserRecipe v0.2 JSON back into Parser Studio → validate its source digest, schema and safe operations → compare any single added mapping against independent holdout data → explicitly approve → generate the same SHA-verified Ruby and CONF DRAFT pair.

**The old six-step Wizard, three-pane Workbench, and their entry points are retired from the v2.0 product UI.** Legacy workspace URLs do not reopen them. Their safe extraction, field mapping, browser worker, revision and code-generation libraries can still be reused internally. No Expert Mode or Advanced Wizard is presented as a third authoring path.

The current ChatGPT path can compile an unchanged canonical supported recipe or **one independently verified additive field mapping**. Arbitrary Ruby, Regex/JSONata execution, unsupported transformations and source formats without a native parser remain rejected rather than misrepresented as deployable outputs. The user sees a review/unsupported message in these cases.

### Data privacy and authorization

Raw source logs stay in the browser during standard analysis. The ChatGPT prompt contains fixed source metadata (event count, source digest and reviewed format labels), an optional declarative schema-owned reference recipe, and **only log examples that the user manually redacted and explicitly approved**. There is no automatic prompt transfer, OpenAI API credential collection, or provider call. Inspect the copyable prompt before sharing it.

Files are DRAFTs and not evidence of a running parser. Version history, ZIP download and mock-only apply appear after a verified generation, not as separate creation methods. Real DP Apply, Sensor Replay and Interflow verification require independent backend authorization and target evidence and remain NOT VERIFIED. The protected development preview blocks unsafe target-mutating routes.

### Backend and tests

The backend owns the validated ParserProject v0.1 compiler, the strict ParserRecipe v0.2 staged equivalence, source-bound SHA receipts, and bounded Ruby3.2/Fluentd1.17.1 public-synthetic Native qualifications, including explicitly TCP-framed Java exception traces. Mixed parser routing is limited to 2–4 chosen reviewed families, and sensor/CONF listener ports are the same. Syslog ports are at least 6800.

A single ChatGPT Chat session owns Web UI, backend, integration tests, the roadmap and two Draft PRs.

- [Final two-path UI and acceptance](docs/14_TWO_PATH_PRODUCT_V2.md)
- [Original roadmap and acceptance; overridden for UI by v2.0](docs/06_ROADMAP_AND_ACCEPTANCE.md)
- [Issue #1 and ACTIVE Work Packet](https://github.com/xdr-labs/parser-studio/issues/1)
- [Web UI Draft PR #7](https://github.com/xdr-labs/parser-studio/pull/7)
- [Backend Draft PR #4](https://github.com/xdr-labs/parser-studio/pull/4)

Development commands: npm ci; npm run dev; npm test; npm run build; npm run test:browser.

Historical Chromium suites relying on the retired Wizard/Workbench are preserved under tests/legacy-removed-ui as a migration inventory; **they are not reported as green/current tests**. The updated Chromium suite exercises the two real user methods, and the backend's independent synthetic Native tests protect generation.

## English-only Parser Studio

All UI text, source, documentation, comments and tests must be written in English.

## Release boundary

No actual sensor traffic, production DP change, external AI provider connection, PR merge or release without separate operator authorization and target-specific evidence.
