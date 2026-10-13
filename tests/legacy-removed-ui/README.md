# Retired Wizard/Workbench Chromium Tests (preserved, not current PASS)

These unchanged historical tests exercise the six-stage Guided Wizard, Expert
three-pane Workbench, and navigation destinations removed by the Parser Studio
2.0 two-method UI decision on October 13, 2026. They are archived in Git,
not deleted or falsely reported as current passing tests.

Original suites: 46 files; approximate historical test declarations: 138.

Feature-contract coverage retained outside retired screens:
- Existing Vitest source/algorithm tests still run without modification.
- tests/auto-parser-three-step.spec.ts: 3-stage source/review/generate.
- tests/integrated-backend.spec.ts: actual generated Ruby, CONF, ZIP and
  SHA-validation, two user methods, metadata and authorization gates.
- tests/two-path.spec.ts: exact two-choice navigation, privacy, no legacy paths.
- tests/private-drain3.spec.ts and ai-integrated-review.spec.ts: gated optional AI.
- New Auto Parser result-specific revision/Apply/Replay/Interflow tests must
  replace applicable sections of these old suites as those tools are
  separately integrated without adding additional creation menus.

These archived files must not be used in release PASS totals. Do not restore
old route access solely to make historical tests green. Explicitly migrate the
functional assertions instead.

Archived files:
- all-family-audit.spec.ts
- approved-testlab-rate.spec.ts
- approved-testlab-session.spec.ts
- artifact-revision-history.spec.ts
- auto-parser-envelope.spec.ts
- backend-bridge.spec.ts
- backend-expanded-formats.spec.ts
- backend-recovery.spec.ts
- backend-schema-guide.spec.ts
- backend-synthetic-preview.spec.ts
- browser-evidence-comparison.spec.ts
- browser-evidence.spec.ts
- browser-rule-trace.spec.ts
- browser.spec.ts
- csv-delimiters.spec.ts
- dotted-routing.spec.ts
- english-interface.spec.ts
- enrichment.spec.ts
- exact-parser-import.spec.ts
- expanded-starters.spec.ts
- family-coverage.spec.ts
- family-isolation.spec.ts
- field-chip-mapping.spec.ts
- field-path-validation.spec.ts
- field-suggestions.spec.ts
- guided.spec.ts
- interflow-readback.spec.ts
- keyboard-raw-selection.spec.ts
- legacy-preflight.spec.ts
- local-format-advisor.spec.ts
- mapping-coverage.spec.ts
- mobile-guided-expanded.spec.ts
- nested-json-mapping.spec.ts
- official-metadata.spec.ts
- offline-project-json-import.spec.ts
- offline-synthetic-scenario.spec.ts
- package-download.spec.ts
- pair-inspection.spec.ts
- port-proposal.spec.ts
- regex-safety.spec.ts
- replay-preview.spec.ts
- sample-templates.spec.ts
- structured-families.spec.ts
- syslog-body-formats.spec.ts
- testlab-evidence-report.spec.ts
- type-suggestions.spec.ts

Additional retired AI creation UI regression:
- ai-integrated-review.spec.ts tested an optional integrated external-provider
  branch embedded inside Auto Parser. The user selected MANUAL ChatGPT
  copy/paste as the only AI creation method, so that extra public entry has
  been retired. Backend metadata-only provider safety logic and its Vitest
  contracts remain preserved as internal code, disabled by default.
