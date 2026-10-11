# Parser Studio — Repository Execution Rules

Canonical Engineering System: https://github.com/datarelay-labs/engineering-system

## First read

Read this AGENTS.md and .engineering/project.yaml before substantive work. For product scope use docs/01_PRODUCT_VISION.md, for UI changes docs/02_WEB_UI_SPEC.md, and for parser or export changes docs/03_FUNCTIONAL_REQUIREMENTS.md and docs/04_ARCHITECTURE.md. Read additional standards only as the task needs them.

## Execution authority

Follow: (1) explicit owner instruction, (2) current ACTIVE Work Packet, (3) Engineering System execution profile, (4) repository rules. The default implementer is CHATGPT_CHAT; alternate runtime and Work mode require explicit owner selection.

Continue the current highest-priority incomplete work, preserve unrelated and dirty changes, implement and test affected behavior, and commit/push verified units. Reports are not a reason to stop. A blocker is only verified owner action or an environmental/permission impossibility; repair solvable issues directly.

## Product invariants

- Build an independent Web UI; do not add features to Stellar Cyber's own Parser Studio.
- Do not bake Stellar Cyber version selections into the authoring data model. Version/runtime differences belong in evidence-backed import/export adapters.
- Fluentd-compatible means native-engine testing, not only a browser regex match.
- Unknown target artifact structure or unsupported syntax must be shown as NOT VERIFIED, not silently exported as supported.
- Raw logs and customer exports are sensitive; redact, isolate and avoid automatic third-party/AI transfers.
- Never mutate production or modify credentials, permissions or release state without the required separate approval.
- Require evidence for readiness: deterministic fixture regression first, browser user paths and Full User E2E on the same candidate before release.

## Initial workstream

The first remaining technical task is ingesting the owner's real sample logs and sample parsers and recording verified contracts. Do not fabricate fixtures as evidence of Stellar compatibility. Read docs/06_ROADMAP_AND_ACCEPTANCE.md for the ordered roadmap.
