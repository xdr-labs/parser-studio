# Parser Studio — Repository Execution Rules

Canonical Engineering System: https://github.com/datarelay-labs/engineering-system

## First read

Read this AGENTS.md and .engineering/project.yaml before substantive work. Then use docs/00_START_HERE.md for document routing and docs/06_ROADMAP_AND_ACCEPTANCE.md for the single ordered development roadmap. For product scope use docs/01_PRODUCT_VISION.md, for UI changes docs/02_WEB_UI_SPEC.md, and for parser or export changes docs/03_FUNCTIONAL_REQUIREMENTS.md and docs/04_ARCHITECTURE.md. Read additional standards only as the task needs them.

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

## Concurrent development and document ownership

- Another chat/session actively owns the implementation; preserve its branch, uncommitted files, current test outcomes and Work Packet. Never reinitialize or clean its working directory from the documentation lane.
- This lane changes only documentation on Draft PR #2 and the single high-level Issue #1 roadmap, without merging, releasing, or changing source/CI.
- docs/08 defines the primary Guided Builder; docs/02 defines only optional Expert Workbench; docs/09 defines paired Ruby/CONF backend behavior; docs/06 defines task ordering. Actual Git/PR/CI and active Work Packet override stale progress prose.

## Initial implementation context

The owner has designated a no-code developer-replacement product: field SEs and partners must generate the two actual host reference files without manually writing Ruby/Regex/Fluentd. Read docs/08_NO_CODE_USER_EXPERIENCE.md and docs/09_BACKEND_PAIRED_ARTIFACT_DESIGN.md before UI, compiler or export work. Read-only reference pair structures were inspected on `rickmodular`; do not modify its live td-agent. No raw user event corpus has been supplied. Do not fabricate fixtures as evidence of real Stellar compatibility. Work in roadmap priority: stable IR and safe pair renderer → accessible Guided Builder → isolated native tests → target import validation. Preserve the preexisting staged `feat/ui-workbench-scaffold` changes.
