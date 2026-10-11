# Parser Studio

Independent, version-neutral log parser workbench for Stellar Cyber and Fluentd-compatible pipelines.

> **Documentation status:** No-code product design is consolidated in Draft PR #2. A separate session owns implementation; verify its current Git/CI evidence before reporting code status. Reference artifact structure is known, but full runtime/import compatibility is not yet proven.

## Document starting point

Read [00 — Start Here](docs/00_START_HERE.md), [06 — Ordered Roadmap](docs/06_ROADMAP_AND_ACCEPTANCE.md), [08 — No-code GUI](docs/08_NO_CODE_USER_EXPERIENCE.md), and [09 — Paired Backend](docs/09_BACKEND_PAIRED_ARTIFACT_DESIGN.md). Source development is handled by the active implementation session; this documentation branch does not modify its code.

## Product goal

Replace the frustrating authoring workflow of Stellar Cyber Parser Studio with a practical web workbench:

1. Paste or upload many real raw log events; classify formats and split multi-line events.
2. Visually extract fields and build ordered parsing / transformation rules.
3. Map results to a version-neutral Stellar Cyber / Interflow field model.
4. Compare raw → extracted → normalized events live, explain failures event by event.
5. Execute reproducible Fluentd-compatible parser tests and regression suites.
6. Export only formats proven compatible with their intended runtime; retain portable project files and test evidence.

**Version-neutral** means the editor, internal model and regression tests do not require selecting a Stellar Cyber release. It **does not** mean a single undocumented config format will load unchanged into every release. Export adapters are capability-tested against actual parser examples and target environments.

## No-code, developer-replacement priority

**Primary user:** a field SE, customer or partner who does not program in Ruby, Regex or Fluentd. The default six-step Guided Builder must generate a matched pair of `customized_<slug>.conf` and extensionless `customized_<slug>` Ruby parser source fragment as found on `rickmodular`. It is not merely a Regex tester. A separate, evidence-backed export adapter is needed for the vendor's modular JSON upload workflow; a host Ruby fragment is not automatically the documented portal JSON upload file.

## Canonical documents

- [00 — Start Here / documentation map](docs/00_START_HERE.md)
- [01 — Product vision & scope](docs/01_PRODUCT_VISION.md)
- [02 — Web UI/UX specification](docs/02_WEB_UI_SPEC.md)
- [03 — Functional requirements](docs/03_FUNCTIONAL_REQUIREMENTS.md)
- [04 — Architecture, compatibility and security](docs/04_ARCHITECTURE.md)
- [05 — Competitor research and design rationale](docs/05_COMPETITOR_RESEARCH.md)
- [06 — Roadmap and acceptance criteria](docs/06_ROADMAP_AND_ACCEPTANCE.md)
- [08 — No-code UX contract](docs/08_NO_CODE_USER_EXPERIENCE.md)
- [09 — Paired parser backend architecture and real host evidence](docs/09_BACKEND_PAIRED_ARTIFACT_DESIGN.md)

## Current scope

- This repository belongs to **xdr-labs** and follows [datarelay-labs/engineering-system](https://github.com/datarelay-labs/engineering-system).
- The documentation PR is specs/roadmap only; implementation and tests are tracked by the separate development session and must be verified from actual Git/CI state.
- Original customer logs, exports and credentials must never be committed by default.
- The owner supplied read-only access to 454 real `.conf` + extensionless Ruby parser pairs on `rickmodular`. Structural analysis is complete in document 09; private raw event samples and exact portal loader/import semantics still require separate behavioral evidence. The next implementation target is safe pair generation and an easy, six-step guided UI.

## Non-goals

No modification of Stellar Cyber production sensors, ingestion rules, tenant settings or deployment without separate owner approval. No claims of 100% vendor-version compatibility without target evidence. No copying competitor-proprietary source code or graphical assets.
