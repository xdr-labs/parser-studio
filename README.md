# Parser Studio

Independent, version-neutral log parser workbench for Stellar Cyber and Fluentd-compatible pipelines.

> **Status: R2 no-code Guided Builder (default) and optional Expert Workbench implemented and browser tested. The R1.5 compiler is owned by a separate backend session. Native Fluentd execution, Stellar export and target import remain NOT VERIFIED.**

## Product goal

Replace the frustrating authoring workflow of Stellar Cyber Parser Studio with a practical web workbench:

1. Paste or upload many real raw log events; classify formats and split multi-line events.
2. Visually extract fields and build ordered parsing / transformation rules.
3. Map results to a version-neutral Stellar Cyber / Interflow field model.
4. Compare raw → extracted → normalized events live, explain failures event by event.
5. Execute reproducible Fluentd-compatible parser tests and regression suites.
6. Export only formats proven compatible with their intended runtime; retain portable project files and test evidence.

**Version-neutral** means the editor, internal model and regression tests do not require selecting a Stellar Cyber release. It **does not** mean a single undocumented config format will load unchanged into every release. Export adapters are capability-tested against actual parser examples and target environments.

## Canonical documents

- [01 — Product vision & scope](docs/01_PRODUCT_VISION.md)
- [02 — Web UI/UX specification](docs/02_WEB_UI_SPEC.md)
- [03 — Functional requirements](docs/03_FUNCTIONAL_REQUIREMENTS.md)
- [04 — Architecture, compatibility and security](docs/04_ARCHITECTURE.md)
- [05 — Competitor research and design rationale](docs/05_COMPETITOR_RESEARCH.md)
- [06 — Roadmap and acceptance criteria](docs/06_ROADMAP_AND_ACCEPTANCE.md)
- [07 — Competitive product comparison, license survey and gap matrix](docs/07_COMPETITOR_RESEARCH_AND_GAP.md)
- [08 — Web UI design decisions and acceptance](docs/08_UI_DESIGN_DECISIONS.md)
- [10 — Guided Builder UI-to-backend integration contract](docs/10_GUIDED_UI_BACKEND_HANDOFF.md)

## Current scope

- This repository belongs to **xdr-labs** and follows [datarelay-labs/engineering-system](https://github.com/datarelay-labs/engineering-system).
- The default screen is a six-step English-only Guided Builder: samples → visual field creation → typed normalization → receiver and classification → tests → guarded artifact handoff. Expert Workbench remains optional. They share one draft and session-local sample logs.
- **Export:** only a JSON draft is available. Fluentd `.conf` and Stellar parser export are deliberately disabled until native/target evidence is provided.
- Original customer logs, exports and credentials must never be committed by default.
- The separate docs session conducted a read-only inventory of real `.conf` / extensionless Ruby reference pairs. Real fixture behavior, native loader assembly and target import remain unverified. Prior GitHub Chromium browser 9/9 PASS was recorded in [Actions run 38153121808](https://github.com/xdr-labs/parser-studio/actions/runs/38153121808) for commit `d751252`; new Guided Builder tests must also pass on the target PR HEAD before release.

## Non-goals

No modification of Stellar Cyber production sensors, ingestion rules, tenant settings or deployment without separate owner approval. No claims of 100% vendor-version compatibility without target evidence. No copying competitor-proprietary source code or graphical assets.


## Local Web Workbench (development)

```bash
npm ci
npm run dev
npm test
npm run build
npm run test:browser  # Chromium and native libs required
```

To test actual browser flows, install Playwright's Chromium and required system libraries, then use `npm run test:browser`. On a development host with an already installed browser, set `PARSER_STUDIO_BROWSER_EXECUTABLE` to its executable path. **A successful unit test or browser-only preview is not native Fluentd evidence.**

Current browser preview is intentionally limited to 64 KiB and 500 nonblank, single-line events; format recognition/extraction remains a **subset** (JSON, KV, CSV, RFC5424, named-group regex). No real Stellar parser file has yet been imported. The only allowed export is a portable **unverified** draft JSON without customer sample content.

**Source artifact boundary:** `/opt/td-agent/etc/td-agent/customized_parser` on `rickmodular` contains owner parser reference pairs. The separate authorized documentation inventory is described in Draft PR #2. Neither this UI branch nor the separate backend is allowed to modify live `td-agent`, copy proprietary raw sources into Git or assert upload compatibility without native evidence.
\n## Language\n\nThe application and all project-authored code, UI copy, diagnostics, tests, and documentation are **English only** as directed by the project owner (October 12, 2026). The English-only test prevents new non-English literals from entering tracked source and documentation.\n