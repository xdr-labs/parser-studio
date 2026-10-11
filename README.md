# Parser Studio

Independent, version-neutral log parser workbench for Stellar Cyber and Fluentd-compatible pipelines.

> **Status: R2 interactive Web Workbench prototype implemented; unit-tested browser-preview parsing only. Native Fluentd execution, actual Stellar export and owner-specific parser pair compatibility remain NOT VERIFIED.**

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

## Current scope

- This repository belongs to **xdr-labs** and follows [datarelay-labs/engineering-system](https://github.com/datarelay-labs/engineering-system).
- Current development branch provides a local Vite/React Workbench with multiple sample events, browser-only parser simulation, typed mapping, per-event diagnostics, selected-source field proposal, and rule-only revision history.
- **Export:** only a JSON draft is available. Fluentd `.conf` and Stellar parser export are deliberately disabled until native/target evidence is provided.
- Original customer logs, exports and credentials must never be committed by default.
- Real owner parser files are still required to characterize and validate the actual `.conf` plus matching parser artifact contract. Live browser qualification is also still pending.

## Non-goals

No modification of Stellar Cyber production sensors, ingestion rules, tenant settings or deployment without separate owner approval. No claims of 100% vendor-version compatibility without target evidence. No copying competitor-proprietary source code or graphical assets.


## Local Web Workbench (development)

```bash
npm ci
npm run dev
npm test
npm run build
```

To test actual browser flows, install Playwright's Chromium and required system libraries, then use `npm run test:browser`. On a development host with an already installed browser, set `PARSER_STUDIO_BROWSER_EXECUTABLE` to its executable path. **A successful unit test or browser-only preview is not native Fluentd evidence.**

Current browser preview is intentionally limited to 64 KiB and 500 nonblank, single-line events; format recognition/extraction remains a **subset** (JSON, KV, CSV, RFC5424, named-group regex). No real Stellar parser file has yet been imported. The only allowed export is a portable **unverified** draft JSON without customer sample content.

**Source artifact boundary:** `/opt/td-agent/etc/td-agent/customized_parser` on `rickmodular` contains the owner's actual parser material, but content inspection was blocked by platform safety on 2026-10-12. Preserve original samples and existing files; do not assert their schema until directly inspected under authorized conditions.
