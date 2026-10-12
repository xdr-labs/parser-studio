# Parser Studio

Independent, version-neutral log parser workbench for Stellar Cyber and Fluentd-compatible pipelines.

> **Status: Product definition / documentation complete; implementation and real-parser compatibility NOT YET validated.** Real sample logs and parser artifacts will be supplied separately.

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
- [09 — Secure test Stellar Cyber API setup](docs/09_STELLAR_API_TEST_SETUP.md)
- [10 — Verified POC Custom Parser API CRUD contract](docs/10_STELLAR_POC_API_CRUD_EVIDENCE.md)
- [11 — Guarded POC Legacy Parser REST Adapter](docs/11_POC_LEGACY_DEPLOY_ADAPTER.md)

## Configure test API credentials on dev-atlas

From an interactive SSH terminal, run `python3 scripts/configure_stellar_test_api.py`.
This saves DP URL, Tenant ID and a hidden API Key only to your private user configuration,
not to Git. Run with `--status` to verify the local file exists (not the remote connection).
No vendor API calls or parser deployments are performed by this setup script.
To safely validate User Scope JWT authentication and tenant-scoped parser GET APIs,
run `python3 scripts/probe_stellar_test_api.py` after saving the credentials.
The probe never uploads, enables, modifies, or deletes parsers, and reports only
sanitized HTTP statuses/counts (not keys, JWTs, raw responses, or parser names).
The separate `scripts/test_stellar_parser_crud.py` supports an explicitly
approved POC-only CREATE → read-back → UPDATE → read-back → DELETE workflow;
it is dry-run by default and its `--execute` option changes the live POC.

## Current scope

- This repository belongs to **xdr-labs** and follows [datarelay-labs/engineering-system](https://github.com/datarelay-labs/engineering-system).
- Current deliverables are specs and roadmap, **not** a functioning parser application.
- Original customer logs, exports and credentials must never be committed by default.
- First hands-on implementation step after receiving the promised samples: characterize sample logs and sample parser, pin expected parsing outcomes, validate compatible import/export shapes, then build the workbench.

## Non-goals

No modification of Stellar Cyber production sensors, ingestion rules, tenant settings or deployment without separate owner approval. No claims of 100% vendor-version compatibility without target evidence. No copying competitor-proprietary source code or graphical assets.
