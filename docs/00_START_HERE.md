# Parser Studio — Start Here

**Product:** Standalone no-code Stellar Cyber custom parser builder  
**Canonical roadmap:** [Issue #1](https://github.com/xdr-labs/parser-studio/issues/1) and [06 — Roadmap](06_ROADMAP_AND_ACCEPTANCE.md)  
**Execution:** A separate chat/session owns implementation. This documentation branch must not touch its worktree, source, CI or production service.

## Goal — replace external parser authoring

A field SE, partner or ordinary user pastes/uploads raw device logs, configures parsing and Stellar Cyber field mapping in a **six-step guided Web UI without writing Ruby, Regex or Fluentd**, tests all representative records, and downloads the reference-format pair:

```text
customized_<slug>.conf    # receiver and routing rules
customized_<slug>         # extensionless Ruby parser fragment
```

The editor is independent of Stellar Cyber versions. Actual compatibility is **per export adapter and verified target**, not a claim that one file works everywhere. The on-host reference pair, the vendor legacy portal upload formats and modular JSON upload are different contracts until proven.

## Documentation roles — read only what the task needs

| Document | Authoritative subject |
| --- | --- |
| **[06 Roadmap](06_ROADMAP_AND_ACCEPTANCE.md)** | Single implementation priority order, milestone acceptance, evidence gates |
| **[08 No-code UI](08_NO_CODE_USER_EXPERIENCE.md)** | Default six-step Guided Builder, controls, screen behaviors and user scenarios |
| **[09 Paired backend](09_BACKEND_PAIRED_ARTIFACT_DESIGN.md)** | Actual host pair shapes, IR/compiler, native runner, routing and safety boundaries |
| [03 Requirements](03_FUNCTIONAL_REQUIREMENTS.md) | Functional IDs, typed mapping, core safety and regression requirements |
| [02 Expert Workbench](02_WEB_UI_SPEC.md) | Optional three-pane advanced view — not the default experience |
| [04 Architecture](04_ARCHITECTURE.md) | General API/storage/runtime separation; 09 is authoritative for the two-file compiler |
| [01 Vision](01_PRODUCT_VISION.md) | Why, for whom, scope and non-goals |
| [05 Competitor research](05_COMPETITOR_RESEARCH.md) | UI interaction rationale and licensing boundaries |
| [Repository AGENTS](../AGENTS.md) and [project profile](../.engineering/project.yaml) | Mandatory engineering policy before implementing |

**Precedence for product choices:** current explicit owner instruction > actual active implementation state/Work Packet > 06 priority > 08 primary UI and 09 paired backend > older 01–05 background. Git, tests and CI override stale status prose; no safety/release gate is waived by these docs.

## Evidence established vs unknown

- Authorized read-only SSH on `rickmodular`: **454 matched .conf + extensionless Ruby source-fragment pairs** and one unpaired source in `/opt/td-agent/etc/td-agent/customized_parser`.
- Parser fragments expose `STELLAR_INIT` / `STELLAR_PARSE` regions, often embedded `top_fields`, `ns_fields`, `vendor_fields` maps, and `parse(text)`. CONF files configure receiver and routing.
- A handful of reference Ruby files passed syntax-only checks. This **does not prove native Fluentd parsing or Stellar Cyber upload compatibility**.
- The host reference directory is not confirmed as directly included in the running `td-agent` configuration; installed plugin wrappers are different from those source fragments.
- Private raw-event golden fixtures and confirmed target portal import/loader semantics are still missing. They block **full compatibility claims**, not implementation of a typed IR, safe pair renderer or user-first Guided Builder.

## Work coordination (two independent sessions)

- **Development session** owns implementation branch/worktree, its ACTIVE Work Packet, code, tests, PR and CI. Continue its exact unfinished step first. Do not repeat completed features.
- **Documentation session** owns only this docs PR and high-level Issue #1 specification/roadmap. Do not modify production, development worktrees, code or release status.
- No new roadmap Issue is needed. Source/task status is live in Issue #1, Work Packet and actual Git/CI; these docs describe *intended* product behavior, not current implementation PASS.

## Ordered large work units

**R1.5 — typed model and paired compiler → R2 — default six-step GUI → R3 — sandboxed native testing and evidence-backed export → R4 — templates/advanced product quality → R5 — browser + Full User E2E and release gates.** The R1 raw-log sample collection can proceed in parallel and must not halt safe R1.5 work.

No arbitrary Ruby execution on the host; no direct deployment to `rickmodular`; no public commit or third-party upload of customer logs or vendor Ruby sources.