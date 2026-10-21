# Parser listener port — default 6801, explicit user override

Owner-approved development integration, 2026-10-21. This document is a development-level evidence record, not proprietary Stellar target-import evidence.

## User path and contract

- The first Auto Parser **Add Logs → Parser identity** screen shows **Parser listener port (.conf)** alongside Manufacturer, Product, and Version, before sample submission. The first **ChatGPT Assisted Parser → Prepare examples** screen exposes the same editable setting. Both share one draft, not two incompatible port values.
- New drafts, starter templates, and common guided defaults use port **6801**. The optional authorized backend port proposal starts at **6801** and skips observed occupancy instead of blindly claiming it is available.
- A user may override the port. One selected integer is kept in the shared receiver draft, backend `receiver.port`, compiled `<source> port`, SHA-verified file download, and ZIP metadata. Syslog validation requires at least 6800, other formats at least 1024, and every port must be at most 65535.
- Existing imported, explicitly saved, or restored user port choices are not reset. Obsolete legacy default fixtures are retired; there is no forced migration or silent mutation of existing user drafts.
- A proposed/free-looking port is **not** a reservation or proof of sensor binding. Generated parser files remain **DRAFT**, target import is **NOT VERIFIED**, and no DP, sensor, external AI, credentials, or production operations are performed by the workflow.

## Bounded verification

- Browser rendering in both creation paths, cross-navigation state preservation, controlled edit to 6819 and invalid-port state; actual offline localhost backend and Python Multi-Pass using synthetic JSON and CSV event records.
- Real generated Ruby and CONF DRAFT downloads on 6801 and 6819 in Auto Parser, plus ChatGPT Assisted reviewed CSV recovery and a downloaded CONF on selected 6819: backend project selected port, CONF `<source>`, and downloaded SHA-256 must agree; source values must not leak into the compiler request.
- Frontend default/override tests, parser adapter, templates, import, and port proposal; backend planner/collision and CONF compilation. Entire regression/CI qualified on the integration PR's exact HEAD, not inferred from historical PR results.
- Public development apply is a separate guarded deployment step after verified main merge. Do not claim it before execution and public Chromium confirmation.
