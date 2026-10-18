# Offline authoring backend — exact-source consolidation candidate

**Status:** isolated DRAFT source-import candidate; **not integrated to `main`**, deployed, released, or qualified for use against Stellar DP/sensors. Repository: `xdr-labs/parser-studio`.

## Why this exists

The two-path Web UI candidate in PR #90 produces vetted parser DRAFT files through a separate pinned Node compiler/backend. A complete product source tree must eventually include the **offline authoring** backend, not just the UI. This candidate brings forward the previously reviewed backend Git tree **without copying any dirty/uncommitted developer worktree state**.

- Clean parent backend commit: `429b179fc674eb07f3e2250e78aea7883a71b433`.
- Expected immutable `backend/` Git tree: `5d8167489fc8c88affd360df9068193588b95934`.
- Files imported: 187 tracked backend files, byte-for-byte tree equality from the pinned commit.
- Local isolated verification: `npm ci --prefix backend`, `npm run build --prefix backend`, `npm run check --prefix backend` **PASS**, using only the imported tree. Source tree parity proves preservation, not native/DP/device accuracy or release readiness.

## Scope boundary and remaining integration

This historical backend tree includes **legacy Test Lab, target, sensor, Interflow, and owner-revision source code** alongside the required schema, compiler, package, inspect, and ParserRecipe endpoints. Importing it into a protected DRAFT branch **does not adopt or authorize those legacy operations**. The current two-path UI does not expose target, Test Lab, or Interflow controls; previous backend deployments default-deny protected APIs. No credentials, production assets, real sensors or DP endpoints are used here.

Before including a backend runtime in `main`, keep the authoring-only API surface, explicitly retire or isolate historical target-capable routes, reconcile current product scope, and qualify the *combined exact product/backend HEAD* with deterministic tests, full Chromium user flows, and real loopback HTTP DRAFT creation. The existing CI's pinned external-backend check is a separate integration proof, **not** proof that this newly copied subtree is productized or permitted for target use.

Do **not** merge this candidate automatically, silently enable target operations, or relabel any historical native/sensor accuracy as verified.
