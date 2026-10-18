# P0-AP2 — Auto Parser as the Default Three-Step UI

**Default entry:** `/` opens **Auto Parser** with a blank sample, not an
already-prepared example or mandatory format selection. The existing six-step
Guided Builder remains under **Edit Details** at
`/?workspace=guided` (also accessible from the left navigation), and the
existing three-pane Workbench remains under **Expert Workbench**. Both
share one in-memory `ParserDraft` and raw sample with the new Auto Parser;
navigating between editors does not discard the user's input or accepted
mapping rules.

## Beginner workflow and evidence

1. **Add Logs** — paste/upload bounded UTF-8 data, with no JSON, CEF, LEEF,
   Regex or Ruby knowledge required. Raw contents are browser-session-only.
   Local envelope/body analysis reports source logical-event denominators and
   unknown/unsupported records without silently dropping minority families.
2. **Review Results** — explicit click fetches the same-origin backend
   **capability metadata only**; never sends raw sample values. A homogeneous,
   supported single-family candidate is applied only after the user approves
   this transition. Conservative deterministic source-name mappings are
   suggested under `custom.*` vendor fields and are clearly marked
   **not an official Stellar dictionary**. Existing edited rules are kept
   unchanged, and incompatible old defaults can be replaced by reviewed
   conservative custom mappings. The selected event inspector shows
   raw/extracted/normalized values only inside the browser.
3. **Test & Generate** — the same complete source is re-previewed in a local
   Web Worker. All source events must extract and normalize without failures.
   The client retrieves and verifies the real backend v0.1 schema and
   capabilities, validates the sanitized typed Project, requests real Ruby and
   matching CONF, verifies both SHA-256 file bodies and manifest, and permits
   separate individual and immutable ZIP downloads. Real Stellar API writes,
   native per-user parser qualification and sensor operations do not occur.

**Fail-closed:** mixed/unknown/malformed samples, ambiguous multiline
boundaries, unrecognized or unsupported compiler modes, changed source,
incompatible typed field rules, backend unavailability, 403 owner denials,
forged native/target verification and invalid SHA responses never unlock a
DRAFT download. Every success label is scoped to local browser and
backend schema/hash verification, not to vendor ingestion or release.
The default server's real DP/tenant/owner APIs remain disabled.

## Tests

- Local safe handoff and no unwanted mapping mutation:
  `src/guided/autoParserDraft.test.ts`.
- Chromium novice, keyboard, narrow-mobile, source preservation,
  privacy, backend-denial and mixed-family checks:
  `tests/auto-parser-three-step.spec.ts`.
- The pinned **real local backend** novice create/download and source
  invalidation test joins `tests/integrated-backend.spec.ts` and runs
  against backend `5a0a58881296bb10ca3a381acba267ac63b50763` with
  separate Git/worktree and loopback HTTP only.

The older Guided and Workbench browser regression suite is preserved
using explicit `/?workspace=guided` navigation, rather than changing
legacy setup semantics or concealing the newly required default Auto
Parser. Feature completion and exact-HEAD Chromium CI should be recorded
in GitHub Issue #1 and Draft UI PR #7.

## Remaining

P0-AP3 versioned ParserRecipe v0.2 staged typed IR and native-qualified
compiler belongs to the backend implementation lane; UI must implement
a bounded **review-only adapter**, not silently reinterpret v0.1 as
v0.2. P0-AP4 whole-source/holdout explainable repair is next after AP3
support, followed by opt-in P1, never as a substitute for native and
independent DP/sensor/Interflow qualification.
