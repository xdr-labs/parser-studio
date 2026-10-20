# Explicit multi-log-type entry and conditional DRAFT — implementation evidence

Date: 2026-10-19. Scope: development-only isolated branch
feat/explicit-multi-log-input-20261019 based on the verified installed
Parser Studio source SHA 0392401f0331c89dd07eed70e5ba939c8e4ac85c.

## Requested user journey

In the two-path v2 Auto Parser, a nonexpert can press **Add Another Log Type**,
name up to ten types, and separately paste or upload representative event
samples without knowing whether the source grammar is JSON, CEF, KV or Syslog.
The ordinary **Analyze Logs** button processes the unchanged source records
with only explicit inter-group separators. Each type's counts, parsing
statuses and source-extracted field names are reviewed, including residual
PARTIAL/RAW_ONLY and cross-boundary warnings. A single native-authoring DRAFT
remains conditional on qualified extraction and an explicit event discriminator
in the original source, or independently supported mixed-format grammar.

### Implementation contracts

- Separate typed groups, editable names, file upload/replacement, remove, and
  1..10 bound. Empty, duplicate, oversized and unsafe groups block reviewing
  or generating rather than silently dropping an event. 64 KiB remains the
  maximum combined UTF-8 source sample and 500 events the existing bound.
- Group source byte slices are immutable during concatenation. Each group's
  byte range is retained for assigning exact backend Multi-Pass event intervals
  and showing SOURCE_PARSED / PARTIAL / RAW_ONLY counts; events that cross
  group boundaries are unassigned and block promotion.
- Group names are user review metadata, NEVER inserted into the raw events or
  converted into a runtime discriminator. Existing event_type-based reviewed
  conditional mappings and the backend's unknown: reject contract are reused.
  No manufacturer-specific regexes, Wizard, Workbench or third creation method.
- Changing group labels/samples revokes previous review and generated-file
  evidence; ordinary result/edit/export flow remains unchanged.
- Type names, raw group samples and existing parser rules survive explicit
  browser-only Local Version save/restore, using source-bound checksums with
  backward-compatible verification of earlier version snapshots. Changing
  groups cannot fabricate event parser authority.
- **Privacy and scope:** No third-party AI transfer, DP upload, sensor send,
  target compatibility claim or production deployment. Browser-local versions
  are origin-scoped and unencrypted as already documented. Native Ruby parser
  outputs are DRAFT / target NOT VERIFIED.

### Reproducible verification

The tests use synthetic security events and the real local browser/backend,
not physical manufacturer wire captures.

    npm test
    npm run build
    npm --prefix backend run build
    PARSER_STUDIO_BROWSER_BACKEND=1 \
    PARSER_STUDIO_BACKEND_ROOT="$PWD/backend" \
    PARSER_STUDIO_BACKEND_HEAD="$(git rev-parse HEAD)" \
    PARSER_STUDIO_SCOPED_AUTHORING_E2E=1 \
    PARSER_STUDIO_TEST_MULTIPASS=1 \
    npx playwright test tests/reviewed-event-family-backend.spec.ts tests/explicit-multi-log-input.spec.ts --project=chromium --workers=1

Focused deterministic: **14/14 PASS** over explicit named boundaries, original
Unicode samples, invalid group conditions, event-family routing and local
history. Isolated Chromium new feature **4/4 PASS**, with a real localhost
authoring backend and Multi-Pass service: three distinct type inputs/analysis/
mapping/conditional Ruby parser file download; invalid/duplicate/empty; group
file upload and browser-local saved-version restore; 375px viewport.

The exact-HEAD quality workflow runs these four scenarios together with the
six existing conditional-event/relay browser cases, and checks **10 executed /
0 skipped**. Full same-HEAD CI, product integration, public deployment and
owner real-user acceptance are separate gates. Existing live site SHA is
unchanged; no claim is made that this feature is already deployed.

### Local qualification at the final feature candidate

- Frontend full Vitest: **821/821 PASS** across 109 test files.
- Backend authoring-only contract: **341 PASS, 0 FAIL, 11 preexisting SKIP**.
- Isolated Multi-Pass Python regressions: **4/4 PASS**.
- Frontend production TypeScript + Vite build: **PASS**.
- Same-candidate actual Playwright CLI/Chromium with exact local backend and
  real Multi-Pass (not mock APIs): **10/10 PASS**, combining four new user
  journeys with six previous real conditional-routing/relay scenarios.
  Of these 10, **0 SKIP, 0 FAIL**; logged under
  /tmp/parser-explicit-multi-ten-e2e-20261019.log on dev-atlas.

All three demo source log types were synthetic and no vendor/device/native DP
compatibility was claimed. Public application deployment remains unchanged.
