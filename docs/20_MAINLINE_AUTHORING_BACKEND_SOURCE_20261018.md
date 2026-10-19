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

## Scoped shipping runtime after source import

The originally imported 187 files came from the byte-identical pinned
backend tree. This later candidate adds an **authoring-only HTTP wrapper**
plus regression tests and changes the default npm start command. Consequently
the current derived backend tree has new additions and is no longer identical
to the frozen source snapshot; the unchanged original importer commit is
preserved in Git history for reproducible comparison.

The backend package's default entrypoint is now
dist/src/mainline-authoring-server.js. The shipping source invokes the
already qualified, offline-only compiler, validation, schema, inspection,
ZIP and ParserRecipe modules directly, without importing the historical
http.ts server at all. The historical target, Test Lab, sensor,
tenant-revision, automated AI and Interflow HTTP handlers are absent from
the shipping module's transitive source-import graph, not merely hidden
behind an HTTP allowlist. Requests for any such route return a
non-reflecting HTTP 404. The executable binds 127.0.0.1 only. No
access credentials, DP configuration, target authorization or production
instance is modified.

The archived http.ts and legacy modules remain in Git and retain their
independent non-product regression tests; the product entrypoint cannot
construct or register them. A source dependency-graph test fails if
any new unreviewed module is reachable from the shipping entrypoint.
HTTP contract tests validate the original DRAFT Ruby/CONF, Recipe v0.2,
inspection and SHA-256 ZIP behavior with no target access. The scoped
authoring test inventory after the isolation change: 336 passed,
10 explicitly skipped, 0 failed, plus TypeScript build/check PASS.
These results do not certify the entire historical target-capable
backend, customer deployment, proprietary runtime, or external access
security.

This is a candidate for mainline after same-HEAD native and browser/HTTP
qualification, not a completed release or target runtime verification.

## Honest backend regression scope

Before product-scope isolation, the original whole-backend Node runner
returned **361 tests / 340 pass / 12 fail**. Every observed failure came
from four retained historical target/optional Drain3 suites. The complete
historical backend is therefore **NOT FULLY GREEN**. The new
test:authoring command explicitly names those non-product suites,
validates that the scope file inventory exists, and runs every other
backend test without skipped hidden suites. The excluded tests are
preserved and remain runnable but are never reported as passing. The
backend scoped HTTP authorization boundary has its own focused tests.

## Capability projection

The exact offline authoring entrypoint returns only a capability document
accepted by the existing strict Parser Studio client. Legacy Test Lab,
external AI, native manifest, revision and target/DP operations are not
advertised as available, and direct requests to their routes still fail
closed. HTTP tests compare the permitted route set with the advertised
features so future code cannot silently widen product claims.

## Both user creation methods on the scoped service

The same-HEAD browser acceptance step exercises real local backend HTTP
through the authoring-only entrypoint for both Auto Parser and ChatGPT
Assisted Parser, including bounded selected-area split/merge recovery and
DRAFT generation. The opt-in PARSER_STUDIO_SCOPED_AUTHORING_E2E flag is
for a locally started, test-only authoring backend, never a target device.
This does not validate production deployment or Stellar device ingestion.

## Native Ruby syntax regression found in CI

Exact-HEAD Actions on the first scoped backend branch failed in nine
Generic Structural Ruby helper tests because a brace-style lambda contained
an invalid unguarded rescue clause. The generic IP validator now uses an
explicit begin/rescue/end block without changing extraction or source-field
handling. GitHub CI requires ruby -c of the native helper and still runs its
Ruby execution assertions. The local dev-atlas environment lacked Ruby;
source/static checks are **not** represented as native Ruby PASS until
GitHub exact-HEAD CI confirms them.

## Historical CLI entrypoint fail-closed

Both backend CLI source entrypoints now instantiate the same restricted
HTTP authoring-only server. Direct execution of the earlier server.js
filename cannot silently re-enable historical target/Test Lab routes.
This is defense in depth; no historic API handlers are authorized for
production use, and the complete integrated artifact remains a Draft PR.

## Explicit native negative-oracle semantics

Native CI showed three test failures after repairing Ruby syntax: the
top-level Generic Structural dispatcher correctly raised ArgumentError for
unsupported input, while nine historical negative checks incorrectly
expected nil (the contract for *individual grammar probe* functions).
Their assertions now require the specific failure. This preserves the
existing fail-closed parser behavior and does not promote any unsupported
input to successful parsing. New Ruby CI remains the authoritative check.

## Generalized IP host lexical boundary

Follow-up Ruby CI found one genuine false-complete path: an invalid
address in a positional security event could still satisfy a permissive
IP-token count. The common IP validator now accepts only a full four-octet
IPv4 lexical form or a colon-bearing IPv6 form **before** IPAddr validates
the value, so decimal port tokens can never masquerade as IP hosts.
This is a shared parser grammar safeguard, not a vendor-specific patch.
The independently pinned invalid-destination case remains a negative
acceptance check; do not promote it to PARSED to improve metrics.

## ISO calendar and clock fail-closed validation

The most recent Ruby CI exposed a separate real false-positive: some Ruby
Time.iso8601 versions normalize invalid dates (such as February 30) rather
than rejecting them. Both bounded ISO mixed and positional parsers now share
an explicit Gregorian date and clock round-trip validation. An invalid
input must remain unsupported; new negative cases cover nonexistent
February 29/30 and out-of-range clock hours. This is a common standard
parser rule and does not add any manufacturer-specific exceptions.
