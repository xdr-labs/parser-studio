# Mainline integration: reproducible Multi-Pass structural preview

## Purpose and provenance

The original usable beta's Auto Parser requests `/api/v1/multipass/preview-batch` through Vite. Its working local preview on dev-atlas depended on a manually provisioned Python service running on port 4292 from the protected product worktree's `runtime-active/multipass`. The previous GitHub browser CI did not start this service, producing `ECONNREFUSED` failures and preventing full backend integration acceptance.

This candidate explicitly copies **only the 32 transitive Python production modules** needed by `multipass_preview_api.py` from `/home/aella/parser-studio-beginner-parser-set-e2e-20261016/runtime-active/multipass` at the existing qualified user beta baseline. The previously local service file SHA256 was `b9f2f738a4a96529cadc8e48d2a4c6d89a0dfa33ebf2cd3c58c0fdf696853476` before the health check addition. No dataset, private source log, customer payload, benchmark result, or research-only evaluator is copied. Service code uses Python standard libraries only.

## Test isolation and safety

* `PARSER_STUDIO_TEST_MULTIPASS=1` runs the packaged Python service as an isolated Playwright webServer dependency. CI uses loopback port `5292` and starts/stops its own instance; it does not connect to the dev server's existing port 4292.
* `PARSER_STUDIO_MULTIPASS_PORT` controls the **loopback-only** Vite proxy target, with a validated integer port. Default for existing dev preview remains 4292.
* Readiness uses local GET `/health` without any raw source content. Parsing remains opt-in/source-only with explicit no-native/no-target-verification flags; client input limits, strict source-byte accounting, restrictive local Origin acceptance and absence of raw logging are retained.
* The default application's actual production/runtime packaging, authorization and native target import semantics are **not** implied by an isolated GitHub test passing. No DP/sensor integration or automatic external AI transfer is provided.
* CI runs deterministic Python contract checks before the full Chromium suite and, once passing, the pinned independent localhost parser backend Chromium/HTTP integration.

## Acceptance

Verify Python stdlib smoke tests, existing browser workflows, current normalization mappings, security guardrails, TypeScript/Vite build and **exact pushed HEAD** GitHub Actions conclusion. A failed CI step is not release acceptance. Do not deploy or merge on a partially passing gate.
