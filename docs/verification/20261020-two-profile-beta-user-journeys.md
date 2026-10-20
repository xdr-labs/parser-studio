# Two isolated browser-profile beta journeys — public HTTPS and exact-service local contract

**Date:** 2026-10-20 KST
**Scope:** Regression evidence for two independent browser profiles using the same stateless Parser Studio service. These are two synthetic browser users operated by one test runner, NOT two independent human testers providing owner acceptance. No native target compatibility or release signoff is claimed.

## Verified deployed candidate and test-only branch

- Public development deployment: 6c8f552eaf165622a2a23fa491443df5c57dc68d at https://app.parser.xdr.ooo/.
- Earlier verified real public HTTPS Playwright Full User E2E: 134/134 PASS. That unchanged suite was not repeated.
- Main-target Draft PR #111 base 286a0b37442b816ca51367deac538348816b7f12 differs from deployed 6c8f SHA only in an asynchronous Playwright expectation. This test-only branch is stacked above it.
- No changes to src/, backend/, runtime/ or ops/ between the public code and the new test-only branch.
- Locally built Vite production index SHA-256 c505ee5562ceb3217aff8dcf5728f40b6d32061f8303ed08b9a5f12237bf82e9 matches the actual installed public development index byte for byte. The separate test-only Git HEAD is not deployed.

## New synthetic two-profile acceptance scenario

Source: tests/two-profile-beta-user-journeys-20261020.spec.ts.

1. Create two isolated Chromium browser contexts on the same HTTPS URL. Each has its own origin-scoped IndexedDB, downloads and raw working copy. No user login, HTTP mocks or shared storage.
2. Profile A saves a local version; Profile B verifies an empty list. Profile A then enters independently named Threat, User and Asset logs, including original Korean UTF-8 field values, reviews all three source event types, approves the explicit type routing, maps fields, creates and downloads a Ruby parser DRAFT, verifies three event type variants and no raw Korean value in the Ruby body, and saves its own local version.
3. Concurrently Profile B enters a distinct two-row CSV, prepares a redacted ChatGPT Assisted Parser prompt, pastes a deterministic synthetic reviewed recipe, tests unseen holdouts, explicitly approves the passing fix, creates/downloads a CONF DRAFT, returns to Auto Parser with exact original source, and saves its own local version.
4. Reload both physical browser profiles. Profile A sees only its own saved versions, B only its own version. Restoring A recovers its original named logs and UTF-8 values, restoring B recovers its own original CSV.
5. Assert no JS exceptions, API HTTP 5xx, or requests to foreign origins. The compiler runs with a real stateless offline backend. No simulated/fake HTTP responses, external AI provider calls, DP/sensor operations, credential changes or server-side history storage.

## Immutable evidence

- Actual public HTTPS, one Chromium run: 1/1 PASS, 0 failures, 0 skips, 0 flaky.
  /home/aella/.local/state/parserstudio-public-rollouts/verification-6c8f552e-two-profile-20261020/public-two-profile.json
  JSON SHA-256: 447d68d6471ea0fe94ef0fc83579325d729016b9b1b289aa1f116ecfea2a9c23.
  Public config SHA-256: 63f867a803e6041bf2544f2f5973f0b432c0bc8a3e1d99b0bb63cc8076e86c12.
- Real loopback with isolated compiled same-source Vite 5450, Python Multi-Pass 5452 and offline authoring 5451: 1/1 PASS, 0 failures, 0 skips, 0 flaky.
  /home/aella/.local/state/parserstudio-public-rollouts/verification-6c8f552e-two-profile-20261020/loopback-two-profile.json
  JSON SHA-256: c7959f881261a60d10e1766a7f936beb1a97a9491a6428116b58f46278677f47.
- Attached synthetic, no-secret run summary under two-isolated-browser-profile-beta-evidence in each Playwright JSON.

## New six-suite local CI gate result

- Run the exact CI-scoped Playwright configuration with a real in-repository authoring backend, Vite and Python Multi-Pass, 1 worker and 0 retries.
- **28/28 executed, all PASS; 0 skipped, 0 unexpected, 0 flaky**, comprising 27 retained named-type, compiler-gating and source-container cases plus the new two-browser-profile case.
- Raw result: /home/aella/.local/state/parserstudio-public-rollouts/verification-6c8f552e-two-profile-20261020/local-gated-28.json
- SHA-256: 1c05d1343c72593cab66905cec00a8aa196aa59932282e8c4491f949b828dc11. This is a pre-commit local test on the reviewed integration candidate source, not an exact-HEAD GitHub Actions result for the new PR.

## CI gate and limitations

The exact-HEAD reviewed event family / named multi-log browser CI gate now includes this distinct two-profile test and requires 28/28 executed (formerly 27/27), zero skips/failures/flaky. The test is scoped with PARSER_STUDIO_SCOPED_AUTHORING_E2E=1 so ordinary browser suites may skip it, but the dedicated gate MUST execute it.

Two browser profiles in automation do NOT count as two independent humans providing manual acceptance. Separate owner/human acceptance, Stellar native target proof, production authorization, PR merge and release gates remain pending. Do not duplicate the 134 already verified public scenarios for an unchanged deployment.
