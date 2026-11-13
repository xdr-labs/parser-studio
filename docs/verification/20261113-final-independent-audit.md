# 2026-11-13 Final independent code audit and browser E2E

Scope: audit of `main` db929f4 (no trust in earlier audits), real Chromium E2E (Playwright) of the
Paste → Analyze → Review → Map → Create → Download journey on the deployed preview and on a local
instance of this branch, Ruby 2.4.9 execution of every downloaded artifact, ChatGPT Assisted checks.

## Confirmed defects (all fixed at the shared layer, RED → GREEN)

| # | Severity | Defect | Root cause | Guard |
|---|----------|--------|-----------|-------|
| 1 | HIGH | Browser reports BSD tagged / classic-PID syslog as structurally parsed; the downloaded Ruby emitted a parse-error record | Two Generic Structural modes existed only in `src/genericStructural.ts` | `generic-structural-helper.test.ts` (chain parity + behaviour) |
| 2 | HIGH | Ruby 2.4.9: `{**stringKeyedHash}` raises `TypeError` in the generic helper | Ruby ≥2.7 idiom in a template for a 2.4 target | lint test over all templates + compiled-artifact test |
| 3 | MEDIUM | `parserstudio_split_escaped` silently redefined (the helper is appended to the fragment inside one class) | Same method name in two templates | duplicate-`def` test on the compiled artifact |
| 4 | HIGH | Mixed projects (`rfc3164_kv`) dropped tagless BSD-syslog events (`<PRI>Mon dd hh:mm:ss k=v`) | `parserstudio_mixed` router and `parserstudio_syslog_rfc3164` tagless guard | `mixed-rfc3164-tagless-native.test.ts` (positive, negative controls, disallowed family) |
| 5 | MEDIUM | Browser accepted RFC5424 VERSION `2`; Ruby required `1` and hard-coded `version=1` | Regex and value diverged between TS and Ruby | `Generic Structural Ruby envelope accepts the same RFC5424 VERSION digits…` |
| 6 | MEDIUM | ChatGPT Assisted path created files and a success message while the manufacturer/product were still the demo placeholder (`Vendor: Demo Local Draft`, `customized_demo_firewall`) with no warning, unlike Auto Parser | `warnIfPlaceholder` never passed in `ChatGPTAssist.tsx` | `ChatGPTAssist.placeholderIdentity.test.tsx` |

`quality.yml` now runs the generic helper and mixed tagless tests on the digest-pinned Ruby 2.4.9 target.

TS ↔ Ruby differential (818 candidate lines × all browser profiles, 338 accepted by TS):
before 334 same / 4 divergent, after 338 same / 0 divergent.

## Owner action required: reviewed-template approval

Fixes 1–5 change the generated Ruby template. `KNOWN_TEMPLATES` in `backend/src/stellar-legacy-plan.ts`
is an owner approval list for the disposable POC upload path; this audit did **not** add to it.
`test/poc-template-approval.test.ts` and 10 tests that build a reviewed POC pair therefore fail on this
branch until the owner reviews the new generated template and approves its SHA-256
(`95d2bdc6466d1d82f728aec7c0fc2ac222f1afd49a9bcbdf10f17f1ee6c88a2c` on Node 24.21; the hash
is stated to be identical on Node 22 and 24 — re-check from the CI `POC_TEMPLATE_STATUS` line).
On `main` the same tests pass 9/9.

## Behaviours that are design, not defects (left unchanged)

Receive-time fallback when no timezone is present; auto-mapping withheld for fields missing in
some events of a mixed sample; positional-only CSV (header rows not detected); W3C, multi-line XML
and the AWS `{"Records":[…]}` wrapper are blocked or split honestly with no false success claim.

## Open limitations (not fixed here)

- Pretty-printed multi-line JSON (e.g. Suricata publisher example) is not auto-recombined.
- Multi-line XML (Windows 4624) splits into one event per line (0 structurally parsed, reported as such).
- Cisco ASA 106023 with a hostname-less `Mon dd yyyy hh:mm:ss:` timestamp: 0 of 3 parsed (reported).
- Linux audit nested `msg='…'` stays in the unparsed remainder.
- Fortinet CEF written as `CEF: 0|…` falls to generic `space_kv`; `deviceExternalId` stays in the residual.

## Not verified

No independent Stellar Cyber 7.0 dictionary, no real DP/sensor import, Playwright Chromium rather than the
Chrome extension, ChatGPT multi-type and single-sample repair paths covered by existing unit tests but not
re-run in a browser, several vendor publisher pages unreachable (provenance recorded per case).
