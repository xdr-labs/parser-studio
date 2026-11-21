# Lossless-first isolated candidate — independent host qualification v2

## Scope and code identity

- Product code HEAD: `007bd08ee1176f7f4544062ea07dfc871b34df74`
- Follow-up browser regression-only HEAD: `a286f937b4eb99cdcfae2973bc1d87970896ef6f`
- Branch: `experiment/codex-accuracy-lab-20261117`, dev-drlink isolated local clone
- No GitHub push, PR, merge, main, preview, production, or DP change

## Implemented and verified

- Source/event loss guards now reject missing/reordered raw records, invalid UTF-8 residual spans, and truncated path evidence as a full accounting proof.
- Auto Parser passes the exact original sample and same-index exact-match Multi-Pass residuals into the three-column mapping view. Duplicate log lines cannot be associated by first-match search.
- Final event view calculates source SHA-256 and byte count locally, separates record accounting from structural FULL/PARTIAL/UNKNOWN and browser output, prevents stale async results after sample changes, and exposes original raw text when proof is UNKNOWN.
- No browser-normalized value is claimed to be executed in native Ruby/Fluentd or indexed in Stellar Cyber DP.
- Unmapped/unsupported values are visible separately, source leaf names are unchanged and internal canonical paths remain for identity. Omitting raw-line output shows an explicit warning.
- Deterministic corpus includes 24 repository vendor-grammar-derived holdout fixtures and authored synthetic UTF-8, JSON arrays/null/deep/dotted, 128-field, CEF, LEEF, quoted CSV, KV, mixed events. They are **not captured vendor-device originals**. Without native Multi-Pass residual receipts the proof remains UNKNOWN rather than falsely COMPLETE.

## Independent host verification

| Gate | Result | Log filename under /home/aella/.local/state/parserstudio-codex-lab-20261117/ |
| --- | --- | --- |
| Full frontend Vitest | **240 files, 2,072/2,072 PASS** | `20261119-host-full-vitest.log` |
| Python | **191/191 PASS** | `20261119-host-python.log` |
| Grammar & TS-to-Ruby generator sync | **PASS** | exact-head host qualification output |
| TypeScript semantic oracle | **6,288/6,288 PASS**, 32/32 primary mutants killed | `20261119-host-semantic.log` |
| TypeScript/frontend build | **PASS**, old Vite bundle-size advisory | `20261119-host-typecheck.log`, `20261119-host-frontend-build.log` |
| Backend build | **PASS** | `20261119-host-backend-build.log` |
| Chromium Auto/AI/partial/mixed/keyboard | **10/10 PASS** | `20261119-host-fulluser-chromium.log` |
| Chromium source selection to DRAFT Ruby/.conf | **1/1 PASS** | `20261119-host-integrated-draft.log` |
| Chromium real SHA-256/UTF-8 bytes/event count and native-verification disclaimer | **1/1 PASS** (browser test-only HEAD) | `20261119-host-accounting-ui.log` |
| New focused React + adversarial corpus tests | **27/27 PASS**, included in Vitest | `src/guided` source tests |

The code-only changes tested by complete Vitest/Python/oracle/Chromium are at
`007bd08`. Subsequent commit `a286f93` added only a Chromium regression
assertion and passed the focused Chromium check. No product code changed after
the full test run.

## Unverified release gates

1. **Native Ruby 2.4.9 and Fluentd runtime emitted-record/field parity: UNVERIFIED.** Ruby executable unavailable, Docker daemon inaccessible. Compiler/generator sync and DRAFT download do not replace runtime execution.
2. **Actual Stellar Cyber 7.0 DP import, receive and indexing: UNVERIFIED.** Not authorized in this isolated trial.
3. **Captured real vendor-original source corpus mapped to actual native output: NOT FULLY QUALIFIED.** Current fixtures are vendor-grammar-derived or authored.
4. **Native-dependent backend suite: NOT QUALIFIED on this host.** Backend build PASS, not backend native integration test PASS.

This evidence supports the isolated local candidate only; no release readiness or deployment is claimed.
