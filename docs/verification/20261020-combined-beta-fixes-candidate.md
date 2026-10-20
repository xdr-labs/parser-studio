# Combined CSV, local history and Python sender candidate

## Purpose and exact inputs

MAIN-1 and CI-1 require one usable, qualified product candidate. PRs #117,
#118 and #119 each passed their own exact-HEAD CI, but all three were siblings
based on #116. No previous single candidate contained every correction.

This isolated branch starts at #119 and applies the exact source, tests and
verification notes from #117 and #118. All three original Draft PRs remain
open and unmerged. Only their conflicting CI test-list edits are reconciled.

| Input | Exact source HEAD | Behavior retained |
| --- | --- | --- |
| #119 / candidate base | 057f389bc2b97bacf5831012d07da738531b2d46 | Strictly quoted two-column CSV with explicit schema review |
| #117 | a91eb0a2f00320e25cb22660a9ecc733422a162f | Grammar-preserving offline Python sender for CSV and embedded query strings |
| #118 | 8bf57781af80e8b2efaf713cc1e40cc4a1941bcf | Safe restore from a full local history using a verified identical checkpoint |

Eleven imported/inherited source and test blobs were compared to these exact
input commits and matched. No manufacturer-specific parsing rule or new
product behavior is introduced by the integration.

## New actual user path

The new Chromium test imports a dedicated synthetic UTF-8 log fixture,
reviews its two-column schema, saves that reviewed draft in Local Versions,
changes the working sample, restores the saved draft, and downloads the actual
Python sender. Its downloaded payload must retain every original source byte,
the reviewed field names, CSV format, delimiter and record boundary.

Only the downloaded pure transformation runs offline. A Python audit hook
rejects socket operations before the script is loaded; neither main() nor
destination prompts execute. A strict CSV reader verifies two output cells,
the unchanged Korean action values, both URL query keys in their original
order, unchanged query user values, and changed documentation IP addresses.
The browser source remains unchanged. No browser exceptions, API 5xx errors
or external HTTP requests are allowed during this user path after navigation.

This is ordinary snapshot restoration. Full-capacity checkpoint reuse remains
covered by #118's separate 30-version real browser scenario and its unit
tests; this new test is not described as another capacity test.

## Complete affected browser gate

The workflow retains all 32 cases from #116, the sender case from #117,
the full-history restore case from #118 and the two quoted-pair cases from
#119. It adds the four existing Local Versions cases and the new combined
user path: **41 cases across 15 unique specs**. The earlier 23-column CSV
regression remains included.

One worker and zero retries run against the locally built candidate backend,
in-repository Python Multi-Pass and actual Vite/Chromium. The CI assertion
requires exactly 41 expected passes, zero skips, zero unexpected failures and
zero flaky results. Existing later CI gates remain intact.

## Local evidence

Evidence root:
/home/aella/.local/state/parserstudio-qualified-beta-fixes-20261020/

- Complete deterministic frontend: **883/883 PASS**, 117 test files.
- Web TypeScript/Vite build and offline authoring backend build: **PASS**.
- Python sender grammar: **12/12 PASS**.
- New combined real Chromium user path: **1/1 PASS**.
- Full affected Chromium: **41/41 PASS**, 0 failed, skipped or flaky cases; 248.1 seconds.

source-provenance.json records the eleven upstream blob comparisons.
tested-source-manifest.json records 594 source, test and configuration
SHA-256 hashes, all independently verified unchanged before commit.
Local validation uses the source subsequently committed; the exact pushed
commit receives its own new GitHub Actions run.

## Evidence checksums

| File | SHA-256 |
| --- | --- |
| combined-41-browser.log | 3f4f2cbef2d0bd28f0fa0a74e56d9885680d4998ae753f73d24277cbff99c509 |
| focused-integration.log | d67bcee3983a70a937a27e36c0172f24d79f6f13bf7bba4a9dfad9fce1d5ee38 |
| full-units.log | ac6f1c2a5034bf07a2fc3c397b41f71e7b05891218abd2355520020d5d6ca981 |
| web-build.log | b59b2edcc3c8c79e446576056204d5ebe90eb9fbb0131be14e5ad11026f55485 |
| python-sender.log | 6f32dffa13a8ad171db7aa520b4b2571d8b2857be860b249a54634698bcd2276 |
| source-provenance.json | 36e567913bc3aefab12fdb52572616ff83438d0e9158fa1cf98683f4b4a594a4 |
| tested-source-manifest.json | f0d126d0000cea74c379e43d73f25845d5dcdab398465bf633b43c49c4cec8ba |

The final commit-specific CI result is recorded in [Work Packet 6283449791](https://github.com/xdr-labs/parser-studio/issues/1#issuecomment-6283449791).

## Boundaries

This is a source-only isolated integration candidate. It does not merge main
or deploy the public development site. Main remains at
19d123d4e39fa7a0301995cd338b4286f5861b3c and the prior public development build
remains 6c8f552eaf165622a2a23fa491443df5c57dc68d. No production, authentication,
credentials, TLS, DP, sensor or native target operation is involved.
Separate owner and actual two-human release acceptance are not claimed.
