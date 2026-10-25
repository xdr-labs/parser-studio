# Remaining Security Logs — Real Web UI / Native Holdout Acceptance

Date: 2026-10-26 KST. Owner requested evidence-led improvements after the
2026-10-25 novice 54-case acceptance. Execution: CHATGPT_CHAT on dev-atlas.
Baseline source and publicly installed product: exact main
`c73733138e3786b9c4197cf26100bafde89d9f0a`.
The public URL is `https://app.parser.xdr.ooo/`.

## Evidence and interpretation

These tests use **authored synthetic log examples**, not actual manufacturer-device
captures or independent producer/firmware goldens. GPT-6 authored bounded
ParserRecipe v0.2 responses under the controlled same-conversation model/user
exercise; **no authenticated external ChatGPT API/website completions** occurred.
The workflow still uses the real public Chromium UI, HTTP endpoints, manual
review/approval, genuine Ruby/CONF downloads, and actual native Ruby callbacks.
The returned files remain DRAFT; Stellar Cyber target compatibility is unverified.

**Live public Chromium: 7/7 acceptance tests PASS.** These represent two
different expected dispositions, not seven successful native parsers.

| Case | Distinct source-other-than-original holdouts | UI result | Native DRAFT |
| --- | ---: | --- | --- |
| ModSecurity denied requests | 2 synthetic | PASS | 3 callbacks, lexical values retained |
| Cisco ASA 302013 connections | 2 synthetic (with/without optional NAT pair) | PASS | 3 callbacks |
| WatchGuard Firebox | 2 synthetic (allow/deny, TCP/UDP) | PASS | 3 callbacks |
| Snort fast/syslog and optional message quoting/AppID | 2 synthetic | PASS | 3 callbacks |
| Quoted four-column CSV without trusted schema | 2 synthetic | REJECTED | No DRAFT; 2 previously extracted original field paths protected |
| Zeek TSV with #separator/#fields headers | metadata and data | REJECTED | No unsafe header-dependent DRAFT |
| W3C IIS with #Fields schema | metadata and data | REJECTED | No unsafe space-delimited DRAFT |

For the **four** generated parsers, the actual downloaded Ruby ran the original
plus both source-disjoint synthetic holdouts: **12/12 native callbacks PASS**.
A separate malformed or format-incompatible mutation of each original returned
**no successful parsed output: 4/4 fail closed**. This is bounded evidence, not
proof of future firmware/new event family generalization. Source hash/provenance
is tracked in console output. Only authored synthetic fixtures are committed;
no customer/device capture or downloaded parser artifact is staged in Git.

The quoted-CSV proposal correctly extracted the original into four neutral
columns but would have discarded **two preexisting normalized source field
paths**. Parser Studio's before/after comparison rejected the proposal and
disabled Apply/Generate. The old UI only said "Original logs still pass: NO",
which was misleading because the actual candidate source extraction passed.
The implementation adds **source-safe aggregate rejection details** describing
exactly why a candidate is blocked without relaxing that protection.

Header-dependent Zeek and W3C data must not be converted into a single-line
headerless v0.2 parser through a guessed dialect; the public UI correctly
refused those candidates. This remains an explicit format/stream-contract
limitation until a suitable documented header-aware native adapter exists.

## Product change and tests

- `src/guided/chatGptFailureExplanation.ts`: pure aggregate-only rejection
  reason helper; no raw values or source field contents in failure text.
- `src/guided/ChatGPTAssist.tsx`: shows failure reason beside Overall FAILED.
  Existing acceptance/approval gates, generated parser compiler, and
  field-preservation logic are unchanged.
- Pure deterministic helper unit regression: **5/5 PASS**.
- Final exact-source isolated Chromium with real pinned authoring backend and
  multipass service: **2/2 PASS** for lost fields and header-unsupported cases.
- TypeScript + Vite production build: **PASS**.
- Operator-only public browser/native tests are gated by
  `PARSER_STUDIO_PUBLIC_NOVICE_CROSS_E2E=1`. Normal CI does not contact
  the public app; source-backed browser tests are explicitly gated by
  `PARSER_STUDIO_SCOPED_AUTHORING_E2E=1`.

Run the bounded live test explicitly from repository root:
```sh
PARSER_STUDIO_PUBLIC_NOVICE_CROSS_E2E=1 ./node_modules/.bin/playwright test \
  --config=tools/qa/remaining-security-public.config.cjs
```

No change has been deployed to the public UI by this candidate, and no live
Stellar Cyber parser import, DP/sensor, production or release action is claimed.
The earlier nested-array native omissions also remain separately documented;
this task did not change them.
