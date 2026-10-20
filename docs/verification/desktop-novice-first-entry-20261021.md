# Desktop novice first-entry and original CSV end-to-end verification — 2026-10-21

## Owner scope

**Desktop Web UI only. Mobile layout, mobile tests and mobile acceptance are explicitly excluded.** Preserve exactly two creation methods: Auto Parser and ChatGPT Assisted Parser. Never change proprietary target/DP/sensor/credential/production state for this acceptance.

## Independent first-use observation

On the installed preceding source `8c3672b99a0d31b3641da8389a4aa8003d9e9958`, a fresh desktop 1440×900 Chromium profile loaded successfully with no uncaught browser errors, API 5xx or third-party network requests. The original unedited first-screen screenshot was inspected. **The original raw-text log field was below the first viewport**, behind the identity card, explanatory text and multi-type panel, with no first-screen shortcut for a novice who came to paste a log.

The separate isolated branch `fix/novice-first-log-entry-20261021` is based on the same exact merged main commit `59cc0ad8c71640712ea8f171b99c44cd9fa793fe`. It adds only a desktop-visible `Go to log input` action to the initial Auto Parser explanation. Clicking uses the existing textarea's native `focus()`, with no sample rewrite, no new log transport, and no parser/compiler change. The shortcut is not displayed when named log types replace the single raw text box, or when the current Auto Parser stage is no longer Add Logs. The existing manufacturer, product and version inputs remain unchanged.

## Focused qualification

| Gate | Observed result |
| --- | --- |
| Initial RED real Chromium on unmodified main, desktop | Two failures observed: missing shortcut; another test had an ambiguous Playwright identity-field locator. The latter was a test harness selector error, not a product error. |
| Corrected desktop-only Chromium on changed isolated source | **3/3 PASS**, one worker, retries 0, skipped 0, unexpected 0, flaky 0, top-level errors `[]`. |
| Affected frontend, AI fallback and English-language tests | **23/23 PASS** across five files, including source-preservation and explicit profile compatibility. |
| TypeScript and Vite production build | **PASS**. Bundle-size advisory is informational; not a build failure. |
| Source constraints | Desktop-only visible shortcut; original textarea ref and all parser contracts unchanged; all unrelated worktrees preserved. |

The desktop Chromium tests explicitly cover first-viewport reachability, actual textarea focus and Unicode raw-log input, identity persistence, and absence of a misleading shortcut when named type inputs are enabled.

## Separate public-development novice CSV exploration

This additional browser test used the **already-deployed preceding public source** at `https://app.parser.xdr.ooo/`; it does **not** qualify the pending new shortcut as already deployed. A fresh 1440×900 Chromium context, without stored drafts or real user data, entered three synthetic strongly quoted CSV records. The UI requested the two unprovided column names rather than guessing them; reviewed `action,src_ip` were approved. The user continued through Review Fields → Map Fields → Create Parser → actual final test → actual Ruby and CONF downloads.

- Source: three synthetic original quoted CSV records; SHA-256 `37adcfa06f351312e70e10a43741a8c7867929725e0c7055839f019a403e0dfa`.
- The generated parser's recorded identity was `Example Vendor / Edge Firewall / 2.6`, and its extraction metadata contained the reviewed CSV columns and comma delimiter.
- Real downloaded Ruby: `customized_example_vendor_edge_firewall`, SHA-256 `9aff6042295972b5fe0ae25bc981fc6312896590ae65d11d3db47832f54a6405`.
- Real downloaded CONF: `customized_example_vendor_edge_firewall.conf`, SHA-256 `de180b4b2c9a371f1cf0a4d62ff10c5ef51675bdb9a1191f6009342214a25904`.
- Browser errors, public-API 5xx and third-party requests: **none**.
- Initial exploratory attempts used incorrect accessibility-name and backend-project field assumptions in the *test harness*; these were fixed without changing the public product or corpus, and the fully checked final run passed. These earlier failures are not parser defects or passing test executions.
- Local evidence: `/home/aella/.local/state/parserstudio-beginner-acceptance-20261021/public-desktop-quoted-csv-summary.json`, raw desktop screenshots and the ephemeral E2E test script.

## Remaining honest gates

The changed shortcut itself is qualified only in the isolated local real-browser candidate until exact-head CI and subsequent installed/public deployment are actually verified. Any required live restart must use established normal operator authority and hash-checked backup/rollback. Automated synthetic browser contexts are **not** human owner acceptance. Generated parser files remain DRAFT; no Fluentd listener, Stellar importer, sensor or production execution is inferred.

No mobile work was implemented or claimed. The owner retains separate visual acceptance and release authority.
