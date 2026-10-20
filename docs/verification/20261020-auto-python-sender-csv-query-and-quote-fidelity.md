# Auto/Mixed Python Test Sender: preserve CSV URL query data and strict lexical grammar

**Date:** 2026-10-20 KST
**Candidate:** isolated dev-atlas source branch stacked on approved source-only Draft #116 (head `0021de3313392f70fbae1728bcfd46b8bf25715b`). No public deployment, main merge, DP, or sensors.

## Reproduced generic source loss

The optional, manually downloaded Python standard-library sender creates synthetic events from browser-reviewed logs. Its Auto/Mixed path excluded **every** row containing `=` from CSV handling, even when the user supplied exact positional CSV column names. Worse, the fallback KV detection matched `user=` **inside a URL query parameter** and consumed the following `&srcip=...` as part of the value. For example, an authored three-column source:

```text
allow,gw01,https://example.test/path?user=alice&srcip=192.0.2.10
```

was rewritten as only `allow,gw01,https://example.test/path?user=userNNNNN`, silently losing `srcip` and changing the meaning of an opaque URL field. Explicit CSV mode on the same sample retained both query parameters. This is generic structural data loss, not a manufacturer-specific mismatch.

An independent Python RED suite first established failures for Auto and Mixed formats across comma/semicolon/TAB and quoted CSV plus the same shape with no schema, while genuine top-level KV stayed intact. A second RED suite reproduced permissive quote toggling in `_csv_segments()` accepting illegal embedded quotes and nonblank bytes after closing quotes, unlike the UI's strict `tokenizeCSV()` contract.

## Small, common-grammar correction

- Auto/Mixed now *attempts* CSV field-level mutation with the **explicit, reviewed CSV columns and delimiter** before generic fallback when there is no Syslog/CEF/LEEF/JSON envelope and no leading top-level `key=value` signature. It still requires strict Python CSV parsing and exactly the approved number of columns. Unrecognized events retain conservative fallback behavior.
- Top-level Python KV recognition is limited to actual separator boundaries (start, whitespace, `|`, `;`, `,`, `:`); `?user=...`, `&srcip=...` and URL path internals are no longer treated as free-standing KV fields. CEF/LEEF extensions and true space-separated KV still retain their prior behavior.
- Existing `_csv_segments()` now follows the same strict quote-state transitions (start/plain/quoted/after-quote) as the product's browser CSV lexer, while retaining raw lexical substrings. Illegal interior quotes, bytes after a closing quote, and unmatched quotes cannot be treated as structurally valid CSV for field mutation. Explicit CSV with invalid grammar returns the original record unchanged.
- No new dependency, network API, parsing fallback service, manufacturer regex or sensor/DP call. All generated scripts remain Python standard-library only, user-run and confirmation-gated.

## Executed acceptance

- `tests/test_python_sender_formats.py`: 12 source/transport grammar tests including the new Auto/Mixed data-retention and strict invalid-quote cases, plus existing RFC3164/RFC5424, CEF/LEEF, JSON, KV, epoch, UTF-8 and no-eager-network checks. Baseline RED and fixed GREEN transcripts are retained.
- New `tests/python-sender-auto-csv-query-20261020.spec.ts`: actual Playwright CLI Chromium page + browser-generated Python `.py` download. It decodes the downloaded script *offline* using Python `runpy` (never calls `main()` or opens a socket), checks the original source and that modified output still contains both URL query names and a changed documentation IP address, with zero browser exceptions or application API writes.
- Expanded dedicated same-source Chromium acceptance from 32 to 33 test cases, with no mock HTTP responses, one worker, zero retries. Also retain full unit/build and backend scoped checks. Do not describe real target parser delivery, native Stellar import, sensor receipt or manufacturer semantic meaning as verified.

## Evidence

Developer-only evidence lives in `/home/aella/.local/state/parserstudio-auto-csv-sender-query-20261020/`; relevant files: `red-python.log`, `lexical-red-python.log`, `green-python-v2.log`, `browser-focused.json`, `full-unit.log`, `web-build.log`, `backend-build.log`, `scoped-33-browser.json`. Local verified SHA-256:

| Evidence | SHA-256 |
| --- | --- |
| `final-python.log` | `f66812f46e62c933d079e0254b7db44a8a532cee51219515336632a74503fbab` |
| `full-unit.log` | `c6f6c34e520e6a0429de2d196385ab8e2be0ed0f48a30044b3f3bcce0036e5a9` |
| `web-build.log` | `7d7cfc99ace7f07a040a128548c50ac002c23f1dc6b32f544df5f349088c1313` |
| `backend-build.log` | `87cd3cf566da0f143d449cc01b50779a6e5d883f4c780637480d1ebbbd97d559` |
| `browser-focused.json` | `96024ff77e70575e4f0477952fda93a9619515ca6b49171fc44744f2faa4f974` |
| `scoped-33-browser.json` | `67b315ade5aee80278d185d75a570207bf958a0b00889d20ece19c6eb5fb63a6` |

Full deterministic frontend: 865/865 PASS in 115 test files. New Python stdlib: 12/12 PASS. Real Chromium 33/33 PASS with zero failed/skipped/flaky, one worker, zero retries, local Vite + offline authoring backend + in-repo Multi-Pass. The exact pushed source HEAD and independent GitHub Actions final result are recorded on the stacked Draft PR/Issue #1 Work Packet.
