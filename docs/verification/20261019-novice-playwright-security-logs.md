# Parser Studio — first-time-user live browser E2E (2026-10-19)

## Environment and evidence
- Repository: `xdr-labs/parser-studio`, baseline main HEAD `19d123d4e39fa7a0301995cd338b4286f5861b3c`. Candidate: `feat/novice-browser-csv-20261019` in a separate worktree. Protected dirty worktrees remain intact.
- Real Playwright CLI Chromium sessions used the loopback Vite web UI plus live local Python Multi-Pass and backend authoring HTTP services. Tests did not intercept or mock parser endpoints.
- All 15 initial vendor-style log examples were **authored synthetic samples**, not independent original manufacturer/firmware captures. Counts below reflect **structural field extraction** only, NOT vendor completeness, Stellar Cyber normalization accuracy, native loader behavior or target import.

## Initial 15-case findings

| Initial result | Samples |
| --- | --- |
| SOURCE_PARSED (10/15) | AWS WAF JSON, Suricata IPS EVE JSON, CrowdStrike EDR JSON, Microsoft Defender XDR JSON, FortiGate KV, Palo Alto PAN-OS positional CSV, QRadar LEEF, ArcSight CEF, Check Point KV, RFC5424 KV |
| PARTIAL/RAW_ONLY (5/15) | Juniper SRX, WatchGuard Firebox, Zeek TSV with header, quoted multiline CSV, Windows Event XML |

The **10/15 (66.7%) synthetic-case structural** baseline is not a measured all-vendor success rate. Unsupported/partial inputs were not silently promoted to PASS.

## Fixes and beginner navigation

1. RFC/CSV framing: quoted multiline CSV originally split into four events; now input is preserved as three logical CSV records and marked for explicit review, not native compiler success. Byte-offset accounting is checked for comma/semicolon/tab; malformed quotes stay fail-closed.
2. The Multi-Pass batch endpoint previously erased framing errors when re-running the funnel. `FRAMING_*` events now retain their authoritative incomplete status and are displayed by the real UI.
3. Zeek: `#separator`/`#fields` entries were interpreted as independent log events. An explicit Prepare action now separates format declarations from data events, fills TAB + reviewed safe column names, preserves a restorable copy of the exact original, and sets source-name-only **vendor** mappings without guessing Stellar field semantics. User must confirm schema; no automatic input deletion.
4. Contextual beginner text now explains Zeek headers, multiline/unclosed CSV, and unsupported Windows Event XML with actionable recovery instead of internal parser codes.
5. Actual E2E found a dead-end: Zeek's empty mapping set made Review Fields reject even after a successful column-name confirmation. The opt-in preparation now preserves one reviewable vendor-only mapping per declared column.
6. The Zeek corrected scenario exercises source preparation, Analyze Logs, confirm names, Review Fields, Map Fields, Create Parser, actual backend DRAFT file generation, and Restore source.

## Verified commands
- `python3 -m unittest -v tests.test_embedded_multipass_service tests.test_csv_logical_framing_20261019`: **10/10 PASS**.
- `./node_modules/.bin/vitest run --reporter=dot`: **815/815 PASS, 107 test files**.
- `npm run build`: TypeScript + Vite build PASS (existing bundle-size notice).
- `./node_modules/.bin/playwright test tests/novice-live-diverse-20261019.spec.ts --workers=1`: 17 live Chromium test cases; verify exact-run result in final PR.

## Outstanding gates
- Juniper/WatchGuard authored samples still PARTIAL; correct firmware/source evidence and independent expected field/value oracles are required before claiming complete support.
- Quoted multiline CSV remains **review-only** for native DRAFT generation, Windows Event XML unsupported (JSON export recommended). Parsing the Zeek prepared data does not validate its native DP import or production event-time semantics.
- `app.parser.xdr.ooo` DNS points to dev-atlas but HTTPS currently serves the pre-existing service's HTTP **401** (no Parser Studio vhost verified). No nginx/authorization/production configuration was changed. Separate owner-approved public-host and security acceptance remains.
- No DP upload, sensor transmission, target receipt or production parser activation were attempted.
