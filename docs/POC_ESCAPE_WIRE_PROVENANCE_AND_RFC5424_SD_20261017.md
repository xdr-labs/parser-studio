# Wire-Format Escape Provenance Gate and RFC5424 SD-PARAM Reference PoC (2026-10-17)

**Disposition: isolated evidence-only PoC. NOT product parser code, vendor semantic certification, DP test or native parser qualification.** Stacked on Draft PR #41 base HEAD fa51ca0b7f799c3b629db49ca5f96eb662d6ec4b. Completed #29-#41 studies are not repeated as new field-accuracy work. Original worktrees, private source originals, product HEAD da94aa9177c6b652eee47768efb98a9d47df8c5e, main, DP, sensors, credentials, deployments and merges are untouched.

## New isolated features

1. **RFC5424 6.3 Structured Data byte-escape candidate:** src/poc/rfc5424SdByteEscapes.ts. Limited to 16 KiB full input, 32 SD elements, 256 parameters, 8 KiB per raw value. Preserves half-open original UTF-8 positions, keeps the SD-PARAM value separate from MSG, native FGT KV and CEF extensions. Decodes only the RFC-specified escaped quote, backslash and right bracket; unknown backslash sequences remain unchanged as the standard explicitly requires. Repeated SD-PARAM names are kept ordered, repeated SD-IDs rejected. Unparseable, oversized, invalid-UTF8 and non-RFC5424 structures fail closed.
2. **Producer/configuration/provenance gate:** src/poc/vendorEscapeProvenanceGate.ts. Distinguishes FortiGate FGT/CEF, FortiAnalyzer FGT/RFC5424, SonicOS Default/Enhanced/CEF and Sophos Standard/Legacy. Checks original octet hash, lossless UTF-8, declared profile and observed wire shape, plus independently SHA-bound device configuration and semantic expected artifacts when available. Filenames, user-entered versions, documents and upstream test fixtures do NOT establish true device identity. Even a complete *claimed* capture+configuration+expected chain is DEVICE_EVIDENCE_EXTERNAL_REVIEW_ONLY, because file hashes do not attest who actually generated data. Every result has manufacturerSemantics=NOT_CERTIFIED, nativeTarget=NOT_VERIFIED, canDecodeVendorEscapes=false and canAutoPromote=false.
3. **Version-sensitive evidence annotation, NOT a decoder:** Fortinet's FortiAnalyzer advisory says syslog forwarding began adding escapes at 7.2.6. For FortiAnalyzer 7.2.x >=7.2.6 only, risk is labeled FORTIANALYZER_7_2_6_ESCAPE_CHANGE; this never implies a particular source fixture came from FortiAnalyzer or that the exact decoded value is proven. CEF mapping is not imported into native FGT, SonicWall, Sophos, RFC5424 MSG, or unrelated vendor streams.
4. **New evidence-policy regression only:** scripts/poc/runVendorEscapeProvenanceAudit.ts. Reuses protected pinned source corpora to measure failure to *certify* unqualified data, not to repackage prior field value/byte-span matches as new unseen results.

## Frozen provenance audit (all manufacturer semantics remain NOT_CERTIFIED)

| Category | Distinct originals checked | Fixture-only rejected as device proof | Wire format conflict |
| --- | ---: | ---: | ---: |
| Previously pinned Fortinet | 7 | 7 | 0 |
| Previously pinned SonicWall | 178 | 178 | 0 |
| Additional Fortinet | 1,002 | 1,002 | 0 |
| Additional SonicWall | 61 | 61 | 0 |
| Sophos | 270 (271 physical, 1 source duplicate) | 269 | 1 |
| **Total** | **1,518 distinct** | **1,517** | **1** |

This is not a newly unseen corpus. The one mismatched Sophos source remains WIRE_SHAPE_CONFLICT; no format is inferred. Two formerly ambiguous SonicWall originals and 120 physically unscorable Sophos originals have NOT been promoted to exact. The 1,397 events and 21,723 original field/source/value/byte-span triples verified by PR #41 are a *separate and narrower source-only* result, not proof of device escape behavior.

For the new policy only, pinned 571 + 790 = 1,361 previously frozen foreign originals and 2,892 prior invalid mutations were replayed; **0 manufacturer auto-promotions**. The 600 Sophos invalid mutations with general KV syntax matches still have no device provenance/semantic proof. This negative gate is not a new field-accuracy score.

A future manufacturer proof requires an exact original captured packet with SHA, device producer/model/firmware with independent output-mode configuration tied to that packet, and a separately validated expected semantic output for that same source and wire mode. An upstream integration test, device name string in the log, or manufacturer documentation alone is insufficient. No customer or production system was contacted.

## Primary references and boundaries (checked 2026-10-17)

- **IETF RFC 5424, sections 6.3.1-6.3.5:** https://www.rfc-editor.org/rfc/rfc5424.html . Requires quote, backslash and right bracket escaping in SD-PARAM only; other backslash sequences must remain intact; allows repeated parameter names and adjacent structured-data elements; forbids duplicate SD-IDs. Standards-derived synthetic test cases are not a real manufacturer wire capture.
- **FortiAnalyzer version 7.2.x vendor advisory, updated April 24 2026:** https://community.fortinet.com/fortianalyzer-6/troubleshooting-tip-fortianalyzer-log-forwarding-issue-with-syslog-format-causing-parsing-errors-216136 . Describes additional backslash escape changes since 7.2.6 and fgt/rfc-5424 forwarding configurations. The displayed syslog.msg search/query example does **not** provide an authenticated original packet + device configuration and independently decoded expected output.
- **FortiOS 7.2 CEF extension mapping:** https://docs.fortinet.com/document/fortigate/7.2.0/fortios-log-message-reference/998820/fortios-to-cef-log-field-mapping-guidelines . Describes quotes removal and CEF extension escapes, NOT a universal native FGT/KV rule.
- **FortiOS 7.2.8 raw traffic log example:** https://docs.fortinet.com/document/fortigate/7.2.8/fortios-log-message-reference/357866/log-message-fields . Demonstrates a quoted KV format but not exact unknown escape semantics for all firmware.
- **SonicOS 7.1 syslog configuration:** https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-device_log/Content/Logs_Syslog/logs-syslog-settings.htm . Default, Enhanced and ArcSight CEF are distinct selectable configurable outputs. No pinned escaped-value+version+wire output contract for our source corpus.
- **Sophos Firewall 20.0 syslog configuration:** https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/SystemServices/LogSettings/SyslogServerAdd/ . Distinguishes Standard syslog from Device Standard Legacy. No independent escaped-value semantics tied to actual observed physical device versions.

## Focused reproduction

- Vitest: src/poc/rfc5424SdByteEscapes.test.ts and src/poc/vendorEscapeProvenanceGate.test.ts
- Independent private original/provenance safety: node_modules/.bin/vite-node scripts/poc/runVendorEscapeProvenanceAudit.ts
- Repository gates: npm run typecheck ; npm test ; npm run build
- Exact-head GitHub Actions: usual CI tests/build/Chromium/localhost integration. GitHub CI does NOT have private source artifacts, so cannot claim real manufacturer verification.

The new RFC test values are *normative standards-derived synthetic boundary probes*, not independently captured FortiGate/SonicWall/Sophos wire logs. Only aggregate counts, hashes and documented publicly available references are committed; raw originals/expected private values remain on the protected development host, never uploaded or printed.

## Owner authorization / handoff

Only isolated PoC work is authorized. The product roadmap remains separate: R1 Juniper assisted residual 5, Defender artifact/compiler contract and Umbrella Proxy 23-column quoted CSV; R2 beginner progress feedback for 100-400-event analyses; R3 owner visual acceptance for Review Fields -> Map Fields -> Create Parser, automatic mapping overrides and mobile readability; R4 same-HEAD CI/provenance/browser/Full User E2E and separate owner release/integration permission. NORM-01..07 completion is not reopened; DP upload/sensor/index live tests remain excluded from product completion. No product/main/DP/sensor/deployment/PR merge changes.
