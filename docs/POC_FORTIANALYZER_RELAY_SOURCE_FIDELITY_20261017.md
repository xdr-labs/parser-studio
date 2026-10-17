# FortiAnalyzer Relay-Stage Source Fidelity — Version-Scoped PoC

Date: 2026-10-17. **Isolated evidence-only PoC. No product parser changes, manufacturer escape certification, runtime integration, or source-device attestation.**

## New problem independently verified

PR #41 proved collector-visible source field names, decoded lexical values and exact UTF-8 byte spans for **1,397 independently scorable events / 21,723 source fields** in limited previously frozen cohorts. PR #42 added an evidence-only manufacturer/wire gate. Neither proves that a collector-visible event is byte-for-byte equivalent to the original upstream FortiGate (or another upstream security product) event when a FortiAnalyzer relay is in the path.

Fortinet's official **FortiAnalyzer 7.6.6 CLI Reference / log-forward** explicitly documents transformations that can alter forwarded content. This can invalidate *upstream-device* value accuracy even when the collector's received data is tokenized perfectly.

## Vendor-documented transformations, exact 7.6.6 scope

| Forwarding configuration | Documentation-supported behavior | PoC interpretation |
| --- | --- | --- |
| fwd-server-type cef | Send logs in Common Event Format | REENCODED_CEF, not native FGT |
| fwd-server-type syslog; fwd-syslog-format fgt or rfc-5424 | Different selected syslog formats | A format selector alone does not prove escape decoding semantics |
| fwd-syslog-transparent enable | Forward received syslogs without modifications | TRANSPARENT_CONFIG_UNATTESTED; cannot prove upstream-to-collector equality |
| fwd-syslog-transparent disable | Embed received syslogs inside FortiAnalyzer syslog | FORTIANALYZER_SYSLOG_WRAPPER |
| fwd-syslog-transparent faz-enrich | Add FortiAnalyzer fields at end | FORTIANALYZER_FIELDS_ENRICHED |
| log-masking-status enable | Mask configured log fields | FIELDS_MASKED; original values may be lost |
| log-field-exclusion-status enable | Exclude configured fields | FIELDS_EXCLUDED; fields may be absent |
| fwd-syslog-decode-b64 enable | Base64 decode when forwarding via syslog | ATTACKCONTEXT_BASE64_DECODED |
| fwd-syslog-enrich-cve enable | Add CVE identifiers on syslog forwarding | CVE_FIELD_ENRICHED |
| fwd-log-source-ip local_ip | Use relay IP as source | ORIGIN_IP_REWRITTEN (IP metadata is distinct from message body) |

Authoritative versioned reference: https://docs.fortinet.com/document/fortianalyzer/7.6.6/cli-reference/859805/log-forward

Other exact-version descriptions, context only: https://docs.fortinet.com/document/fortianalyzer/7.4.8/cli-reference/859805/log-forward and https://docs.fortinet.com/document/fortianalyzer/7.6.5/cli-reference/859805/log-forward .

**Version boundary:** This implementation qualifies the availability of these documented options in the 7.6.6 reference only. It DOES NOT infer flags, defaults, actual wire bytes or decoded semantics for 7.2.6, other FortiAnalyzer releases, native FortiGate, SonicWall or Sophos. The separate 7.2.6 escape advisory from PR #42 remains a version-risk observation, not a manufacturer decoder.

## New isolated implementation and safeguards

- src/poc/fortianalyzerRelayFidelityGate.ts is a pure configuration-state classifier. It never reads a device, performs network calls, modifies parser output, or supplies a vendor escape decoder.
- src/poc/fortianalyzerRelayFidelityGate.test.ts exercises every documented transformation, FGT versus CEF and Syslog mode consistency, missing options, version mismatch, untrusted configuration origin, and separation of sender-IP rewriting from payload changes.
- A *claimed* device configuration export is required even for a preliminary mode review. A document, file name or user declaration is not independent evidence. Absent/unknown default settings are **UNKNOWN**, never silently interpreted as benign defaults.
- The output payloadFidelity is one of UNKNOWN, POTENTIALLY_TRANSFORMED, or TRANSPARENT_CONFIG_UNATTESTED. Original upstream source byte equivalence is NOT_PROVEN in all cases. The actual collector-visible input may still be scored independently at its own source stage; never conflate it with earlier upstream stage.
- All decisions require additional independent attestation: originalDeviceByteEquivalence=NOT_PROVEN; vendorEscapeSemantics=NOT_CERTIFIED; nativeTarget=NOT_VERIFIED; canAutoPromote=false. No export, no integration.

## Current independent evidence availability: negative result

A read-only filename/extension metadata census, restricted to private Parser Studio material under ~/.local/state/parserstudio-*, found **19 project-specific directories and 129 files**. There were no directly identifiable PCAP/PCAPNG, device CLI configuration export, or complete upstream/relay twin-capture bundles. Some files are archives; this metadata census does not prove that they contain no capture bytes. It does NOT establish any complete independently verified device producer/version + specific forwarding config + matched upstream and collector packet + independently derived semantic expectation. No real DP, sensor, firewall or FortiAnalyzer was contacted.

**Manufacturer semantics remain NOT_CERTIFIED and unsupported original events remain SOURCE_UNSCORABLE/REVIEW_ONLY.** Avoid promoting source-field correctness into native/Stellar product readiness.

Needed for an eventual independent vendor qualification:
1. Exact source device and forwarding appliance model/firmware; independently exported and redacted forwarding settings, including the specific route and relevant transformation flags.
2. Raw upstream and downstream capture byte SHA-256, source/receiver identity, transport/framing and physical event correlation.
3. Producer-authenticated or separately independently verified decoded expected values for exactly that source and wire mode. Do not infer expected output by running the candidate itself.
4. Field names, values and absolute original UTF-8 byte ranges plus FP, FN, false-complete and raw retention tests, with prior source-ambiguous events excluded.

## Verification and authorization

Focused: node_modules/.bin/vitest run src/poc/fortianalyzerRelayFidelityGate.test.ts src/language-policy.test.ts.
Full: npm run typecheck, npm test, npm run build, exact SHA Draft-PR CI with Chromium and localhost HTTP.

The new tests are **synthetic documented configuration boundary cases**, not actual upstream FortiAnalyzer device captures. PR #29–#42 evidence and frozen protected sources are preserved and not counted again as newly unseen accuracy gains.

Product backlog carry-forward **only** (not implementation authorization): R1 Juniper 5 assisted residuals, Defender Create Parser Files compiler, Umbrella Proxy 23-column quoted CSV; R2 beginner 100–400-event analysis progress feedback; R3 owner visual acceptance of Review Fields → Map Fields → Create Parser and mapping overrides/mobile; R4 same-HEAD full E2E and separate owner release approval. NORM-01..07 remain completed, and live DP/parser upload, sensors and target index readback remain excluded from product-completion criteria.
