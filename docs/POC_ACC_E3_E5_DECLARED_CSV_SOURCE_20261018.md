# ACC-E3/E5 — Independent Headerless CSV Source/Schema Fidelity

## Goal and boundaries

This isolated evidence-only PoC is based on Draft PR #86 exact HEAD
5555caf7f9120b9b2914e794a36f43f9dddb29a2. The existing
independentQuotedCsvSource observer already extracts positional original-byte
cell values, but does not attach an externally declared column order to a
bounded CSV excerpt *without manufacturing a nonexistent original CSV header*.

The new vendor-neutral source observer in
src/poc/accE3E5DeclaredCsvSource.ts requires: a byte buffer and independent
SHA-256 of the entire displayed source; a caller-declared half-open original
CSV byte slice with a second independent SHA-256; ordered out-of-band schema
names and their canonical SHA-256; explicit single displayed-record boundary;
RFC 4180 comma CSV dialect; and explicit schema provenance. It reuses the
qualified source CSV lexer, validates every original UTF-8 byte span, rejects
unsafe/duplicate schema names, malformed CSV, invalid UTF-8 and unsafe
boundaries, and keeps all unreviewed prefix and suffix original bytes.

The source is never alleged to contain a schema header: nameStartByte is
null for every result. Externally asserted field names and lexical source
values are independent trust categories. Numeric, boolean-looking or empty
cells remain untyped source strings: no manufacturer-typed or null semantics
are inferred. Cross-realm byte views are admitted only after byte-type,
SHA-256 and UTF-8 exact-roundtrip checks.

Results are always REVIEW_ONLY_EXTERNAL_CSV_SCHEMA, RAW_ONLY or
ABSTAIN_UNSAFE. The following always remain false: sourceComplete,
canAutoPromote, autoPromoted, independentOracleCertified and nativeVerified.
Manufacturer semantics, real producer identity and transport peer are NOT
CERTIFIED/NOT ATTESTED/NOT VERIFIED. Default Generic Structural, Funnel,
native adapters and product behavior are unchanged.

## New manufacturer-published documentary evidence

1. Fortinet FortiNAC-F 7.6.0, publisher Syslog files page:
   https://docs.fortinet.com/document/fortinac-f/7.6.0/administration-guide/880398/syslog-files
   HTML SHA256 001a7c9dd71301cf372de2bde5568143829b249c9dc744af18f49f1ce3defd7d.
   One 89-byte publisher example, original-display-source SHA256
   08ff77b36096dfce0fff84098c65152bd9dd93f52ae4f6a9c2166f516ad4e471.
   Published seven-column descriptions establish the external order: action,
   alert severity, source IP, source MAC, component ID, rule ID, situation.
   Seven of seven independently frozen names/lexical values/source byte
   intervals agree after explicit source schema association. Normalized
   lowercase names are externally assigned aliases, not original log keys.

2. Palo Alto Networks manufacturer knowledgebase, Syslog Message Format
   Different for Logs Received from Two Firewalls:
   https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClsYCAS
   HTML SHA256 728c12519c54f52153318496c831d0b8eb0d10fede85922cbd6a349146686841.
   The publisher displays original-reporter-format cases with hostname on
   and off, with different Syslog/message prefixes.
   The 446-byte and 430-byte display texts have explicit 63-byte and
   47-byte unreviewed prefixes respectively, then 46 CSV cells each;
   total 92 source positions, including four lexical empty cells.
   Source SHA256:
   1c026bd12c9e69584618c2e55b78b2c29f2119b7d5f20f2294ef498f30e2f65a
   b5094458e853283008df9f243abfb72f0f5be723095a5a030754a9a6735ac00a.
   92 of 92 original-byte positional values agree. These are explicitly
   synthetic ordinal aliases (column_01 etc.), NOT independently certified
   manufacturer semantic field names or firmware-version typed values.

The Python independent documentary Oracle was frozen BEFORE the new
TypeScript source observer. SHA256:
17a28a81ca4af6402067a0407fe05d17d3890c5e6a256b6296642fbadd865da7.

Manufacturer publisher HTML and source/oracle data are private under:
~/.local/state/parserstudio-acc-e3-e5-declared-csv-source-20261018
with restrictive filesystem access; raw examples and expected values are
NOT committed to GitHub. These are publisher-displayed documentary logs,
NOT a device-authenticated original wire PCAP, matched relay transfer,
real captured firmware version, or native Fluentd/Stellar expected output.
The FortiNAC document's 7.6.0 heading is NOT captured-device attestation.

## Before/after and measured scope

- Full publisher display strings in unchanged Generic Structural:
  3/3 declined as unqualified, not falsely accepted.
- Previous qualified independently bounded CSV observer:
  99/99 positional source values/spans already correct but zero
  **externally declared headerless named-source fields**.
- New opt-in declared-schema reviewer:
  99/99 exact source lexical values, original UTF-8 byte spans; 7/7
  publisher-documented externally assigned field labels plus 92/92
  deliberately positional-only aliases.
- Explicit unreviewed source bytes: FortiNAC zero; PAN examples 63 and 47.
- All exact source mappings remain REVIEW_ONLY, zero auto-promotions.
- New manufacturer device-native accuracy denominator: 0 / UNSCORABLE.
  Do not represent 99/99 as physical-device/native F1 or improved complete
  events. Actual upstream wire/relay and independently typed semantic
  accuracy remain unmeasurable from the publisher documentation alone.

## Independent synthetic RED/GREEN safety

The Python preimplementation source oracle generator
scripts/poc/freezeAccE3E5DeclaredCsvOracle.py froze fixture
scripts/poc/accE3E5DeclaredCsvOracle.pinned.json with SHA256:
e86141b4b2ad8da47e9c2a53a770d2068a0e807b73eeaea01640f532014f00bf.

- 37 independent synthetic cases: 13 valid, 24 invalid/unsafe controls;
  42 positive source name/value/original UTF-8 byte claims.
- RED: the new test failed when no source observer existed.
- Initial implementation exposed cross-realm Uint8Array rejection in the
  new boundary; it was corrected without changing shared parser behavior.
- GREEN: 39/39 focused tests, zero false complete/promotion/unsupported
  column-name provenance and zero source-byte span drift.
- Private independently pinned publisher replay:
  3/3 published examples, 99/99 source fields, seven publisher-specified
  externally named fields; all non-device/native and REVIEW_ONLY.

## Reproduction and regression gates

1. Run the Python oracle generator and confirm the frozen fixture SHA256.
2. Run focused source Vitest, private publisher replay, TS typecheck, full
   Vitest, and Vite build.
3. Replay the historical 1,361 original/2,892 invalid source cases and
   prove existing 197 REVIEW_ONLY unchanged (171 Sophos KV, 26 RFC3164).
4. Commit/push the isolated source-only files; create a DRAFT PR and verify
   exact-HEAD Actions web/build/Chromium/localhost HTTP integration.
5. Do not treat a successful source-only reviewer as a manufacturer-native
   accuracy or physical source identity qualification.

Product/main and the protected Frontend 11 / Backend 10 dirty files,
prior Draft PR #83-#86, native Fluentd/Stellar, DP, sensors, deployment
and merges remain outside this authorization. ACC-E1-E5 still require
physical producer/relay wire evidence, firmware/output mode and separately
authored typed semantic oracle before manufacturer accuracy admission.
