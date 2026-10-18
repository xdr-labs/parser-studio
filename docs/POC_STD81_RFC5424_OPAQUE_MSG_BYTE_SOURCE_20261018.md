# P0-STD-81 — Byte-Native RFC6587 Frames and Opaque RFC5424 MSG-ANY

## Normative grounding and explicit limitations

RFC 5424 §6.4 declares MSG-ANY as arbitrary octets not beginning with a UTF-8 BOM, and MSG-UTF8 as BOM followed by a valid UTF-8 string. Other parts of the RFC5424 record (HEADER and STRUCTURED-DATA) have stricter grammars and remain independently validated. RFC 6587 §3.4.1 defines the exact decimal octet-counted record boundary, independent of text line breaks or Unicode code unit counts.

Authoritative sources:
- https://www.rfc-editor.org/rfc/rfc5424.html
- https://www.rfc-editor.org/rfc/rfc6587.html

Original existing defect: the shared source-stage RFC5424 SD byte scanner decoded the **entire input record** as strict UTF-8 before checking ASCII HEADER/SD. Consequently fully framed and otherwise legal non-UTF8 MSG-ANY bytes were denied, although the RFC makes no such encoding guarantee. Re-encoding the message through a JS string would instead fabricate replacement-byte source values.

## Generic source-level correction

1. Add source-byte RFC6587 octet-counted framing to the *existing* src/syslogFraming.ts, with original half-open record byte offsets, bounded decimal token / record size / message count, exact captured record slices, and fail-closed incomplete or malformed streams. The legacy text-oriented stream parser now calls this **same byte grammar** then performs strict UTF-8 decoding for its existing browser string API. No duplicate stream parser or vendor-specific regex is introduced.
2. Rework the existing src/poc/rfc5424SdByteEscapes.ts source audit so the original binary record prefix, version, header tokens and SD are validated **without requiring the entire MSG to be UTF-8**. SD-PARAM values still require valid UTF-8 and RFC escape rules. The whole record is hashed from the original octets; no lossy text reserialization.
3. New source-only src/poc/standardOpaqueRfc5424MsgBytes.ts observer composes qualified RFC6587 framing and the existing RFC5424 SD byte auditor. It retains absolute source intervals, distinguishes absent MSG from zero-byte present MSG, and labels MSG-ANY as opaque. It never emits a fabricated string value for invalid UTF-8 octets.
4. If the message starts with BOM EF BB BF, the observer requires the remainder to decode as valid UTF-8. Malformed/overlong/truncated UTF-8 after BOM must ABSTAIN. If no BOM is present, byte-level MSG-ANY is preserved verbatim without claiming any producer-provided character encoding.
5. A bad frame, bad version/PRI/header/SD, unqualified BOM, or stray tail makes the **entire stream** ABSTAIN and emits zero field claims; otherwise it remains REVIEW_ONLY. Device identity, original vendor meaning, SOURCE_PARSED completeness, native Fluentd/Stellar and deployment remain NOT VERIFIED.

## Independent immutable oracle and measured gates

- scripts/poc/freezeStdOpaqueRfc5424MsgBytes.py manually authored source bytes and independent expected absolute byte intervals, prior to code scoring.
- scripts/poc/standardOpaqueRfc5424MsgBytes.pinned.json SHA256 **60f1234f32bf993aaeab1ff7d09168123cadd6edca63898f33adb3a2780cb902**.
- 24 standards-authored synthetic scenarios: 10 legal / 14 invalid, 11 exact original record/MSG byte claims. Legal cases include invalid UTF-8 bytes without BOM, binary high-bit bytes, NUL and CRLF in MSG, valid Unicode without BOM, valid MSG-UTF8 with BOM, multiple records and SD followed by opaque bytes, and present-empty versus absent MSG.
- Negative controls include invalid BOM-tagged UTF-8, overlong/surrogate/truncated UTF-8 sequences, truncated or short counts, leading zero, extra trailing bytes, invalid PRI, non-ASCII HEADER, non-UTF8 SD, duplicate SD-ID and non-transparent ambiguous framing.
- RED on baseline: five source-byte observer cases rejected legal opaque MSG-ANY. GREEN after generic correction: four focused files **65/65 PASS**; native/vendor source semantics remain unscored.
- Entire Vitest, TypeScript/Vite build, 1,361 historical original / 2,892 historical invalid (197 REVIEW_ONLY) plus previously independent source *safety-only* replays, and exact-HEAD CI require separate result checks before closure. Historical safety is not fresh manufacturer accuracy data.

## Isolation

Source-only Draft PR based on preceding PR #80 exact HEAD 615f1f87e86c456dc9bd3897397a09709b5c1e0e. Do not touch product/main, dirty frontend or backend worktrees, native target adapters, real device traffic, DP, sensors, credentials, production, deploy, release or PR merge. Real publisher wire/native confidence still needs separate source/target evidence and owner authorization.

## Reproduction

~~~sh
python3 scripts/poc/freezeStdOpaqueRfc5424MsgBytes.py
sha256sum scripts/poc/standardOpaqueRfc5424MsgBytes.pinned.json
npx --no-install vitest run src/poc/standardOpaqueRfc5424MsgBytes.test.ts src/poc/standardFramingSdTransfer.test.ts src/rfc6587Stream.poc.test.ts src/rfc5424Nilvalue.poc.test.ts
npm test
npm run build
npx --no-install tsx scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
npx --no-install tsx scripts/poc/auditHistoricalMalformedReviewBounds.ts
npx --no-install tsx scripts/poc/runIndependentNonJsonSafetyReplay.ts
git diff --check
~~~
