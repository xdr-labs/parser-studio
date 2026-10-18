# P0-STD-80 — RFC5424 MSG-ANY/MSG-UTF8 Under RFC6587 Octet Counting

## Authority, formats and scope

- RFC 5424 §6.4 permits otherwise discouraged control octets in the MSG region and defines MSG-ANY (no leading BOM) and MSG-UTF8 (UTF-8 BOM prefix). Header and structured-data grammars have different restrictions.
- RFC 6587 §3.4.1 uses a strict ASCII decimal **octet** length prefix followed by a space and exactly that number of message bytes. This boundary supports embedded LF/CR inside a single counted message. Under §3.4.2 non-transparent framing, embedded LF may instead split messages, so no ambiguous cross-line completion is allowed.
- IETF authoritative references: https://www.rfc-editor.org/rfc/rfc5424.html and https://www.rfc-editor.org/rfc/rfc6587.html .
- This source-only PoC starts from Draft PR #79 exact HEAD 0be503d485b8bd235c194d38684d003da7ef29b5, not product/main. It does not certify native Fluentd, proprietary Stellar, true device wire, or complete security event semantics.

## Independently observed shared grammar mismatch

The previously qualified RFC6587 stream splitter correctly counted bytes for messages containing a newline, but BOTH existing parseSyslogEnvelope source and parseRfc5424Subset browser scanner rejected the message again when inspecting the record. Consequently physically framed valid messages could be misreported as invalid, even though RFC5424 MSG allows those bytes.

Root correction is **context dependent**, not a vendor-specific regex:
1. Existing source and browser parsers accept an explicit RFC6587_OCTET_COUNTING framing interpretation for control octets within RFC5424 MSG only. The previous unframed/default safety policy remains: newline and NUL are refused, not guessed to be safe.
2. The existing RFC5424 header/SD scanner still checks the header and SD grammar, and the source parser does not fall back to RFC3164/PRI-only when a counted message with control characters fails its RFC5424 grammar.
3. The existing RFC6587 stream splitter now rejects unpaired UTF-16 surrogates before TextEncoder can silently replace source code units, preserving byte fidelity.
4. The new src/poc/standardCountedRfc5424MsgSource.ts observer reuses the bounded parsers and RFC6587 splitter. It returns only REVIEW_ONLY source lexeme/absolute original UTF-8 half-open byte intervals, or ABSTAIN_UNSAFE for any malformed framing, inconsistent source bytes or mismatched source/browser interpretation. Empty-but-present and absent MSG remain distinct; a BOM-prefixed message is kept as original bytes and decoded only for lexical review.
5. The observer requires original input to reconstruct the **exact** canonical counted prefix and every physical record byte, and refuses to expose partial claims if any event fails. No field, device identity, timestamp or native output can be promoted based only on lexical matches.

## Frozen oracle, RED → GREEN and acceptance boundary

- Independently authored, SHA-pinned fixture scripts/poc/standardCountedRfc5424MsgSource.pinned.json: SHA256 **c43c7b0f604777f12ce5491206ec0295e3975310e44f1042c6b373fb27011852**.
- 22 synthetic standards-derived cases: 11 valid octet-counted streams, 11 invalid/unsupported cases; 13 independently authored record boundaries and MSG raw spans.
- Positive coverage includes LF, CRLF, bare CR, multiple control line endings, literal NUL, UTF-8 BOM and multibyte UTF-8, RFC5424 structured data, MSG present-but-empty vs absent, and multiple concatenated counted records.
- Negative controls include unframed embedded newline, non-transparent LF ambiguity, off-by-one count, leading zero, extra junk, malformed RFC5424 header and SD newlines, unclosed SD, unsupported version, invalid PRI and an additional unpaired surrogate safety test.
- On the unchanged predecessor, nine valid counted-message tests failed and a malformed surrogate was silently byte-normalized. After the generic context-aware correction, related five focused files **119/119 PASS**.
- Whole Vitest, TypeScript/Vite, historical safety replay and exact-head GitHub CI are separately required. Do not infer their status from the focused result.
- Previous 1,361 originals, 2,892 mutated invalids with 197 REVIEW_ONLY, and previously independent originals are **historical safety only**, never fresh manufacturer extraction accuracy.
- This source-only stage can represent only well-formed UTF-8 transport bytes that can round-trip to a JS string; RFC5424 permits non-UTF8 MSG-ANY octets, which this candidate deliberately leaves UNSCORABLE/ABSTAIN rather than manufacturing decoded text. Transport TLS peer origin, upstream relay mutability and native parser fidelity remain NOT VERIFIED.

## Reproduce

~~~sh
python3 scripts/poc/freezeStdCountedRfc5424MsgSource.py
sha256sum scripts/poc/standardCountedRfc5424MsgSource.pinned.json
npx --no-install vitest run src/poc/standardCountedRfc5424MsgSource.test.ts src/syslogEnvelope.poc.test.ts src/rfc5424Nilvalue.poc.test.ts src/rfc6587Stream.poc.test.ts src/rfc6587Framing.poc.test.ts
npm test
npm run build
npx --no-install tsx scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
npx --no-install tsx scripts/poc/auditHistoricalMalformedReviewBounds.ts
npx --no-install tsx scripts/poc/runIndependentNonJsonSafetyReplay.ts
git diff --check
~~~

No changes to the product, main, native adapters, DP/sensors, credentials, production, release or deployment. All fixes stay on an isolated Draft PR pending separate owner integration/acceptance gates.
