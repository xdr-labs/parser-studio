# P0-STD-78 — Generic Source-vs-Relay Syslog Provenance Boundaries

## Authority and compliance scope

RFC 5424 (§6) defines originator-controlled header fields including HOSTNAME and TIMESTAMP. RFC 5425 (§4) explicitly establishes authentication and integrity for the *transport hop* only: the authenticated transport sender need not match the HOSTNAME field in the Syslog message. RFC 6587 framing must be removed and its byte boundaries verified separately before interpreting a single collector-visible record. RFC 3164 timestamps without an independent year/zone and relay clocks cannot establish chronological order.

This isolated source-only PoC follows verified STD-77 Draft PR #77 HEAD 71b19c002b03a3233b3475653dbc1e0e3eddabb1. It does not alter the existing qualified grammar, browser extraction, manufacturer profiles, any native target, production or product branch.

## Specific observed gap and generic mitigation

- Existing nested-relay parser src/genericStructural.ts exposes lexical outer/inner header fields and collector raw; this proves only source text syntax, not true original manufacturer, trusted sender, TLS peer or event time.
- New independent observer src/poc/standardRelayProvenanceReview.ts reuses parseSyslogEnvelope and checks an explicit one-hop original nested Syslog span within the exact collector-visible UTF-8 byte stream. It outputs ordered claimed outer/inner hostname and literal timestamps and optionally compares the embedded original bytes against separate caller-supplied upstream source bytes.
- A byte-for-byte comparison gives a strict, narrow **REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH** outcome; mismatch => REVIEW_ONLY_SOURCE_BYTES_DIFFER, no upstream bytes => REVIEW_ONLY_UNPAIRED, no nested hop => REVIEW_ONLY_NOT_NESTED, malformed/deep/over-bounded/invalid UTF-8 => ABSTAIN_UNSAFE_SOURCE.
- Even matching bytes may be copied, forged, replayed, transformed elsewhere or paired with unauthenticated inputs. Every output retains originalDeviceIdentity=NOT_ATTESTED, transportPeerAuthentication=NOT_VERIFIED, eventClockOrdering=UNSCORABLE, sourceComplete=false, nativeVerified=false and canAutoPromote=false. No direct clock precedence or origin-address inference is performed.
- The implementation avoids vendor-specific regex or per-device escape guesses; it never makes a transport security claim from a message header or fixture alone. Capture identity and TLS peer validation require independent, versioned real packet evidence.

## Independent standards-authored synthetic verification

- Script scripts/poc/freezeStdRelayProvenanceReview.py authored the source strings/expected outcomes prior to implementation. Pinned scripts/poc/standardRelayProvenanceReview.pinned.json SHA256 **d22ba4469494deb3394ececb09a075acc8043cbbac7c843681614bb7b064253a**. Seventeen authored cases cover RFC3164/RFC5424 nesting both ways; paired byte-match and changed/missing source; header-host spoof equivalence; RFC5424 NILVALUE host; source UTF-8 multibyte bytes; reversed claimed timestamps; direct nonnested input; invalid PRI/clock, malformed inner source and depth >1.
- RED: new source observer unimplemented on isolated PR #77 base. GREEN: focused 20/20 test assertions, including invalid byte streams, unexpected framing bytes and byte/source metadata replay.
- Test inputs are **synthetic**, not upstream devices, customer captures, authenticated TLS sessions, or a new vendor accuracy holdout. No full event F1 or source semantic/native promotion.
- Historical prior 1,361 originals + 2,892 invalid mutations including 197 REVIEW_ONLY and previously scored independent material remain *safety-only*, not fresh accuracy denominators. Full repository suites, build and exact-head CI are separate verification gates.

## Remaining evidence and ownership

Genuine manufacturer source-vs-relay attestation still requires matched upstream device raw bytes and collector raw bytes, exact hashes, capture points, transport framing and TLS authenticated peer assertions (when applicable), forwarding appliance/software versions and settings, and independently established expected source field values. Mere matching hostnames or timestamps cannot substitute.

No device, DP, sensor, production service, release or native parser export was contacted or altered. Source-only branch/PR stays DRAFT/UNMERGED until owner accepts broader integration gates.

## Reproduction

~~~sh
python3 scripts/poc/freezeStdRelayProvenanceReview.py
sha256sum scripts/poc/standardRelayProvenanceReview.pinned.json
npx --no-install vitest run src/poc/standardRelayProvenanceReview.test.ts
npm test
npm run build
npx --no-install tsx scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
npx --no-install tsx scripts/poc/auditHistoricalMalformedReviewBounds.ts
npx --no-install tsx scripts/poc/runIndependentNonJsonSafetyReplay.ts
git diff --check
~~~
