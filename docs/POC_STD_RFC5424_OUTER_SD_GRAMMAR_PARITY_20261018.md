# P0-STD-2/10 — RFC 5424 general Syslog envelope observer grammar parity

## Scope and source

Primary authority: RFC 5424, Sections 6.3.2–6.3.3:
https://www.rfc-editor.org/rfc/rfc5424

- The same SD-PARAM name MAY occur more than once in a single SD-ELEMENT.
- An SD-PARAM escape that is not one of escaped quote, backslash or
  right bracket MUST remain literal rather than acquiring speculative
  CEF/KV escaping or being called malformed RFC5424 input.
- Duplicate SD-ID remains unsupported/malformed. Unescaped closing right
  brackets, unterminated quotation, malformed time/PRI, and unsafe
  physical source controls must not be promoted as valid.
- The outer Syslog TIMESTAMP and HOSTNAME identify the visible
  transmission header. Without independent network/topology/source
  truth they do **not** prove the original event-producing device,
  time-of-detection or relay hop. Even if a nested Syslog-shaped
  MSG contains another hostname, native source attribution remains
  UNSCORABLE: the parser preserves it in MSG without assigning it as
  a second trusted hostname.

The work is isolated on an independent branch rooted at the verified
source-only cross-family Draft PR #68 HEAD
90e73aca5ed417d8c13484e70b084c3f7b1d29f9.
It does not modify Draft PR #68, existing product HEAD da94aa9,
main, intentional Frontend/Backend dirty worktrees, Native Stellar/
Fluentd, DP, sensors, credentials, release, production or deployment.

## Frozen independent oracle before any candidate changes

- generator: scripts/poc/freezeStdRfc5424OuterObserverParity.py
- case file: scripts/poc/standardRfc5424OuterObserverParity.pinned.json
- SHA256: acc3e484221c9edb48c3952d3c4b7e023c4ecae86433974f80110ea900dee4db
- 14 independently authored standards-derived **synthetic** source texts:
  8 narrowly valid, 6 malformed.
- The expected original Syslog field names/values, original total SHA
  and UTF-8 bytes, Structured Data starting/ending byte offsets,
  message bytes and explicit undecidable origin provenance are fixed
  before candidate execution; never derived from Parser Studio output.

Controls include repeated SD-PARAMs, unknown escapes with multibyte
UTF-8 text, defined escape sequences, adjacent SD elements, NILVALUE,
empty param, legal SD names, nested source-looking MSG and negative
duplicate SD-ID, unescaped bracket, invalid quotes, calendar/PRI cases.
These are **not manufacturer publisher wire captures**, native
semantic field values or real relay-topology evidence.

## RED -> GREEN change

On the unchanged PR #68, new focused frozen test:
**2 failed / 13 passed**. The existing independent byte SD observer
and RFC5424 browser scanner treated the two standard-valid inputs as
syntactically valid, while the general Syslog envelope source observer
incorrectly rejected repeated SD-PARAM name and literal unknown escape.

The source observer implementation in
src/poc/generalSyslogEnvelopeSpans.ts was minimally corrected in-place.
It now preserves the full original SD lexical wire bytes in one
structured_data_raw source field while accepting repeated parameter
names and retaining undefined escape bytes unchanged. It does NOT
decode each parameter or assign vendor semantics, and it still
rejects duplicate SD-IDs and the malformed controls.

Prior synthetic tests that incorrectly expected those valid RFC cases
to be rejected were revised to assert standard-permitted source
preservation, no decoded standalone parameter claims, and no native
auto-promotion. This is standards-level source grammar compatibility,
not a vendor-specific workaround.

### Second-stage source arbitration remains conservative

The independently pinned historical malformed input replay detected a
real safety regression on the first patch: 55 prior Junos-related
mutation examples with repeated SD-PARAM names became REVIEW_ONLY
instead of the preceding ABSTAIN_UNSAFE, despite no independent
producer semantic contract. This raised the fixed historical safety
counter from 197 to 252 (both old/new in the earlier replay), which
is **not acceptable** and was not papered over by updating fixture
denominators or weakening historical assertions.

Root correction: while the general envelope observer now properly
accepts *RFC-valid syntax*, it counts repeated SD-PARAM occurrences in
the same original SD-ELEMENT. That generic occurrence count is carried
as an optional source-evidence diagnostic, NOT a new parsed value.
The existing layered source arbitrator inspects this diagnostic and
requires ABSTAIN_UNSAFE with a specific producer-ownership reason
when repeated SD-PARAM names make unique value ownership unverified.
It never overwrites source occurrences or assumes CEF/KV/vendor
semantics. A source-stage abstention does not claim invalid RFC syntax.

Focused source grammar/byte and layered arbitration tests now PASS
49/49. One targeted SHA-pinned history replay after this correction:
1,361 originals, 2,892 invalid mutations, old/new REVIEW_ONLY
**197/197**, independent prior 50, zero source byte drift, zero
result changes, no new unsafe promotion. The immutable baseline was
preserved rather than relabeled as new accuracy.


## Evidence limits, regression and remaining work

- 14/14 frozen synthetic source cases, including original source field
  byte offsets and independent browser/byte observer parity.
- Focused source grammar and layered arbitration tests: 49/49 PASS.
- Whole Vitest, TypeScript/Vite build, original historical safety and
  exact-HEAD GitHub Actions CI are separately required and recorded
  from actual execution before closure.
- Historical 1,361 originals + 2,892 invalid mutations (197 retained
  REVIEW_ONLY), plus previously independent 50 source examples
  remain safety replay only, NOT new manufacturer accuracy gains.
- Genuine relay hop mapping, publisher-original root device hostname
  and timestamp, outer-to-inner clock provenance, RFC5425 TLS
  records, heterogeneous firmware and Native compatibility remain
  NOT VERIFIED / REVIEW_ONLY / UNSCORABLE.

No product merge/deployment is authorized.

## Reproduce

    python3 scripts/poc/freezeStdRfc5424OuterObserverParity.py
    npx --no-install vitest run src/poc/standardRfc5424OuterObserverParity.test.ts src/poc/generalSyslogEnvelopeSpans.test.ts
    npm test
    npm run build
    npx --no-install tsx scripts/poc/runIndependentLogfmtSafetyReplay.ts
    git diff --check
