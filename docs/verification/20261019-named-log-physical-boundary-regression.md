# Preserve named log input physical boundaries and historic browser versions

Date: 2026-10-19. Candidate branch:
fix/named-log-transport-boundary-20261019 based on committed, CI-qualified
ef0f81d1ab0a9677eb9fcc703ca96d11b53a0f0d (Draft PR #104).

## Bug and generic fix

Auto Parser lets users paste or upload separate log types from the same
product. Before this fix, assembleNamedLogs() inserted a new LF between
every nonempty group, even when one group already ended in LF or the following
group began with LF. A user could supply perfectly valid original
LF-delimited container records, yet the newly invented blank physical line
would invalidate the downstream framing contract.

Frozen authored, same-byte source examples, not manufacturer/device originals:

| Two separately named groups | Before fix | After fix |
| --- | --- | --- |
| CRI stdout P/F message, stderr standalone F | 1 RAW_ONLY invalid whole container | 2 PARTIAL original logical events |
| Docker JSON-file stdout, stderr lines | 1 RAW_ONLY invalid whole container | 2 PARTIAL original logical events |
| Trailing-LF JSON Threat/User/Asset | Fabricated empty separator | Exactly 3 source events, reviewed conditional DRAFT downloads |
| CRI P in one named group, F in the next | Misframed / unassigned | One source event crosses group boundary, correctly blocks unqualified export |

The new common join algorithm adds one LF only if neither adjacent sample
already supplies one. It never trims or edits a byte belonging to a named
sample; exact source byte spans remain attached to each group. Intentional
empty lines remain untouched. No manufacturer-specific parser rule was added.

CRI/Docker source results stay PARTIAL, never artificially SOURCE_PARSED or
native-/Stellar-verified. A logical record spanning two declared type groups
remains unassigned with a visible warning, not coerced into either type.

## Browser-local version backwards compatibility

Prior Parser Studio versions could save named groups after adding redundant
LF separators. Existing user-saved Local Versions store a SHA-256 checksum over
the full source, labels, timestamps, ordered group inputs and draft settings.

- A genuinely checksum-valid snapshot created by that older assembly is still
  readable; exactly the prior assembly algorithm is recognized during
  verification only, not for new saves.
- When explicitly restoring such a version, original group names and raw
  samples remain exact. The working copy drops only the previously
  application-inserted LF characters, not source-provided delimiters.
- The historical, checksum-verified snapshot itself is NOT changed.
  Local Versions displays the migration explicitly and asks the user to
  re-analyze before generating files.
- A forged/tampered or inconsistent snapshot is still rejected, and newly
  created versions cannot use the legacy delimiter assembly.

## Regressions and evidence

- New deterministic regression tests initially RED (4 failures), then GREEN
  on 5 physical-boundary cases. Existing named input/history tests remain
  GREEN. Authentic legacy-checksum regression independently RED, then GREEN.
- Actual isolated Playwright CLI/Chromium with real Python Multi-Pass and
  offline authoring backend: CRI/Docker two-event source, spanning-event
  abstention and JSON conditional parser download 4/4 PASS.
- Separate real IndexedDB / browser reload migration test 1/1 PASS,
  confirming verified legacy group-label restore without altering original
  group samples or stored revision.
- Exact-HEAD quality workflow now also requires these five browser scenarios,
  in addition to the ten previously qualified named/routing scenarios,
  with no skipped tests.

The public development site https://app.parser.xdr.ooo/ still runs the
previous owner-authorized f789736 build. This Draft fix does not merge,
deploy, access DP, send to a sensor, alter Nginx/TLS/authentication or claim
physical manufacturer/target semantic verification. Owner's separately
approved release/deploy gate remains required for future installation.
