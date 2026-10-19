# Standard-library Python test sender: prevent repeated mutation of generated field values

Date: 2026-10-19. Follow-up to CI regression on Draft PR #105 at
92ee5f3e2bf4dfcb468c275e32119df38173c8f1.

## Failure

The exact-HEAD GitHub Actions #39242221848 failed in the ordinary Chromium
browser scenarios, not the feature-specific 15-case gate. The existing
downloaded Python test sender UDP scenario received original src_ip
192.0.2.10 where the contract requires a changed documentation-network
IPv4 address. This failure was reproduced deterministically on the product
source with two controlled successive random draws.

Root cause: the previously generated Python script mutated a named source
field (src_ip) to a safe random value, then ran a generic IPv4 substitution
over the already generated result. The second independent draw could
recreate the original input value, defeating the intended transformation.
The same failure existed in JSON, KV and positional CSV code paths. Random
failure was infrequent, so retrying the old CI would not prove correctness.

## Root-cause fix

The stdlib-only Python template now mutates any one source field at most
once. Named source schema values take priority over fallback inline IP/email
recognition; generic substitutions run only on original, otherwise unchanged
segments. KV lexical quoting, field order, unknown text and CSV escaping
remain intact. No change to the 1-event/second rate, explicit YES approval,
loopback test isolation, recipient prompt or no-eager-network requirement.

This correction is vendor-independent and does not change emitted protocol
framing, public hosted Parser Studio or any real sensor/DP target.

## Actual RED/GREEN evidence

- Single-pass IP mutation unit: JSON/KV/CSV three deterministic subcases,
  all RED before correction because second mocked choice produced the
  original IPv4; all GREEN after correction.
- All Python stdlib-only grammar tests: 8/8 PASS.
- Playwright CLI Chromium with a pinned offline HTTP backend, genuine
  downloaded Python sender and isolated real localhost UDP/TCP receiver:
  2/2 PASS. The original failing UDP test now receives three changed IPs,
  timestamp/current identifier mutations and one event per second.
- Source failure log:
  /tmp/parser-sender-double-mutation-RED-20261019.log
- Fixed unit log:
  /tmp/parser-sender-double-mutation-GREEN-20261019.log
- Fixed browser log:
  /tmp/parser-sender-regression-browser-fixed-20261019.log

Exact-head CI after this corrective commit is required before marking
Draft #105 complete. All intentionally dirty worktrees, the public
app.parser.xdr.ooo pinned static build, Exporter, main, DP and live sensors
are unchanged.
