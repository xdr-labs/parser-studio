# Phase 3 residual audit items G-06, G-08, G-10..G-13 (2026-11-23)

Definitions: docs/verification/20261122-phase3-independent-audit2-b117e05-88c0768.md. Priority: wrong FULL,
lost data, wrong official mapping.

| Id | Effect | Decision | Change | Reproduction test |
|---|---|---|---|---|
| G-11 | Wrong FULL: `a=1&b=2&c=3` FULL with one field | Fixed (guard). Inside one token a key behind `&` is a pair, unless a `?` earlier in the value opened a URL query (`url=/a?x=1&y=2` stays one value). The event is PARTIAL instead of FULL; the pairs are not yet read as fields. | `src/grammar/parseStatus.ts` (`unquotedValueEnd`), generated Ruby (`grammar-core.generated.rb.tpl`, ts2rb), `runtime/multipass/source_kv.py` | `src/grammar/ampersandPairGuard20261123.test.ts`, `tests/test_kv_ampersand_pair_unread_20261123.py` |
| G-13 | Wrong official mapping: ICMP pseudo-ports approved as srcport/dstport when the protocol is written `protocol.name`, `flow.l4.proto`, `ip_protocol`, `l4_proto` or ECS `network.transport`; lower mapping rate: a TCP protocol object with `flags` kept the ports in review | Fixed. Protocol evidence is read by the path of each scalar: a protocol-named segment (or ECS `network.transport`) makes the scalars at or below it evidence, except `flags`, `tcp_flags`, `flag`, `state`, `direction`; only a protocol object or the ECS network object is descended into (another object is another family of the record); a bare `transport=` stays a port (FortiGate); ECS `network.protocol` is the application protocol and is not evidence (re-audit A1). | `src/guided/normalizationCandidates.ts` | `src/guided/protocolEvidenceNames20261123.test.ts`, 17 cases in `scripts/verification/mcv2-candidate-independent-oracle.mjs` |
| G-10 | Reported as parity: the Python preview SOURCE_PARSED for a comma list of 101 pairs or a repeated key while the TS/RB key=value grammar declines | Not a defect (re-audit A2): the Python comma_kv / delimited_kv frames are the counterpart of the Generic Structural comma_kv / delimited_kv modes of src/genericStructural.ts (no pair limit, repeated keys kept as a list), which the generated Ruby follows. A first fix that declined such lists created a divergence and was reverted. | - | tests/test_comma_kv_limits_20261123.py (parity: 101 pairs parsed, every value kept) |
| G-06 | Ambiguous reading: one token `opts=rw,uid=1000,gid=1000` is read as three pairs (values preserved, split) | Open by design: one token cannot say which reading is meant; no value is lost. | - | - |
| G-08 | Lower mapping rate: a host beside a bare upper-case method word, or inside an object, stays a review proposal | Open: conservative (no wrong mapping); the user approves it in Map Fields. | - | - |
| G-12 | Parity (P3): a quoted list value ending in a backslash is PARTIAL in TS/RB, SOURCE_PARSED in Python | Open: the conservative grade (PARTIAL) is the one the generated parser uses. | - | - |

The G-11 change alters the generated Ruby grammar: template-set digest
09de3c540f0ef12341773c13764414408a1ea4400674a54d123e177198ee1ac5 -> see the final report (owner approval
required; KNOWN_TEMPLATES and approval constants unchanged).

## Independent re-audits (separate agents)

- Re-audit of e1af64d..0bd7b58: A1 MAJOR (ECS network.protocol read as the IP protocol; TCP/UDP ports of ECS
  records fell to review) and A2 MAJOR (G-10 Python limits diverged from the Generic Structural modes) fixed in
  6b40461; A3 (source path kind ignored by the family merge) fixed in 6b40461.
- Re-audit of 0bd7b58..6b40461: no BLOCKER. F2 MAJOR, fail-closed: a JSONata reply that restates a shared
  mapping carries sourcePathKind nested, which the A3 comparison treated as a change, so nothing was applied.
  A mapping without a kind now equals the same mapping marked nested. F3: the family record check now reads a
  literal-key mapping as written. F1 (limit): a record whose only protocol statement is network.protocol
  icmp (no network.transport) gets HIGH ports; correct for ECS, wrong for a vendor that writes the IP
  protocol there.

## Accuracy at 6b40461 (full validation T22, same corpus as T19/T21)

Holdout 102 correct / 0 wrong / 0 lost; golden canonical 148/182, preserve 176/179: unchanged from the
baseline. The per-family vendor-name fix maps the CEF tuple of mixed_envelope_cef_kv in the automatic draft
(unit test), but the browser journey of that golden case does not take that path, so its golden score is
unchanged (2/8).
