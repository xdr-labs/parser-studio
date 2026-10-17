# Declarative ordered Syslog source header: independent publisher PoC (2026-10-17)

## Scope and safety

Source-only new isolated PoC, branched exclusively from prior Draft PR #52 exact HEAD
`492964acf36594be02a6c10f14f43dfa1c90614a`. Implementer
CHATGPT_CHAT on dev-atlas, worktree
`/home/aella/parser-studio-declared-syslog-prefix-poc-20261017`.
No product parser integration, PR merge, main, frontend/backend dirty WIP,
Stellar native, DP, sensors, production, credentials, deployment, or release.

This is a **generic declared-grammar** alternative, not a vendor-name-specific
regex repair. The base qualified Multi-Pass / Generic Structural / bounded
Funnel architecture is preserved. Runtime layout authority is provided
explicitly to a bounded isolated observer. No profile means RAW_ONLY.

## Independent sources frozen before candidate inspection

The manufacturer field **names, order, and selected numeric limits** come
from the authoritative Cisco ISE remote syslog format documentation:

https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_IntrotoSyslogs.html

That document identifies header fields `pri_num`, timestamp, hostname,
`cat_name`, `msg_id`, `total_seg`, and `seg_num`. It specifically
distinguishes `cat_name` from an ordinary RFC5424 `appname` label. The
actual Cisco firmware release/wire mode used to construct a third-party
fixture is not independently verified.

The **six newly selected** Elastic-maintained Cisco ISE publisher fixture
files and six separate author-expected ECS JSON files are SHA-256 pinned from
`elastic/integrations@615252c0910be1b8dc4dbe8f70acabe02ea8757e`.
The upstream Elastic License 2.0 materials are **private evaluation only**;
raw originals and expected values must never be checked into Git or output
in logs. They live in the mode 0700 private state directory
`~/.local/state/parserstudio-declared-syslog-publisher-20261017`, with
mode 0600 files. Git contains **only** the hash/path manifest, the generic
observer, frozen-oracle builder, evaluation script, tests, and report.

The publisher provided expected normalized ECS **values** per original, not
exact raw source byte positions. The evaluator derives positions
deterministically from independent author expected values and raw received
bytes **before** the candidate is evaluated, and freezes v1 immutable
source tuples. The source **field names** are taken separately from Cisco's
manufacturer-authored format contract, not from our parser or from a
guess about the publisher's normalized field names.

Oracle: `declared-cisco-source-oracle.v1.json` private SHA-256
`64b4ababf7c701c8226575dde2e4e4690cb1c6c8f69c6981bd47d9a2b41a0e2f`.

This test is not proof of independently manufacturer-authored byte locations,
a full-event field oracle, original manufacturer device captures, every
firmware version, or production Stellar-native parsing.

## Frozen comparable partial-source results

| Measure | PR #52 source-envelope baseline | New declared-schema observer |
| --- | ---: | ---: |
| Independently published original physical events | 69 | 69 |
| Partially source-scorable original events | 41 | 41 |
| UNSCORABLE / abstained events | 28 | 28 |
| Publisher-valued / manufacturer-name-and-order-declared / evaluator-byte-located tuples | 245 | 245 |
| Exact name/value/original UTF-8 source-span match | 81 | **245 (+164)** |
| False negatives in frozen partial denominator | 164 | **0** |
| Conflicting claims on these same scored names | 0 | 0 |
| Raw byte loss/drift | 0 | 0 |
| Unqualified new source claims | 0 | 0 |
| Auto/native promotions | 0 | 0 |
| Max source branch attempts | Existing | 3 |
| Max source recursion depth | Existing | 1 |

**This is a scoped partial-source improvement, not a universal parser success
rate or complete-event precision/recall.** The complete number of original
source fields is unknown; unasserted field false positives cannot be
numerically scored. Source offsets are independently computed by the
reference builder from the raw source and externally supplied expected values,
but were not themselves published as expected offsets.

The **entire same publisher cohort** receives the same independently
declared header profile regardless of per-event expected truth. Of 69 source
events, the candidate emits review-only field proposals for 41, abstains
for 28 with zero fields. No source oracle is used to decide which records
receive a profile. Prior PR #53's initial oracle-guided dispatch audit
is explicitly avoided.

## Generic structural algorithm

`inspectDeclaredSourceHeader` accepts an external ordered
`DeclaredSourceHeaderProfile`, using bounded field definitions with
`opaque_token` or `unsigned_integer` syntax, min/max where independently
specified, and explicit canonical source field labels. Implementation:

1. Reuse the existing qualified bounded RFC3164 source envelope observer.
2. Require an explicit, unique, bounded, non-colliding declared schema
   (max 8 header fields), no hidden manufacturer matcher.
3. Parse the declared leading fields in order, with strict bounded
   token lengths (128 UTF-16 units), whitespace, numeric ranges and
   untouched residual message.
4. Verify all source fields against original UTF-8 byte slices,
   ordered non-overlapping offsets, and bounded raw input length.
5. If the profile, frame, boundaries or payload are ambiguous, return
   ABSTAIN_UNSAFE or RAW_ONLY with **no fields**, never a false complete.
6. Keep remaining payload un-decoded; REVIEW_ONLY, no source
   auto-promotion, semantic/normative/native certification.

The rule applies generically to any independently supplied ordered
source schema. The **four declared field names** here happen to come from
Cisco documentation, but no `Cisco`, `ISE`, model, or firmware condition is
included in the parser algorithm. Future user-supplied field definitions
are planned separately in roadmap Draft PR #51; this PoC does not add
any product UI/API behavior.

## Unresolved negative evidence and other safety gates

- **2** originals contain backslash escapes without manufacturer-authoritative
  decoded-value assertions; no string escape rule is forced.
- **1** original has syntactically empty assignments without independent
  device-authoritative empty-vs-nil-vs-absent meaning; no value inferred.
- Publisher source files do not independently pair device-origin bytes,
  one-hop and multi-hop relay outputs; nested Syslog hop/source identities
  remain UNSCORABLE.
- Historical 1,361 originals + 2,892 generated invalid mutations are
  **SAFETY ONLY**, not new blind manufacturer correctness data. Existing
  197 lexical REVIEW_ONLY cases (171 Sophos-shaped KV; 26 RFC3164
  envelope-only) require independent producer bad-input truth, unchanged.
- Manufacturer-specific firmware escape, complete event FP,
  Stellar field normalization and native Fluentd/DP semantics remain
  **NOT_CERTIFIED / UNSCORABLE / NOT_VERIFIED**.
- Product-specific future work—user-named sample types, 10 diverse samples
  per type, Union Schema, CSV field definition, drag-selected Prefix/Postfix
  and ONE dynamic Stellar parser—remains in separate PR #51 only.

## Reproducibility and acceptance

The private oracle is immutable; all raw/event values remain private.
On dev-atlas in this **isolated** worktree:

```sh
python3 scripts/poc/freezeDeclaredSyslogPublisherOracle.py
npx --no-install tsx scripts/poc/scoreDeclaredSyslogPublisher.ts
npx --no-install tsx scripts/poc/runDeclaredSyslogHistoricalSafety.ts
npx --no-install vitest run src/poc/declaredSyslogHeader.test.ts
npm test
npm run build
git diff --check
```

Only source-specific independent, demonstrable improvements with regression
proof may be pushed as a NEW Draft PR. Exact-head GitHub Actions must also
PASS full Vitest, English-only, TS/Vite, real Chromium user flows,
pinned backend build and actual Chromium↔localhost HTTP integration
before the candidate may be labeled quality-CI verified. Even success
**does not authorize product integration or native deployment**.
