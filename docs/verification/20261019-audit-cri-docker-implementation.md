# Linux Audit serial grouping, CRI P/F and Docker json-file source framing

Status: isolated development candidate, 2026-10-19. Integration base:
440183d5856cde630da7d647957ed4a64a91e0e0 (unmerged Draft PR #101).
Source worktree: feat/poc-followup-framing-20261019 on dev-atlas.

## What changed / what did not

The common source_container_stream.py entrypoint now recognizes three
additional *original transport/container grammars* before falling back to
single-line source parsing. No manufacturer-specific regex was introduced;
the rules are protocol framing properties, not message semantics.

- **Linux Audit**: A strict type/epoch/serial signature groups only
  *contiguous records* with identical node, timestamp and serial. Interleaved
  serials remain independently accounted for; event lines are never reordered
  or artificially spanned across other events. Record type, literal body
  and grouped event serial are exposed with exact field-value UTF-8 offsets.
  Unsafe/malformed records fail closed.
- **Kubernetes CRI**: Strict RFC3339Nano timestamp, stdout/stderr, P/F tag and
  LF line delimiters. Consecutive same-stream P records plus their F record
  form one logical source event. Standalone F is one event. Interleaved
  streams, interrupted partial chains, missing final newline, bad timestamp,
  oversized group and malformed tagging abstain. Partial fragments stay
  separate in the source tree; the code does not fabricate a contiguous
  byte range for an invented merged payload.
- **Docker JSON-file**: An original JSONL stream with log, stream and time
  source fields must meet the strict source schema, date and record boundaries.
  Missing metadata, invalid JSON, duplicate keys or unexpected stream values
  fail closed. Original JSON lexer field/value spans and Unicode remain intact.
- No native compiler, transport encoder, file exporter or Stellar loader was
  added. Each structurally extracted original container carries
  FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER and stays **PARTIAL**.
  Invalid streams remain RAW_ONLY. Native/target verification flags stay false.

## Exact baseline / independent regressions

See 20261019-audit-cri-docker-before-after.json for the same 11 authored
synthetic source SHA256 inputs on the old and new engine, event accounting and
statuses. This is NOT physical vendor/device original performance.

| Fixture | Previous 440183d | Candidate | Why |
| --- | --- | --- | --- |
| Audit two records, one serial | 2 SOURCE_PARSED | 1 PARTIAL | Correct logical grouping |
| Audit serial 12 then 13 | 3 SOURCE_PARSED | 2 PARTIAL | Distinct serial groups |
| Interleaved 12,13,12 | 3 SOURCE_PARSED | 3 PARTIAL | Never reorder overlapping source |
| CRI P + F | 2 RAW_ONLY | 1 PARTIAL | Partial/final structure recognized |
| CRI P+F plus stderr | 3 RAW_ONLY | 2 PARTIAL | Independent stream records |
| CRI invalid/truncated | RAW_ONLY | RAW_ONLY | Abstain |
| Docker two JSON-file rows | 2 SOURCE_PARSED | 2 PARTIAL | Container no longer falsely claimed native |
| Docker missing time | SOURCE_PARSED | RAW_ONLY | Invalid container is not a complete event |
| Ordinary JSON and KV | SOURCE_PARSED | SOURCE_PARSED | Unrelated source unchanged |

RED tests exposed the above, then GREEN after adding strict common source
framing and explicit nested source_segments for dictionary/redaction contract.
Focused Python 8/8 PASS, complete date-scoped Python 37/37 PASS, and actual
isolated local Vite + real Python Multi-Pass API + Playwright Chromium 4/4 PASS
for Audit, CRI, Docker and malformed partial. Three earlier CI failures for
duplicate KV, wrapped pfSense and OPNsense were reproduced against actual
pinned HTTP authoring backend: **3/3 PASS** after updating test expectations to
honor the source-only compiler-block guidance. Earlier 21-domain audit, 28
protocol cases and 100 synthetic browser cases are not rescored as new blind
benchmarks.

## Compiler gate

The current backend authoring capability provides a bounded reviewed
strictMixedSingleLineFamilies vocabulary and conditionalEventProfiles,
but no original Linux audit, CRI, Docker JSON-file, W3C/Zeek declared-schema,
RFC6587/7464, GELF or journal stream compiler contract. Native Ruby/CONF
import or Stellar DP compatibility for these wrappers is NOT VERIFIED.
The correct UX is to review source fields, retain residuals and offer a
manual supported export or ChatGPT Assisted correction after redaction,
never to silently strip wrappers or synthesize a classifier.

Exact-HEAD CI and review remain required. Do not merge Draft PR #101,
touch protected dirty worktrees, or deploy to the public domain. The live
https://app.parser.xdr.ooo/ remains on owner-approved SHA f789736 pending a
separate instruction.
