# Parser Studio PoC integration & actual novice E2E audit — 2026-10-19

## Scope and immutable baseline

- Baseline deployed HTTPS development beta: **0392401f0331c89dd07eed70e5ba939c8e4ac85c** / Draft PR #100.
- Audit lane: `feat/poc-coverage-audit-20261019` based on deployed HEAD. Existing protected dirty worktrees, production/public deployment, Exporter, and previous Draft PRs remain untouched.
- This change is **only a candidate on an isolated developer worktree**; the public site serves the previous baseline until separately approved and deployed.
- 34 registered Git worktrees and 108 accessible Git checkouts enumerated by metadata; audit covers 21 architectural topics. A SHA/file/import match proves **presence only**, not PoC behavioral equivalence.
- Source-only parser evidence is never promoted to Stellar DP/native import, target normalization accuracy, firmware/transport provenance, or a deployable DRAFT.

## 21-feature coverage and empirical evidence

| Function | Current candidate classification | Behavioral evidence or remaining gate |
|---|---|---|
| RFC 3164/5424 envelope | `SOURCE_EXTRACTED` | Existing authored source replay retained the same structural status. — 28-fixture replay: `rfc5424_sd_kv`. |
| RFC 6587 TCP octet/NUL | `SOURCE_FRAMED_DRAFT_UNVERIFIED` | Two frames recovered by new common container grammar; original transport DRAFT not qualified. — 28-fixture replay: `rfc6587_octet`. |
| JSON typed lexical spans | `SOURCE_EXTRACTED` | Existing typed JSON and UTF-8 source structure unchanged in the corpus replay. — 28-fixture replay: `json_single_nested_utf8`. |
| RFC 7464 JSON text sequence | `SOURCE_FRAMED_DRAFT_UNVERIFIED` | RS/JSON source framing restored; no native wire-compiler claim. — 28-fixture replay: `rfc7464_json_seq`. |
| GELF TCP NUL | `SOURCE_FRAMED_DRAFT_UNVERIFIED` | NUL-delimited GELF 1.1 JSON source framing restored; not native-verified. — 28-fixture replay: `gelf_tcp`. |
| NDJSON source boundary | `SOURCE_EXTRACTED` | Multi-event newline boundaries unchanged. — 28-fixture replay: `json_ndjson`. |
| CEF escapes / field structure | `SOURCE_EXTRACTED` | Authored CEF source replay unchanged; independent firmware oracle unavailable. — 28-fixture replay: `cef_extension`. |
| LEEF delimiter / KV structure | `SOURCE_EXTRACTED` | Authored LEEF source replay unchanged; independent firmware oracle unavailable. — 28-fixture replay: `leef_implicit_tab`. |
| KV quoting + duplicate occurrences | `SOURCE_PRESERVING_COMPILER_GAP` | Ordered duplicate key source values retained; downstream mapping not automatically qualified. — 28-fixture replay: `duplicate_kv`. |
| RFC 4180 CSV logical records | `SOURCE_PARTIAL_DRAFT_GAP` | Quoted multiline CSV remains conservative PARTIAL and needs native qualification. — 28-fixture replay: `multiline_quoted_csv`. |
| W3C Extended Log #Fields | `SOURCE_EXTRACTED_DRAFT_GAP` | Declared original header rows restored; 12/12 pinned publisher claims, native unverified. — 28-fixture replay: `w3c_declared_two_rows`. |
| Zeek TSV #fields/#types | `SOURCE_EXTRACTED_DRAFT_GAP` | Zeek declared original header rows restored; DRAFT parser grammar not qualified. — 28-fixture replay: `zeek_declared_two_rows`. |
| systemd journal exported entries | `SOURCE_GROUPED_DRAFT_GAP` | Two journal records no longer appear as four independent SOURCE_PARSED KV lines. — 28-fixture replay: `journal_export`. |
| Linux audit serial grouping | `STILL_MISSING_GROUPING` | Linux audit event sequence group by serial not integrated or independently qualified. — 28-fixture replay: `linux_audit_group`. |
| CRI + Docker JSON log wrapping | `PARTIAL_CONTAINER_GAP` | CRI partial/final continuation group still absent; Docker JSON line remains source-extracted. — 28-fixture replay: `cri_multiline`. |
| Mixed JSON/CEF/LEEF/KV arbitration | `SOURCE_EXTRACTED_COMPILER_GATED` | Mixed source parsing works for authored cases, parser export supports only declared subset. — 28-fixture replay: `mixed_json_kv_cef`. |
| UTF-8 source byte accounting | `SOURCE_QUALIFIED_NARROW` | All 28 replay cases accounted bytes; pinned W3C lexical/name/decoded values exact. — 28-fixture replay: `utf8_bom_kv`. |
| User-declared relay prefix/suffix | `SOURCE_INSPECTION_ONLY` | User-declared prefix/suffix UI inspection is separate from a downloadable wrapping grammar. |
| Multiple event types / dynamic mapping | `PARTIAL_COMPILER_QUALIFICATION` | Threat/user/asset review workflow exists; full dynamic native event mapping not independently qualified. |
| Stellar dictionary mapping | `METADATA_ONLY_NOT_NATIVE` | Dictionary projection metadata exists, but target field normalization not checked on actual Stellar. |
| Parser-file compile/readiness gate | `IN_PROGRESS_FAIL_CLOSED` | Source PARTIAL is not native success; three public beginner review-gate UX gaps reproduced. |

### Deterministic before/after (28 authored *synthetic* cases)

- Compared **the same immutable SHA-256 source strings** against deployed HEAD and the candidate via the actual Python Multi-Pass preview API. Evidence: `docs/verification/20261019-protocol-before-after.json`.
- Original byte accounting 28/28, no new false-complete alerts in the deliberately invalid guard cases. This is **not** 28 independent manufacturer accuracy oracles.

| Scenario | Deployed baseline source events | Candidate source events | Candidate success qualification |
|---|---:|---:|---|
| `w3c_declared_two_rows` | 4 | 2 | PARTIAL; native **NOT VERIFIED** |
| `zeek_declared_two_rows` | 7 | 2 | PARTIAL; native **NOT VERIFIED** |
| `rfc6587_octet` | 1 | 2 | PARTIAL; native **NOT VERIFIED** |
| `rfc6587_nul` | 1 | 2 | PARTIAL; native **NOT VERIFIED** |
| `rfc7464_json_seq` | 2 | 2 | PARTIAL; native **NOT VERIFIED** |
| `gelf_tcp` | 1 | 1 | PARTIAL; native **NOT VERIFIED** |
| `journal_export` | 4 | 2 | PARTIAL; native **NOT VERIFIED** |
| `linux_audit_group` | 2 | 2 | SOURCE_PARSED; native **NOT VERIFIED** |
| `cri_multiline` | 2 | 2 | RAW_ONLY; native **NOT VERIFIED** |
| `mixed_json_kv_cef` | 3 | 3 | SOURCE_PARSED; native **NOT VERIFIED** |

### Independent publisher-issued standards example (not hardware wire data)

- Pinned W3C publisher raw example SHA and frozen independent digest-only oracle match: **4/4 data rows** and **12/12 exact field name/value/original UTF-8 byte offsets**.
- A local private 0600 raw example and committed digest-only oracle are read exclusively offline on dev-atlas. **No raw original source or decoded original values** were committed, embedded in browser fixtures, logged, or sent to app.parser.xdr.ooo.
- The source is publisher documentation, **not** authenticated manufacturer/firmware wire capture; Stellar native target/export correctness remains **UNSCORABLE**.

## Real Chromium E2E at actual public HTTPS

- Exactly **100 Playwright CLI Chromium scenarios** performed at `https://app.parser.xdr.ooo/` with no API response stubs: legacy 54 + expanded 31 + earlier representative 15, all security solution examples authored for testing.
- Actual result on deployed beta: **97 PASS, 3 FAIL**; raw console and trace evidence under `/tmp/parser-poc-public-full-corpus-20261019-r3.log` and `/tmp/parser-poc-public-full-corpus-results-20261019/` (not added to Git).
- Failure 1: repeated KV keys (two source occurrences) successfully read but no safe automatically reviewable/exportable DRAFT. Failures 2–3: syslog-wrapped unlabeled positional CSV similar to pfSense/OPNsense: source extraction success but compiler family unsupported. In all three, enabled Review Fields did not navigate, while summary said “parsed completely”.
- These are **actual UX/compiler-readiness gaps, not proof of missing source values or a failure of the Python Multi-Pass detector**. Do not downgrade native verification gates to make the UI green.
- Candidate fix: separate source extraction from compile readiness; explicit block reason and no silent progression, read-only preview of source fields, ChatGPT Assisted Parser recovery, retry after edits. Normal JSON Review Fields → Map Fields remains reachable.
- The historical **27 public full-user flows** (prior Draft PR #100; including generation/download/ZIP and sender-file generation) remain earlier evidence at original deployed HEAD, **not independently re-run as another 27 in this audit**. New public matrix mostly covers analysis and conditional Review→Map, not end-to-end DRAFT download for every source.

## Isolated candidate browser and unit regression

- Chromium + real isolated local Vite/Multi-Pass API and controlled same-host authoring capability GET: **13/13 PASS** (W3C/Zeek 4, common transport 5, original three blocked-compiler workflows 3, and eligible JSON Review→Map 1). Evidence: `/tmp/parser-poc-candidate-ready-20261019-r2.log`.
- Python source-schema & transport tests: **13 PASS**, including invalid/malformed fail-closed, exact UTF-8 byte location, boundaries and journal record grouping. Full date-scoped Python suite **29 PASS**.
- Frontend static tests: **815/815 Vitest PASS**; TypeScript/Vite production build PASS. Exact final run logs stored in /tmp on dev-atlas and should be checked for completion before claiming candidate HEAD validation.

## Open gaps — no silent promotion

1. **DRAFT compiler compatibility** for metadata-dependent original W3C/Zeek streams and RFC6587/GELF/JSON-seq/journal framing remains **NOT VERIFIED**. The review API must not claim this source is downloadable or deployable.
2. **Linux audit event-serial grouping and CRI partial/final line reassembly** remain missing; Docker JSON wrapped logs require independent container-semantic replay. RFC 4180 multiline CSV still conservative PARTIAL and requires native grammar verification.
3. Wrapped positional CSV and ordered duplicate KV source occurrences need an approved **generic, non-vendor-specific compiler representation**. Do not fabricate field names, overwrite repeated values, or force a source-complete status into compilation.
4. **Full archived original/manufacturer and firmware/transport/relay oracles are not replayed through the public site.** The older independent 1,361 originals / 2,892 mutated-invalid safety study, 571/790 partial coverage and 197 REVIEW_ONLY records have varying provenance/rights/availability. They are not counted as the 100 authored-browser denominator. When authorized private originals are available, score entirely offline with a pinned independent answer; otherwise mark UNSCORABLE.
5. **Stellar Cyber native normalization, parser import, DP upload, sensor send and receipt are not tested**. DP upload and sensor sends explicitly excluded. Publish no F1/success rate for actual customer logs from authored fixtures.
6. Public beta still runs **0392401f03**, and the three user journey defects remain there until a separately approved rollout. Exact-head CI and owner final acceptance must be repeated on the candidate commit before any release.

## Reproduce without changing public hosts

```bash
python3 scripts/verification/poc_product_inventory_20261019.py
python3 scripts/verification/structural-protocol-before-after-20261019.py
python3 scripts/verification/score_publisher_w3c_20261019.py  # private 0600 source required; else UNSCORABLE
python3 -m unittest discover -s tests -p "test_*20261019.py" -v
npm test && npm run build
npx playwright test --config playwright.poc-candidate-20261019.config.ts
# Public browser replay uses REAL HTTPS and authored synthetic samples only:
npx playwright test --config playwright.poc-public-matrix-20261019.config.ts
```

Public/browser logs are intentionally not committed: they may contain screenshots, file downloads, or raw test input values. Repeating a broad real-domain browser suite is optional only after the next candidate implementation; do not claim existing public failures resolved until code is actually served.
