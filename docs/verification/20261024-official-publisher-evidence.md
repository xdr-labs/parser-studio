# 2026-10-24 Parser Studio — publisher-original evidence qualification (read-only)

## Scope and provenance

Continuation of Issue #1 ACTIVE Work Packet `6369068053`. Parent source: `main@7fe33b737aa25a492180d21ede27eb74cd83a4bd`, tree `7171b0fdcbacb69bafadaeb5f91d684818bd38e7`. The prior 152 production-browser acceptances were **not** rerun. The deployed development UI remained at `https://app.parser.xdr.ooo/`; this work creates no live deployment.

**Provenance classes are separate:** Four unchanged, manufacturer/publisher-hosted documentation **log examples** (three products, four types, four event records) were captured with private immutable raw UTF-8 SHA-256s, publication paths, exact source-field labels and byte ranges. These are **NOT independently authenticated instrumented firmware/device captures**, and no firmware-wide statistical accuracy is claimed. Unlabeled fields are **not** counted as true/false positives. Dates/product releases identify documentation provenance, not the observed firmware that emitted the bytes.

| Source ID / event family | Publisher and origin | Raw SHA-256 | Source fields | Independent labeled matches (name + value / raw-token span) | Production UI & compiler |
| --- | --- | --- | ---: | ---: | --- |
| FortiGate traffic/forward | Fortinet FortiOS 7.0.0 [sample logs](https://docs.fortinet.com/document/fortigate/7.0.0/administration-guide/986892/sample-logs-by-log-type) | `e0b6363ca5fbfd5fc41c130837bf587f81aba5377185ad05d77c396a16eb1f73` | 47 | 15/15 and 15/15 | SOURCE_PARSED, Ruby+CONF DRAFT download succeeded |
| FortiGate event/system | Fortinet FortiOS 7.0.3 [system subtype example](https://docs.fortinet.com/document/fortigate/7.0.3/fortios-log-message-reference/463430/event-log-support-for-cef) | `8db8e0b7e49e25ab85b139882a46ff92513dca79ebaa5567a9a1b027098c0d40` | 19 | 12/12 and 12/12 | SOURCE_PARSED, Ruby+CONF DRAFT download succeeded |
| Suricata EVE alert | OISF [EVE JSON 8.0.0 documentation](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html) | `55321e46b4f2b5108bd7545491f61a9679b0a39de0a09d9924a316b450417b51` | 19 | 12/12 and 12/12 | SOURCE_PARSED, UI requires reviewed native parser rule; **no DRAFT generation claimed** |
| AWS CloudTrail ConsoleLogin | AWS [IAM/CloudTrail documented event](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html) | `d0a97acca154187eb50d4b118c69b1466e28a34547abeef62438edeb21a349e8` | 18 | 8/8 and 8/8 | SOURCE_PARSED, UI requires reviewed native parser rule; **no DRAFT generation claimed** |

**Totals:** 4/4 records/framing and source grammar statuses `SOURCE_PARSED`, 0 source residuals; 47/47 independently labeled decoded field values and 47/47 byte span boundaries checked against real API responses initiated by the public Chromium UI. **Important span contract:** KV spans reference decoded text (quotes excluded); JSON spans reference lexical JSON values (including enclosing quotes), which must be decoded before comparing to expected semantic values. Unlabeled 56 field occurrences are unscored; this is not a 100% full-schema precision claim. Full parser-generation E2E is **2/4**, not 4/4.

Actual generated artifact hashes (not installed):
- Traffic: `customized_fortinet_fortigate.conf` SHA-256 `cf5ae5d7532af685681fd973d4b2e12ebfcbd5f8c254b9b9d1da0eb4587d7586`, Ruby fragment SHA-256 `4235b151c2964c023c541db2fa7f4076ba96400a3d60697929e4792d521ceed8`.
- System: CONF SHA-256 `c1355d45d64f5a75a623854b6862929790f62e2bfd2c6697e98175163756501c`, Ruby SHA-256 `5c289a4d1ed56fca30387212972a7cfb6f69e992b605951e2eefb3a04ccb318e`.
- Both CONF outputs specify port 6801 and final Syslog `invert true`; no Ruby syntax or target installation is asserted from this browser test. An ancillary test harness attempted to access the log textarea after leaving the log-input stage and timed out; downloads were already completed, so this is **not** a product download failure.

## Independent external ChatGPT

Four genuine public-UI prompts were prepared using the unchanged four publisher example log bodies; each contained the same source text and requested fields. Prompt SHA-256s: traffic `a4fd8389d17808ad515e3201271c97169f91eca7a7125dad298f982afe579bea`; system `534117427fe503e9130178ccc6e790d36e6135e228f252446ff4e2214e1dd77e`; Suricata `d37c7c2ffef60f636e4b8cf9fd39c1788a1a64f57b96ca4513107b6dcab2f3b5`; CloudTrail `fd3e88b1e70fb8b8ad03b6fbe89a082b1c0c449464de548c7f2c9b50853725b5`. No external egress occurred. **Independent separate provider calls: 0; real model replies: 0; accepted/compiled/holdout-qualified actual model responses: 0.** Neither this session's generated text nor old controlled 9/9 recipes qualifies. A separately authorized external-model execution channel is not available in this runtime; it remains a genuine evidence gate.

## Stellar Cyber 7.0 target

Read-only `rickmodular` target discovery found `/etc/aella/version = 7.0.0_023bdc1`, running `td-agent`, and 454 existing `.conf` + 455 extensionless files in `/opt/td-agent/etc/td-agent/customized_parser` (historical reference collection; no target writes). The newly generated candidate pair name does not exist on that target. Its ruby interpreter path was discovered, but code was not executed on it. Official 7.0.xs dictionary-only mapping review was observed in the Web UI: Traffic 10 Stellar-matched / 37 vendor-only; System 4 Stellar-matched / 15 vendor-only; ambiguous bare clock/epoch-to-timestamp suggestions remained review-only. **Target import/run/events/index field verification: 0.** Status: `TARGET_7_PRESENT_READ_ONLY / IMPORT_UNAUTHORIZED / TARGET_VERIFIED_FALSE`, not TARGET_UNAVAILABLE and not TARGET PASS. Do not deploy or send traffic without a separately authorized nonproduction stage, backup/rollback and action approval.

## Reproducibility and protected artifacts

Private dev-atlas evidence: `/home/aella/.local/state/parserstudio-real-evidence-20261024/`, with `source-pages/` original publisher HTML, `raw/` byte-preserved excerpts and `reports/` per-browser screenshots, actual HTTP response JSON, golden ledger, prompt text/hashes, DRAFT downloads, and summary `official-source-span-accuracy.json`. Do not commit raw documents, private logs, generated parser logic or full source-bearing API responses into the Git repository.

From a clean authorized checkout: `python3 tools/vendor_evidence_20261024.py --acquire` gathers the four official source pages (preserving already-cached originals), then `node tools/score_official_live_api_ui_20261024.cjs` with Playwright/Chromium installed runs the same four source uploads against the development UI; finally `python3 tools/score_official_spans_20261024.py` checks independently labeled values and byte spans. Set `PARSER_STUDIO_EVIDENCE_ROOT` to change the private artifact root and `PARSER_STUDIO_BROWSER_CHROME` to use an installed compatible browser. Product and publisher docs may change; a mismatch is a new corpus, not evidence for silently overwriting frozen originals.

## Separate owner-ordered UI simplification

The owner removed the unnecessary **Open or inspect an existing parser** UI. Source deletion and preserved novice Analyze flow are in [Draft PR #151](https://github.com/xdr-labs/parser-studio/pull/151), exact head `9c21510a71f1cf61a32f7aaaed7032a35b5b0119`. Local TypeScript/Vite PASS, guided unit 837/837 PASS, affected actual Chromium 16/16 PASS. No merge or public deployment was done.

## Remaining acceptance gates

1. Independently authenticated real product/device captures and distinct same-vendor holdouts, with complete full-schema labeling, not merely documentation examples.
2. Actual separate ChatGPT model invocation; retain model ID, exact prompt/response hashes, strict v0.2 acceptance, holdout compilation/replay and unsupported/hallucinated field metrics.
3. Explicitly authorized isolated 7.0 target import, listener reception, indexed field checks and rollback. Real targets must not be mutated by read-only evidence work.
