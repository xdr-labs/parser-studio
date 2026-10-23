# 2026-10-23 — Full User E2E and AI-assisted prompt fidelity across 22 security-log scenarios

## Product / test boundary

- The **public development Web UI** was checked by Playwright Chromium at `https://app.parser.xdr.ooo/`, released main `2f7a0d876213e5775ca3e2ae04e25bc63d9299f5`.
- Source fixtures are authored examples of vendor-style logs, **not validated firmware-specific original vendor logs**.
- A separate candidate branch adds conservative source-grammar evidence and corrects the misleading holdout claim. **Candidate tests run in pinned local Chromium + real isolated source services**, not on the deployed public app. Do not claim deployment.
- No automation posts raw customer logs to an LLM; copying a prompt is explicit user action. The synthesized log data in these tests contains TEST-NET addresses.
- No independent external ChatGPT inference calls were run. In particular, strict recipe exchanges use a **known, controlled valid/invalid response**, so their PASS is pipeline acceptance, not ChatGPT hallucination/accuracy rate.

## Actual public first-time-user functional paths

Playwright browser interaction, not static component inspection:

| Scenario | Actual flow | Result |
|---|---|---|
| New Auto parser and re-import | input 2 JSON events → Analyze → Review → Map → Create → actual Ruby/CONF/ZIP downloads → New Parser → upload the same files → read-only inspection → reopen with source reset | PASS |
| File import | upload valid .log → Analyze; upload malformed UTF-8 → show warning and preserve prior source | PASS |
| Forwarder prefix/postfix | select exact bytes in textarea → Mark prefix/postfix → 2/2 wrapper detection → clear marks → original logs untouched | PASS |
| Declared Syslog relay | enter relay01 and max hop 2 → 2/2 source recognition → Apply → confirm active profile → Clear | PASS |
| Python test sender | download a .py file containing sample template; inspect required confirmation and dynamic sender; do **not** send to a sensor | PASS |
| Local Versions | V1/V2 browser-only checkpoint → diff → restore → separate browser context has no access | PASS |
| Three named event types | Threat/User/Asset source entry → Analyze → duplicate-name validation → return to combined editor with explicit confirmation | PASS |

The first attempted 7-case harness run had a faulty assumption about UI mode inputs (the single textbox is replaced by group inputs) and omitted an expected browser confirm. After correcting the **test harness only**, the seventh scenario was separately rerun and **PASS**; the other six had already passed. No product defect established from those harness errors.

## ChatGPT preparation — 22 input scenarios

Every row was actually entered into Auto Parser, analyzed, carried to ChatGPT Assisted, annotated with source vendor/product/version and desired fields, copied from the generated prompt via its user button and independently compared for:
- exact original source bytes, projectId, sourceCount and SHA-256;
- source solution info and user's requested extraction fields;
- explicit REVIEW_REQUIRED fallback and a prohibition on invented grammars;
- exact copied clipboard equals visible prompt, no automatic cross-origin requests or HTTP 5xx.

The 22 cases are **22/22 PASS** for those assertions, grouped into **14 baseline-review prompts** and **8 full-recovery prompts**. The number in 'source event identity' comes from the unchanged *physical source record accounting*, not always logical data events.

| # | Input log / scenario | Source event identity | Auto result | ChatGPT request mode |
|---:|---|---:|---|---|
| 1 | Fortinet FortiGate traffic | 1 | complete | BASELINE_REVIEW |
| 2 | Palo Alto PAN-OS traffic | 1 | complete | BASELINE_REVIEW |
| 3 | Cisco ASA session | 1 | complete | BASELINE_REVIEW |
| 4 | Juniper SRX RT_FLOW | 1 | needs review | FULL_RECOVERY |
| 5 | WatchGuard Firebox | 1 | needs review | FULL_RECOVERY |
| 6 | Check Point Firewall | 1 | complete | BASELINE_REVIEW |
| 7 | F5 ASM WAF | 1 | complete | BASELINE_REVIEW |
| 8 | ArcSight CEF IDS | 1 | complete | BASELINE_REVIEW |
| 9 | IBM QRadar LEEF | 1 | complete | BASELINE_REVIEW |
| 10 | Suricata EVE alert | 1 | complete | BASELINE_REVIEW |
| 11 | Snort alert | 1 | needs review | FULL_RECOVERY |
| 12 | CrowdStrike Falcon | 1 | complete | BASELINE_REVIEW |
| 13 | Microsoft Defender XDR | 1 | complete | BASELINE_REVIEW |
| 14 | Okta System Log | 1 | complete | BASELINE_REVIEW |
| 15 | AWS CloudTrail | 1 | complete | BASELINE_REVIEW |
| 16 | Cisco Umbrella DNS | 1 | needs review | FULL_RECOVERY |
| 17 | Zscaler ZIA Proxy | 1 | needs review | FULL_RECOVERY |
| 18 | Zeek connection TSV | 4 (2 data events + 2 headers) | needs review | FULL_RECOVERY |
| 19 | W3C IIS WAF | 3 (1 data event + 2 headers) | needs review | FULL_RECOVERY |
| 20 | Multitype JSON threat/user/asset | 3 | complete | BASELINE_REVIEW |
| 21 | Korean UTF-8 EDR | 1 | complete | BASELINE_REVIEW |
| 22 | Unsupported Windows Event XML | 1 | needs review | FULL_RECOVERY |

## Actual on-screen AI response validation and compiler paths

An additional independent 9-case browser suite fed known, controlled, strict v0.2 ParserRecipe responses into the **real** UI and authoring API: seven unchanged validated baseline JSON recipes (FortiGate KV, CEF, LEEF, Suricata, Defender, CloudTrail and Korean UTF-8 JSON); one two-record CSV FULL_RECOVERY proposal with independent holdout logs and explicit user approval; and one `REVIEW_REQUIRED` Windows XML refusal. **9/9 acceptance PASS**, including actual downloaded `.conf` files when a parser could be compiled. These were not produced by external ChatGPT calls.

### Identified errors and root fixes

1. **Zeek and W3C declared headers:** the prepared prompt's `sample.events` uses exact physical record accounting as an immutable source identity (4 for Zeek, 3 for W3C), while local Multi-Pass correctly analyzes 2 and 1 logical data events respectively. Without a clear distinction a model may mistake header rows for events. The candidate prompt now adds a locally verified declared-schema observation with the original header count and logical data event count; never alters the original source identity. For header-dependent streams it directs `REVIEW_REQUIRED`, not a fabricated deployable single-line grammar.
2. **Claiming tests that were not run:** unchanged baseline recipe compilation formerly displayed an assertion that 'additional examples passed' when no independent holdout was provided. Now the UI explicitly states the original unchanged recipe passed and **no different holdout was tested**. Actual changed recipes still require independent holdout and explicit approval.
3. **Unsupported free text:** for Snort-style raw events, only unknown-grammar status is presented, no manufactured vendor grammar or native import approval.
4. **Prior separate bug:** public Multi-Pass valid 500-record JSON input hits HTTP 422 because JSON wire encoding exceeds the raw-source limit; it was fixed on separate **Draft PR #148** and passed exact-HEAD CI 7/7, but is not yet deployed. Avoid conflating that outstanding work with prompt improvements.

## Full same-source browser regression and CI time-limit diagnosis

- Full real Chromium Playwright collection on the isolated exact source:
  **393 registered scenarios**, **367 PASS**, **26 explicitly conditional
  SKIP**, **0 unexpected failures**, **0 flaky**. The source tests ran with
  in-repository Multi-Pass and built same-source authoring backend; JSON proof:
  `/tmp/parserstudio-chatgpt-full-chromium-20261023.json`.
- Frontend Vitest **1,141/1,141 PASS** across 147 files and a fresh
  TypeScript/Vite build **PASS**.
- Original PR #149 Actions #39966462589: all six browser catalogue shards
  succeeded, but Web Quality was **CANCELLED**, not test-FAILED, after its
  configured 18-minute job timeout. Its first Chromium dependency installation
  consumed much of the allotted job time before backend-driven Chromium
  acceptance could finish. GH job log records `The operation was canceled`
  during the later `Same-HEAD authoring-only HTTP and beginner Chromium`
  step; no product-code failure was established. Increase only the Web Quality
  time budget to 35 minutes and preserve its existing mandatory quality gates.
  The new source HEAD must be separately checked; do not call the earlier
  cancelled run SUCCESS.
- The six browser-shard passes, full isolated local browser census and unit
  suite are independent useful evidence, but the exact-head CI release gate
  remains unqualified until the replacement GitHub run completes successfully.

## Proof requirements / result classification

- Prompts: **22/22 model-input/clipboard fidelity**, **not** model-output semantic accuracy.
- Controlled ParserRecipe validation: **9/9**, **not** independent external model inference.
- Real browser first-time-user workflows: **7/7 distinct tested functionality** (six initial PASS + corrected seventh PASS).
- Previous broad source test: 54 synthesized log types included 42 complete structural extraction and 12 honest review-required; 106 separate real public E2E functional paths passed. These are not vendor-certified parsing accuracies.
- The candidate-specific unit and Chromium gates are separate from public E2E; exact source and CI status must be checked before promotion. PR148 backend boundary fix remains a separate draft awaiting owner release approval.

## Evidence and privacy

- On-server public 22-row prompt records: `/home/aella/.local/state/parserstudio-public-rollouts/parserstudio-novice-prompt-audit-20261023/prompt-v2.log`.
- Candidate 22-row pinned local Chromium: `/tmp/parserstudio-chatgpt-vendor-prompt-matrix-20261023.log`.
- On-server controlled recipe responses: `/home/aella/.local/state/parserstudio-public-rollouts/parserstudio-ai-recipe-e2e-20261023/results.log`.
- Feature browser: `/home/aella/.local/state/parserstudio-public-rollouts/parserstudio-novice-features-20261023/results.log`, correction rerun in isolated Playwright session.
- Root source files: `src/guided/chatGptSourceEvidence.ts`, `ChatGPTAssist.tsx`, `chatGptPromptBuilder.ts`.
- Reproducible tests in current source: `tests/chatgpt-prompt-source-evidence-20261023.spec.ts`, `tests/chatgpt-vendor-prompt-matrix-20261023.spec.ts`, `tests/chatgpt-controlled-result-matrix-20261023.spec.ts`, `src/guided/chatGptSourceEvidence.test.ts`.
