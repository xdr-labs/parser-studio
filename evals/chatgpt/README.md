# Independent ChatGPT ParserRecipe benchmark — operator protocol (2026-10-25)

## Purpose and provenance limits

This isolated QA-only benchmark targets the already-published development Parser Studio. It is not a product model integration or new user mode. The security case set includes **10 one-log inputs**: **5 literal vendor-documentation log lines**, **2 vendor-documentation JSON objects converted only from pretty-printed multiline JSON into single-line JSON** (Suricata, AWS), and **3 explicitly project-synthetic examples** for WAF, EDR and proxy. Each source has its actual input SHA-256, public source URL and exact expected values. The two whitespace-compacted JSON examples also retain the SHA-256 of their distinct documentation presentation and the transformation label; neither is claimed byte-identical to the published pretty-printed JSON. Synthetic examples must not be called independently collected manufacturer logs.

This runner never invokes an LLM, extracts credentials, uploads customer logs, or sends security logs to ChatGPT. Manual review and copy/paste remain user-controlled. A separately authenticated, actually invoked ChatGPT.com or OpenAI API is required to measure independently generated parser quality. This same conversation's authored responses, controlled fixtures and hand-crafted recipes are not valid provider evidence.

Pinned deployment: commit 4ca65ebafcde67f02bd296357d4340e216feecbc, public JS index-BwZ2Ek3z.js. A different published bundle fails closed rather than silently testing another release.

## Run procedure

From the isolated QA worktree on dev-atlas:

1. Run: node --test tools/qa/chatgpt_independent_benchmark.test.cjs
2. Run: node tools/qa/chatgpt_independent_benchmark.cjs prepare
3. The prepare command launches actual Chromium against https://app.parser.xdr.ooo/, enters each source log, and captures its exact first prompt as prompt-1.txt with a SHA-256. It performs zero external model calls.
4. In a **separately signed-in ChatGPT session**, submit each exact prompt-1.txt manually and save the unmodified result as response-1.txt in the matching private case folder. Supply receipt-1.json with origin CHATGPT_WEB_SIGNED_IN, model, recordedAt, operatorAttestation, a real conversationUrl beginning https://chatgpt.com/c/ (or /share/), plus responseSha256 and promptSha256. For an authorized OpenAI API completion, use origin OPENAI_API and its real completionId. Receipt metadata is operator-attested, not a cryptographic proof of provider identity.
5. Run: node tools/qa/chatgpt_independent_benchmark.cjs replay
6. The replay command recreates the source and original prompt in real Chromium, pastes the external reply, runs Check ChatGPT Result, Test Original Sample Only, explicit approval, genuine DRAFT Ruby/CONF generation, and native Ruby callback/value checks. On a failed attempt it saves the actual UI-generated improved prompt as prompt-2.txt / prompt-3.txt. Obtain a new independent model response, its receipt and repeat the replay. No fourth attempt.
7. Run: node tools/qa/chatgpt_independent_benchmark.cjs score

Default private evidence root: /home/aella/.local/state/parserstudio-independent-chatgpt-qa-20261025/. Override with --out=/absolute/private/path. Never commit provider transcripts, receipts or raw customer logs.

## Metric and acceptance rules

First, second cumulative and third cumulative success rates use the **entire ten-case denominator** only when all ten have independently recorded model outcomes. Partial or no provider evidence returns **null / UNMEASURED**, never 0%, PASS or an invented uplift. A successful result requires a local sample PASS, manual approval, genuine Ruby and CONF DRAFT files, native Ruby callback with no parser exception, and no missing expected source values. A partial result is separate from SUCCESS. The run computes exact source-value recall and original-byte fidelity; field-role semantic accuracy stays **null** until independent manual adjudication, rather than inferring source/destination meanings from a matching IP literal. Native verification is still not a Stellar Cyber 7.0 target installation.

The original single sample and controlled single-IP substitutions are not an independent holdout; one-record success never proves generalization to firmware versions or unseen event types. This is a deliberately small, nonrandom evaluation panel, not a global ChatGPT success-rate estimate.

The first fixture inspection detected that the unmodified pretty-printed JSON documentation displayed 26/27 physical lines, violating the one-record-per-input rule. After clearly recorded whitespace-only JSON compaction, each of the ten browser prompts must report sourceCount 1; do not pass a mere prompt-creation check without checking this count. At initial preparation: 10/10 real Chromium prompt captures PASS; 8/8 QA contract tests PASS; provider responses 0, so independent first/second/third generation success **UNMEASURED**. GitHub hosted Actions PR #159: 7 pre-run failed jobs, zero executed steps (billing/startup external gate). No release, main merge, production, DP, sensor or target import occurs here.
