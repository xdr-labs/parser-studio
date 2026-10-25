# Independent ChatGPT ParserRecipe Benchmark — Authenticated Provider Handoff (2026-10-25)

## Scope and measurement truth

- Project: xdr-labs/parser-studio, accepted development runtime from main HEAD 2626558daf5d489517e5863a4e77beb9d95f24ac.
- Target: 10 source-bound **single-event security-solution** prompts from evals/chatgpt/security-cases.json: 5 unchanged vendor-documented, 2 separately labeled documentation JSON compacted, 3 explicitly project-synthetic. No customer captures.
- The current public development site generated all 10 prompts and preserved exact source bytes and SHA-256. prepare-audit.json shows 10/10, 0 unexpected third-party requests.
- The existing tools/qa/chatgpt_independent_benchmark.cjs replays external provider text in **real Chromium**, verifies exact original/retry prompt identity, uses the actual source-bound Recipe validator, tests the original sample, requires review/approval, downloads genuine Ruby/CONF DRAFTs and executes native Ruby.
- The additional tools/qa/chatgpt_independent_provider.cjs invokes an independently authenticated OpenAI Responses API **only when run with explicit opt-in**. It never runs in Parser Studio, CI, or the ordinary site. It stores provider-issued response IDs, exact prompt/response hashes, raw reply text and metadata in a private directory; key bytes are never logged or committed.
- Its default chat-latest API model tracks the latest **Instant** model used by ChatGPT. This is a separately authenticated **API** evaluation, not the same user interface or a bit-for-bit equivalence claim about ChatGPT.com. Use one model for all cases and attempts, and record the returned model ID.
- Three total model attempts maximum per case, only when the UI provides an improved prompt. No invented second/third attempts. Sample-only passing is not independent holdout validation or physical Stellar Cyber 7.0 DP validation.
- Provider metadata and receipts are operator-observed/attested, not cryptographically signed provider proof. Semantic accuracy stays null without independent human adjudication.

## Already measured before provider authorization

- Source/UI prompt preparation: **10/10 PASS**; source-bound and correct vendor/product metadata; development asset pin index-BwZ2Ek3z.js.
- Offline unit tests: original benchmark 8/8 PASS; provider adapter adds independent mocked success/failure/privacy-key tests.
- External independent model completions: **0**; first/second/third cumulative generation rates **UNMEASURED** (not zero).
- OpenAI endpoint is reachable but returns unauthenticated HTTP 401 when no key is provided.
- Do not substitute responses authored in the current conversation for independent provider replies.

## User action: enable a separate API project

An OpenAI API project with enabled billing and chat-latest model access is required; a ChatGPT subscription alone is not an API key. Open https://platform.openai.com/api-keys, create a scoped project key, and configure an appropriate project spending limit.

On **dev-atlas**, from the authorized operator's interactive shell, run the following; input remains hidden and the key stays solely in the operator's home directory. **Never paste this secret into chat, issue comments, source, or browser JavaScript.**

    install -d -m 700 ~/.config/parserstudio-qa
    umask 077
    read -r -s -p "OpenAI API key (hidden input): " PARSERSTUDIO_QA_KEY
    printf '\n'
    printf '%s' "$PARSERSTUDIO_QA_KEY" > ~/.config/parserstudio-qa/openai-api-key
    unset PARSERSTUDIO_QA_KEY
    chmod 600 ~/.config/parserstudio-qa/openai-api-key

Only report "key configured"; do not provide the secret itself. At that point, the implementer can run the benchmark through Remote Desktop Commander without needing the owner to copy any prompts.

## Operator execution

    cd /home/aella/parser-studio-independent-api-runner-20261025
    node --test tools/qa/chatgpt_independent_benchmark.test.cjs tools/qa/chatgpt_independent_provider.test.cjs
    node tools/qa/chatgpt_independent_provider.cjs preflight
    node tools/qa/chatgpt_independent_provider.cjs run --model=chat-latest --execute-external-inference=yes

The final command sends **only the 10 approved public/documentation/synthetic fixture prompts** to the explicitly authorized OpenAI API; it does not send customer logs. store:false disables optional persistent Responses storage, but normal provider operational and abuse-monitoring retention policies may still apply.

The runner resumes from existing valid prompt/response SHA and provider receipts after recoverable interruptions; it refuses mismatched or partial receipts, replaced live Web bundles, wrong fixture hashes, group-readable key files, and absent opt-in.

Outputs: private /home/aella/.local/state/parserstudio-independent-chatgpt-qa-20261025 per-case response/receipt/report/native DRAFTs, benchmark-summary.json, and api-execution-*.json. Never commit response bodies or credentials.

## Acceptance and reporting

- Per-case first/second/third attempt status, explicit failure categories, and real provider completion ID.
- Real source-bound original sample and native Ruby pass, including lexical source values and normalizer output. Exclude sourceLine from derived field-value scoring.
- Report **cumulative success after one, two and three attempts** over the fixed denominator 10. Treat cases not completed with proper receipts as UNMEASURED; never count them as 0% success.
- Distinguish VENDOR_DOCUMENTED_COMPACTED, VENDOR_DOCUMENTED and PROJECT_SYNTHETIC when reporting per-family evidence. Never call these 10 independent vendor-captured logs.
- Semantic truth and Stellar Cyber native target ingestion remain separately unverified until separately observed; do not promote auto lexical checks into semantic precision claims.

## Alternative signed-in ChatGPT.com route

The benchmark supports manual independent ChatGPT.com responses: use prepare, paste prompt-N.txt into a **separate signed-in browser conversation**, save the returned exact text as response-N.txt and a corresponding receipt-N.json with origin CHATGPT_WEB_SIGNED_IN, conversation URL, model, recorded time, attestation, and matching prompt/response hashes; run replay to create the next improved prompt only when needed. This requires direct browser access and substantial manual copying; Chat-mode Browser read-only access in the originating mobile session is insufficient for automatic entry.
