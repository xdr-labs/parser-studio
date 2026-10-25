# Parser Studio — Controlled User + GPT-6 ParserRecipe E2E (2026-10-25)

## Scope and attribution

The owner directed CHATGPT_CHAT to play both user and ChatGPT roles. This is a **same-conversation GPT-6** simulation, not separately authenticated external ChatGPT.com/API inference. The externally sourced model first/second/third-generation success rates remain **UNMEASURED**.

The target is the unchanged accepted main commit 2626558daf5d489517e5863a4e77beb9d95f24ac, public development app asset index-BwZ2Ek3z.js. The source-bound ten cases are one event each: five vendor-documented originals, two compacted vendor-documentation JSON examples, three explicitly synthetic security logs; no customer logs were used.

**Eight of ten prompts ALREADY EMBED a validated ParserRecipe.** GPT-6 elected to reproduce those eight baselines unchanged, exactly as their prompts requested. Those eight are baseline-reuse/user-E2E cases, not evidence of *new grammar generation*. The two genuinely model-authored new grammar cases were F5 ASM WAF and Zscaler ZIA (both synthetic source examples).

## Actual UI and native results

All ten source-bound prompts were prepared by the deployed HTTPS ChatGPT Assisted UI in real Chromium. The model-selected/generated replies were pasted into the actual UI, reviewed, and generated ten genuine downloaded Ruby+CONF DRAFT pairs. All ten native Ruby 3.2.3 fragments produced one callback from their source.

| Security source | Model behavior | Strict native first | Strict native final | Files | Original lexical values |
| --- | --- | --- | --- | --- | --- |
| FortiOS traffic | Reused embedded baseline | PASS | 1 | Ruby+CONF | 15/15 |
| FortiOS system | Reused embedded baseline | PASS | 1 | Ruby+CONF | 12/12 |
| Suricata EVE | Reused embedded baseline | PASS | 1 | Ruby+CONF | 12/12 |
| CloudTrail ConsoleLogin | Reused embedded baseline | PARTIAL | 1 | Ruby+CONF | 7/8* |
| FortiOS VPN | Reused embedded baseline | PASS | 1 | Ruby+CONF | 5/5 |
| FortiOS web filter | Reused embedded baseline | PASS | 1 | Ruby+CONF | 5/5 |
| FortiOS IPS | Reused embedded baseline | PASS | 1 | Ruby+CONF | 5/5 |
| F5 ASM WAF | New Regex grammar | REJECT | 2 | Ruby+CONF | 5/5 |
| CrowdStrike Falcon | Reused embedded baseline | PASS | 1 | Ruby+CONF | 5/5 |
| Zscaler ZIA | New strict TAB CSV grammar | PASS | 1 | Ruby+CONF | 5/5 |

* CloudTrail source eventTime text 2014-07-16T15:49:27Z was converted to native timestamp integer 1405525767000. Independent Python UTC date conversion verified exactly the same epoch milliseconds. It is a correct typed-normalized value, but it is not the verbatim source text and so remains one mismatch in the strict lexical metric.

Distinct measures:
- **Functionally created DRAFTs / native callback:** 9/10 at first answer and 10/10 by second answer. This INCLUDES eight prevalidated embedded-baseline cases; it does not measure unseen parser generation.
- **Strict full native scalar-exact gate:** 8/10 first (80%), 9/10 by second (90%) and 9/10 by third (90%). Total exact scalar occurrences are 76/77; CloudTrail intentional timestamp type casting accounts for the one mismatch.
- **Genuinely new grammars only:** 1/2 new first responses and 2/2 after the single necessary retry. Both cases are synthetic and source-only; no statistical generalization claim.
- **Independently authenticated external provider responses:** 0; no external ChatGPT inference was run during this simulation.

## Retry and fail-closed observations

First F5 response was rejected SCHEMA_REJECTED / UNTRUSTED_RECIPE because its grouped repetition conflicted with the product Regex safety contract. The actual user-facing second prompt preserved the original source and hash and included local validation failure feedback. A safer model-authored named-capture Regex then produced all five expected F5 source values in native Ruby. The F5 UI was SAMPLE PASS (NOT GENERALIZED); its built-in synthetic variation was NOT_APPLICABLE.

Zscaler used source-supported strict TAB CSV with seven columns, and the UI passed its original-sample synthetic IP substitution.

An unchanged embedded baseline intentionally has no Test Original Sample Only button. The product instead directly revalidates the existing recipe during DRAFT generation. The original independent replay harness initially assumed that button was always present; the isolated controlled replay accounts for this actual UI path. It is an evaluator-path correction, not a discovered product bug.

## Follow-up native synthetic tests, not holdout

For the two model-authored grammars, independently executed the genuine downloaded native Ruby parser fragments against controlled alterations of the input:
- 12/12 changed-value cases PASS across IP, username, method, HTTP request status, URL, domain, timestamp and combined substitutions.
- 6/6 malformed-input cases safely rejected, including missing/misordered F5 keys, wrong Zscaler TSV column count and invalid IPv4.
- These are synthetic metamorphic checks and **not** source-disjoint independent vendor captures or physical Stellar target validation.

## Evidence and safeguards

- Real source data, 10 first replies, F5 second prompt and response, 10 genuine downloaded Ruby+CONF pairs, browser acceptance results, native checks and synthetic probes remain in private dev-atlas directory /home/aella/.local/state/parserstudio-samechat-user-ai-20261025.
- Immutable receipt FINAL_SAME_CHAT_USER_GPT6_ACCEPTANCE_20261025.json SHA-256: 3b714551a7a54eb1711ed70c8c46c4fd5e3cc71c83da968134137d6033047718, binding 67 source/response/result file hashes.
- Isolated same-chat replay uses explicitly labeled SAME_CHAT_GPT6 capture provenance, rejects OpenAI API/browser provider receipt substitution, and never claims an independent model completion.
- Combined isolated benchmark and replay contract test suite 18/18 PASS. Main, public installed assets, backend services, credentials, production, real Stellar Cyber DP/sensors and the external-model benchmark data were not changed.
- Actual external API attempt made earlier returned 429 credit_balance_exhausted. This controlled same-chat run incurred zero provider completions, and real external ChatGPT success rates remain unmeasured.

## Conclusion

The bounded manual user/ChatGPT copy-paste, adaptive-retry and real native DRAFT workflow works on these ten cases. The preexisting baseline embedded in eight prompts heavily biases any apparent first-shot model-generation success. No broad grammar replacement or forced product features are justified by this evidence alone. Genuine blind model generalization still requires independent inference and new unseen security examples with independent ground truth.
