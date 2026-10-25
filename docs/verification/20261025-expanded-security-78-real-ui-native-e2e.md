# Parser Studio — Expanded Security-Solution Real Browser and Native E2E

Date: 2026-10-25 (KST). Owner requested dozens of additional security-solution logs under the existing GPT-6 acting-user/acting-model workflow. No Work/Codex mode, production, Stellar target, sensor/DP or user app deployment.

## Provenance and scope

Use the prior pinned private security corpus in /home/aella/.local/state/parserstudio-security-scope-20261024/security-corpus.json. Its 86 unique records were filtered to eliminate all SHA overlap with the previous 10-case AI benchmark and explicitly repeated F5/CrowdStrike/Zscaler cases. The resulting 78 original records and 78 unique UTF-8 source SHA-256 hashes include:

- 24 VENDOR_DOCUMENTED source texts
- 28 VENDOR_DOCUMENTED_JSON_EXAMPLE texts (potentially compacted JSON; not identical published page bytes)
- 26 PROJECT_SYNTHETIC fixture records

Fourteen publisher/vendor labels: Fortinet, OISF/Suricata, Zeek, Palo Alto, Cisco, Juniper, WatchGuard, Check Point, ArcSight, IBM, Microsoft, Okta, Amazon and Example Security. Not 78 instrumented manufacturer device captures. Never infer exact vendor semantic accuracy from source-derived lexical oracle.

Production-shaped developer UI version remained accepted main 2626558daf5d489517e5863a4e77beb9d95f24ac; tested HTTPS address https://app.parser.xdr.ooo/. Test-only QA scripts remain in Draft PR #164. No runtime code or services were changed.

## Real public Chromium: Auto Parser and ChatGPT prompt preparation

All **78/78** cases passed actual manual user-path automation:
Paste original log in Auto Parser → Analyze Logs → capture the actual non-mocked Multi-Pass POST response → compare source SHA and extracted values → open ChatGPT Assisted → generate the source-bound prompt.

- **78/78** unchanged original bytes and displayed hash; **78/78** copyable ChatGPT prompts preserve exact original and matching hash.
- Status: **SOURCE_PARSED 66**, **PARTIAL 8**, **RAW_ONLY 4**; no unknown status, browser JS exception, HTTP 5xx or automatic third-party/model request.
- A source-derived lexical oracle found **964/964 literal scalar values** present somewhere in the source-structure extraction. Exact lexical path/value identity **943/964**; the 21 alternate paths are because the product exposed syslog envelope/structural group prefixes in 12 Fortinet, two WatchGuard and seven Check Point instances. These are not manufacturer golden fields.
- ChatGPT prompts split: **63 already contain a locally validated ParserRecipe**, **15 are FULL_RECOVERY without a ready baseline**. This distinction is required for valid model-quality interpretation.

Harness: tools/qa/expanded_security_browser_20261025.cjs. Private evidence: browser-78-real-public.json.

## Controlled GPT-6 role: 63 previously validated baseline recipes

For 63 source examples GPT-6 followed the actual prepared prompt by returning the already embedded, validated v0.2 recipe unchanged. The genuine public Chromium UI imported each response, rechecked the original, and downloaded 63 Ruby+CONF DRAFT pairs. All **63/63** actual Ruby 3.2.3 native callbacks passed. These are baseline-reuse E2E outcomes, NOT 63 new AI grammar generations.

Strict verbatim native-source scalar score: **935/950**. All 15 differences were inspected against actual compiled Ruby output, prevalidated source mappings and original data:

| Strict string differences | Count | Checked behavior |
| --- | ---: | --- |
| Source ISO date-time converted to epoch ms | 3 | Exact UTC epoch equivalence |
| Fully expanded IPv6 canonicalized to ::1 | 2 | Exact typed IP address equivalence |
| Source reason=N/A | 1 | Explicit configured ignoreValues behavior |
| Nested source-array values not requested by v0.2 mappings | 9 | NOT emitted in compiled native output |
| **Total** | **15** | Do not report 950/950 literal native preservation |

The nine native omissions concern Suricata exception-policy/PGSQL nested list values and Zeek HTTP/TLS response-file/certificate-chain array elements. They are *real scope/coverage limitations* even if unmapped by the current proposal; there is no evidence that they are newly introduced regressions. Browser original/source preview retains the raw source.

Harness and readback: tools/qa/expanded_baseline_native_20261025.cjs, expanded_native_mapping_audit_20261025.cjs, expanded_source_value_audit_20261025.py. Private baseline-reuse-e2e/summary.json, native-mapping-gap-analysis.json, native-source-value-mismatch-adjudication.json.

## Controlled GPT-6 role: 15 new full-recovery decisions

Each of the 15 additional source-bound prompts came from the actual HTTPS ChatGPT Assisted UI and contains no embedded baseline. Eight complete v0.2 proposals were authored and seven deliberately responded REVIEW_REQUIRED where only headers, untrusted positional schemas or unsupported XML were available.

After source-preserving real UI retries: **7 actual Ruby+CONF native DRAFT successes; 8 safe REVIEW_REQUIRED**. No unsafe DRAFT was generated for refused cases.

| Case | Final | Number of model-role answers | Qualification |
| --- | --- | ---: | --- |
| Juniper SRX RT_FLOW | NATIVE_PASS | 1 | Bounded source/destination IP and port |
| WatchGuard Firebox | NATIVE_PASS | 1 | Safe text capture and field mapping |
| Cisco Umbrella DNS positional CSV | NATIVE_PASS | 1 | Neutral column labels; semantics not certified |
| Zeek data TSV row A | NATIVE_PASS | 1 | Neutral 5-column tab structure |
| Zeek data TSV row B | NATIVE_PASS | 1 | A second source, same structural grammar |
| Microsoft W3C-looking data-only row | NATIVE_PASS | 1 | Source-only Regex; no W3C schema claim |
| Cisco Snort IDS | NATIVE_PASS | 3 | Two real improved-prompt corrections |
| Fortinet synthetic PRI directly concatenated to date= | REVIEW_REQUIRED | 2 | Initial KV missed date and failed synthetic IP check |
| PAN-OS sample with unverified positional CSV layout | REVIEW_REQUIRED | 1 | Needs declared field layout |
| Cisco ASA one-off message ID | REVIEW_REQUIRED | 1 | Needs additional event/template coverage |
| Zeek separator/fields metadata-only | REVIEW_REQUIRED | 1 each | Missing complete data record |
| Microsoft W3C Version/Fields metadata-only | REVIEW_REQUIRED | 1 each | No event row |
| Windows Event XML | REVIEW_REQUIRED | 1 | Unsupported source grammar |

Cumulative sample-only v0.2 native results among the 15: **6 first**, **6 by second**, **7 by third**. The Snort first Regex inadvertently used a conventional capture name clock that triggered the date guard; its second was 259 characters, exceeding the 256-character limit; its third properly accepted and generated native files. The Fortinet second response refused unverified source prefix behavior instead of silently losing date. All successful new DRAFTs were labeled SAMPLE PASS (NOT GENERALIZED), with no independent source-disjoint manufacturer holdouts.

Harness: expanded_recovery_prepare_20261025.cjs, expanded_author_replies_20261025.py, expanded_recovery_replay_20261025.cjs. Evidence: private new-grammar-recovery/ directory.

## Native metamorphic and malformed-input replays

Against the actual seven downloaded new-grammar Ruby fragments, **21/21 synthetic source-value changes PASS** (IP, ports, method, action, URI, domain, Snort signature, Zeek UID/protocol) and **14/14 malformed records were rejected** rather than returning false-valid native callbacks. These mutations are NOT independent real manufacturer captures. Native harness: tools/qa/expanded_native_metamorphic_20261025.py. Evidence: new-grammar-native-mutations.json.

## Honesty and final scope

- Explicit role attribution: all new responses are **GPT-6 in the SAME conversation**, selected/authored for this task. There are ZERO independent externally authenticated OpenAI API or ChatGPT.com completions in this run. Previous actual API call was blocked with HTTP 429 credit_balance_exhausted. External-provider model generation rates remain UNMEASURED.
- Exactly two manually tested ChatGPT role behaviors: existing baseline copy/review and new source-supported recovery/refusal. No claim of blind model generalization or physical Stellar Cyber 7.0 native import, DP/sensor ingestion, production rollout or manufacturer semantic truth.
- Sample-only source success is not a production-readiness criterion. Keep nested-array output gaps and unsupported vendor positional schemas visible for a future evidence-led product decision; no speculative grammar patching.
- Private original logs, prompt/response text, screenshots, generated Ruby+CONF and full result JSON remain on dev-atlas, not in Git.
- Test code and summarized evidence in this QA Draft only. The accepted development version and main remain unchanged.
