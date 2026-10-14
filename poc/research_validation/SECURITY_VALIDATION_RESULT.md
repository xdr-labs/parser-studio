# Independent PoC — Security-System Source Validation

## Authoritative decision

**Keep the current main security engine at `c2f464444a7aa899bd8b251507234720e4cbdde2`, using `security_source.parse_security_source`. Add only the separately verified declared-metadata document capability for further integration consideration. Do not replace the whole engine with this lane's CEE or H1 implementation.**

The main lane added CEE security framing while this independent experiment was running. Its current security entry point is NOT the historical `source_parse.parse_source` function. We acquired an isolated exact-current snapshot and repeated the same-source comparison against the actual security API. The earlier CEE 0-to-100 result against `2fee28f` is valid historical evidence, but **is not an additional gain over the current main PoC**.

Primary scope: ordinary security-system logs, including AWS WAF, Suricata IDS/IPS, FortiGate firewall/IPS, and Zeek network-security records. Message, signature, payload and request content remain native fields, not sentence-mining targets. No prose cases are pooled into these KPIs. Dictionary normalization and masking optimization were not performed.

## 1. Actual current-PoC comparison

Correctness requires original native field identity, typed value and exact source byte span. Complete source-tree equality is also checked, so empty containers are not silently lost.

| Source / evidence class | Evaluated records | Expected fields | Current security PoC | Current + declared metadata |
|---|---:|---:|---|---|
| AWS WAF upstream parser fixtures | 5 | 156 | 156 TP, 0 FP/FN | Identical |
| AWS WAF first-party documentation JSON examples | 8 | 268 | 268 TP, 0 FP/FN | Identical |
| Suricata EVE source fixtures: alert, DNS, HTTP, TLS, flow and metadata | 66 | 1,709 | 1,709 TP, 0 FP/FN | Identical |
| FortiGate source fixtures, versions 6.2/7.2/7.4 and regression variants | 208 reference-scored of 213 inputs | 5,715 | 5,715 TP, 0 FP/FN | Identical |
| CEE + Syslog deployment forms derived from 66 Suricata bodies | 264 derived records | 6,836 body fields | 6,836 TP, 0 FP/FN | Identical |
| Zeek explicit source-schema data rows | 127 | 3,132 | 0 TP, 44 FP, 3,132 FN; F1 0% | 3,132 TP, 0 FP/FN; F1 100% |

These scores qualify these specific source fixtures, not all products, versions, input sizes or production traffic. The 264 transport forms are four transformations of 66 already seen bodies, not 264 independent production captures. They are kept separate from original inputs and never inflate original-source accuracy.

**IPS subsets are explicitly checked:** FortiGate `subtype=ips` has 7 records / 292 fields; Suricata `event_type=alert` has 24 records / 748 fields. Both current and composed candidates preserve every scored field and byte position. These are subsets of the table, not additional records.

**No extra WAF/IPS accuracy gain was demonstrated over the latest main engine.** The current native JSON/KV and security-envelope decoders already handle the measured examples. Additional generic delimiter or whole-CEE replacement is not justified by this corpus.

## 2. Honest input and completeness accounting

The unmodified security corpus has **284 records**. All 284 remain preserved, and the selected document composition leaves all 284 complete output structures exactly unchanged.

Of those inputs, 279 have independently referenceable fields. Five NUL-corrupted inputs remain raw-only controls, not successful field extractions. One of the 279 has a malformed quoted tail: only the independently identifiable prefix is scored, and the record remains PARTIAL. Two other complete-reference records retain conservative PARTIAL status for bare empty values. The current engine therefore reports **276 fully correct SOURCE_PARSED records out of 284 inputs**, not 284 complete parsing successes. All scored field occurrences, including those in the explicit partial prefix, agree.

The first-party WAF page has **10 code blocks**. Eight are valid JSON examples and are field-scored. Two non-parseable snippets are retained and explicitly counted outside the field oracle; neither becomes a false complete result. Documentation placeholders are not unmasked production evidence.

The Zeek corpus has **187 physical lines = 127 data + 60 reference metadata/preamble**. Six BTest provenance preambles remain explicit RAW_ONLY records; they are not silently dropped or counted as data-field successes. Source-declared header lines are separately retained in the document ledger. The prior heldout subset of 80 records / 1,976 fields also completed at 1,976 TP, 0 FP/FN with metadata import.

## 3. What was actually added

`security_document.parse_security_document(records, base_parser=...)` adds a document-level source-schema reader around the caller's current security parser. Only an explicit supported separator declaration admits the metadata reader. It uses native source `#fields` names and exact scalar column boundaries, not Dictionary semantics or guessed field meaning. All ordinary events still use the current main security API. This avoids reviving the previously rejected H1 KV replacement.

Both baseline and composition receive the same complete physical input, including source headers. The gain is the ability to use metadata that was already in the source document; it is not an LLM or unlabeled semantic-learning gain.

The existing `candidate.py` malformed-metadata exception guard and `benchmark.py` preamble accounting fixes were found applied in preserved WIP and were audited, tested and finalized. The previous narrow tool denials are **resolved for this checkpoint**, not current blockers.

## 4. Rejected independent replacement

The separately implemented `security_envelopes.py` passed its authored tests against the older engine. It nevertheless lacks the current main adapter's plain BSD Syslog form when used as a whole replacement.

On the expanded 264 derived security forms, the actual main adapter extracts all 6,836 body fields. The independent whole replacement gets 5,127 TP / 1,709 FN, F1 **85.71%**, and only 198/264 exact records. **Reject wholesale replacement.** The selective document composition retains the actual main adapter and preserves all 264 forms.

This negative finding is retained; an old-baseline improvement is not allowed to hide a current-baseline regression.

## 5. Oracle audit and verification

An initial KV oracle incorrectly applied shell quote concatenation to one unquoted vendor value containing interior quote characters. The existing parser had correctly preserved the source. The oracle was corrected, independently tested on authored bare-quote/path cases, and rescored without changing parser predictions. The unchanged prediction SHA and discarded 1 FP / 1 FN interpretation are recorded in `security-oracle-audit.json`. This is an oracle correction, not an engine improvement.

- Independent validation suite on exact current runtime modules: **57/57 PASS, no skips**.
- Scoped current-main JSON/KV/structured/security regressions: **58/58 PASS, no skips**. Two initially unavailable fixture-dependent tests were rerun after copying already authorized local fixtures into the isolated snapshot; no source worktree or network changes were needed.
- Exact-current source-module bytes were checked against Git before test execution.
- Same-source original and derived predictions were persisted before independent scoring; only aggregate evidence and hashes are committed.
- No main worktree files, product UI/backend, hosted LLM, DP, sensor, credentials, production, merge or release were modified.

Generic repository CI is tracked separately on the research commit. It is not a substitute for the local Python tests, nor does it qualify native Ruby/CONF or Stellar deployment.

## 6. Reproduction and evidence

Prepare the isolated current baseline without touching the main worktree:

```bash
mkdir -p poc/research_validation/.cache/current-c2f4644
git archive c2f464444a7aa899bd8b251507234720e4cbdde2 poc/vendor_engine \
  | tar -x -C poc/research_validation/.cache/current-c2f4644
```

With the SHA-pinned, already approved local source caches present:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/run_security_tests.py
PYTHONDONTWRITEBYTECODE=1 python3 poc/research_validation/verify_current_security.py
```

Authoritative current artifacts: `final-current-security-summary.json`, `security-current-tests.json`, `current-main-regression-tests.json`, `security-source-manifest.json`, `aws-waf-official-manifest.json`, and this report. Historical `security-frozen-summary.json` / `security-envelope-summary.json` compare the older `2fee28f`; do not present them as latest-current gains. `zeek-resumed-summary.json` preserves the earlier 80-record subset, while the final-current report scores all 127 data rows.

Raw source and documentation examples remain ignored and are not redistribution-approved product assets. Public fixture sources are regression examples, not verified customer production captures. Redaction status is unassessed unless explicitly documented; no hidden values are reconstructed.

## 7. Remaining security-only research order

1. Independently extend commercial IPS/NGFW CEF/LEEF and vendor-version/rare-subtype coverage, preserving all native fields and original bytes.
2. Fix only failures measured on those sources. Keep the current main security adapter and qualify additive primitives, not wholesale alternatives.
3. Validate document/stream schema rotation and mixed-source admission before adopting metadata/layout primitives in the main PoC. Preserve the known H2r source-drift limitations; prose is only a separate negative guard, never the primary KPI.
4. Consider main-engine integration only after independent evidence and coordination; product/native/DP/sensor/release remain separate gates. Dictionary mapping and masking stay later.

User action required: **none**. No current tool, host or permission blocker was identified.

Reference contracts: AWS WAF logging fields and log examples; Suricata EVE JSON documentation with optional `@cee: ` prefix; pinned Elastic integration fixtures and pinned first-party Zeek test outputs. Source URLs, revisions and hashes are in the manifests.
