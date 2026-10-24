# Security-product ChatGPT first-answer A/B and native defect qualification

Date: 2026-10-24. Reproducible private evidence directory:
`/home/aella/.local/state/parserstudio-security-prompt-ab-20261024`.

## Scope and interpretation

The intended population is **security-product logs** (firewall, IDS/IPS,
WAF, NDR, EDR/XDR, security DNS/proxy, identity and cloud security).
Old HDFS/Hadoop/Spark/ZooKeeper application/infrastructure samples are
outside the new product acceptance population.

The 13 initial comparable *vendor-documented* FortiGate, Suricata and
Zeek sources all already had a compiler-reviewable parser baseline in
both versions. Both variants generated exact original source prompts,
and the PR #157 variant included source-event diversity and previously
extracted field-preservation evidence in all 13 where applicable.
These 13 examples are **not** new-parser model-generation successes.

To test *FULL_RECOVERY*, eight separate security-solution families used
source-disjoint synthetic permutations of explicitly marked project test
fixtures: Cisco Snort, Juniper SRX, WatchGuard Firebox, Cisco ASA,
Palo Alto Networks PAN-OS, F5 ASM, Cisco Umbrella and Zscaler ZIA.
Each training prompt included four events and each independent holdout
two events; synthetic variants are **not manufacturer firmware captures**.

## Same-response A/B and what it does NOT establish

- Copied 8 before-PR157 and 8 after-PR157 prompts in **real Chromium**
  from isolated Vite candidates, both with existing authoring and
  Multi-Pass services. Both versions generated exact source/hash/
  event identity. After PR157 the event-coverage evidence was present
  in all eight cases.
- Composed **eight first candidate plans in this ChatGPT conversation**
  and froze 16 text answers *before* any candidate execution. Each
  before/after pair used the **identical** answer bytes, with the exact
  source identity mechanically bound. One is a justified
  `REVIEW_REQUIRED` (unlabeled PAN-OS CSV columns), the other seven
  are strict ParserRecipe JSON.
- Both before and after: **7/8 first JSON imports accepted**,
  **4/8 passed source-plus-holdout browser comparison**,
  **3/8 failed due to insufficient grammar for actual examples**,
  **1/8 safe refusal**.
- There was **no changed pass/fail outcome between the two prompt
  variants when the submitted answer was fixed**. This is expected
  by design and CANNOT measure improved generative response quality.
  **Separate independently invoked external ChatGPT/provider calls: 0**.
- Prior to the product defect correction, the four holdout-positive
  cases failed to generate downloadable Ruby/CONF. Do NOT count
  those as fully functioning parsers.

## Actual product defects found and corrected

1. **Order-sensitive Recipe equivalence check.** The browser compared
   `JSON.stringify` output of the validated compiler-owned recipe
   against the user-pasted JSON. Identical JSON objects with different
   property order were rejected. A canonical key-sorted JSON comparison
   already used by the receipt verifier now governs exact recipe
   equality, stage edits and the unchanged-baseline decision.
   Source digest, schema, order of stages/arrays, field types and
   no-regression guards are unchanged. A negative test still rejects
   a source identity mutation.
2. **Ruby CSV TAB compatibility.** Ruby 3.2.3's
   `CSV.parse_line(..., col_sep: "\t", strip: true)` raises
   `ArgumentError`. The compiler now emits the compatible strict
   `strip: (separator != "\t")` option **only for explicitly selected
   TAB CSV or TAB-enabled mixed CSV**. Other projects retain their exact
   previously approved template bytes and SHA-256, including the
   historical POC template allowlist. `liberal_parsing` remains false;
   malformed CSV values must still be rejected.

## Retested evidence

After the canonical comparison correction, the **unchanged frozen**
source-family JSON responses were replayed through actual Chromium:

- 7/8 JSON strict import accepted; one source-justified review refusal.
- 4/8 original+holdout parser drafts generated as real downloadable
  Ruby + CONF pairs: Snort, F5 ASM, Cisco Umbrella, Zscaler ZIA.
- Three first recipes (Juniper, WatchGuard, Cisco ASA) still failed
  independent holdout. They remain FAIL, not silently repaired.
- The four **actually downloaded after the compiler correction** Ruby
  parser fragments were executed with Ruby 3.2.3 over all four training
  plus two holdout records per family: **24/24 callbacks,
  0 native exceptions, 48/48 independently compared source field
  values exact**. This is bounded fixture-local evidence, not
  semantic correctness for every manufacturer firmware revision.
- Stellar Cyber 7.0 native target install, sensor reception and
  production/DP actions were not performed.

## QA gate and limitation

- The browser regression for an intentionally noncanonical property
  order now passes strict import → different logs → download.
- Exact scoped frontend Vitest: **1,168/1,168 PASS** in 150 files.
- Scoped backend CSV/compiler/mixed-format tests PASS. Complete
  backend suite encountered legacy POC and Drain3 environmental
  failures: 473/485 PASS in that all-suite attempt. An **unchanged
  before-fix worktree independently reproduced the same four
  legacy POC failures**; do not misattribute those to this code
  change. The entire backend suite remains NOT ALL GREEN.
- Current GitHub Actions for ancestor PRs are also blocked by
  organization billing before workflow steps; do not claim CI PASS.
- Security product model-first-response *generative uplift percentage*
  is **NOT MEASURED**. The observed 0/8 → 4/8 end-to-end artifact
  recovery in the same frozen answers is due to fixing two **product
  defects**, not evidence that PR157 prompts cause ChatGPT to author
  better first answers. Do not extrapolate this synthetic fixture
  rate to a population-wide model success rate.

## No unrelated changes

No additional model integration, new user mode, direct cloud AI transfer,
generic infrastructure-log scope expansion, deletion of prior parser
safety checks, production deployment, live Stellar target operations
or automatic repair of failed AI answers.
