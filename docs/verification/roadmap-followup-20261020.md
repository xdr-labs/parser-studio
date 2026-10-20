# Roadmap continuation verification — 2026-10-20

This continuation implements the finite DRAFT-1, RECOVERY-1 and BATCH-1 work
packet on top of main `00e783520c005a96b37b5fbf5eb4ad81c74381a6`.
The active product remains Auto Parser and ChatGPT Assisted Parser.

The [Issue #1 work packet](https://github.com/xdr-labs/parser-studio/issues/1#issuecomment-6287789712)
records the frozen source/tree, pull request, exact-candidate CI result and
development rollout outcome. The earlier main/public baseline remains in
[the previous completion record](https://github.com/xdr-labs/parser-studio/issues/1#issuecomment-6286114104).
Passing local tests alone does not assert that main or the public service has
already changed.

## Implemented behavior

| Area | Result and contract |
| --- | --- |
| Strict RFC5424 SD and free-form MSG | A valid RFC5424 envelope with structured data and an otherwise unstructured MSG can use the existing raw-body compiler. The exact SD text and MSG survive through review, mappings and downloaded files. Malformed structured bodies retain review/error states. |
| Syslog description followed by KV | The explicit `syslog_prefix_kv` Generic Structural profile accepts a bounded, fully consumed RFC3164 prefix and safe key/value sequence. It retains the description, source and complete values, without a manufacturer-specific rule or invented year/timezone. |
| Original implicit-TAB LEEF 2.0 | The explicit `leef2_implicit_tab` profile retains the original header, TAB boundaries, Unicode, literal escapes and padded values. A selected LEEF family is handled before the older general KV route; a rejected event cannot fall back to that approximation. The original fixture needs no delimiter rewrite before parser download. |
| Explicit grammar persistence | The additional profile is represented in project, recipe, import and browser-version contracts. Capabilities advertise the finite supported profiles. Unknown/mismatched profiles and older backends without the required capability are rejected. V15 projects with no extra profile retain their behavior. |
| Partial text recovery | Generic quoted bracket labels retain exact values, UTF-8 spans, repeated and empty occurrences, and previously recovered network atoms. Re-analysis does not duplicate zero-length occurrences. Residual prose remains PARTIAL. |
| Novice repair review | The problem inspector and assisted prompt expose recovered source values and the next review steps. An incomplete proposed repair is blocked. Reusing the source as independent verification is blocked; distinct held-out examples must pass before the reviewed recipe is applied. |
| 100–400-event analysis | The UI reports actual request/verification phases, source bytes and elapsed time, and offers cancellation. Cancellation, source edits and replacement runs prevent late results from adopting an obsolete draft. No percentage, truncation or success is fabricated. |
| Format transitions | Explicit preparation of a non-generic format clears incompatible additional-profile metadata. Generic and mapping-only edits preserve it. Browser save/restore, recipe exchange and subsequent review enforce the same contract. |

All new grammars are structural and finite. No general prose catch-all, new
vendor-specific regular expression, silent mapping truncation or target-ready
claim was added. A batch requiring two incompatible additional profiles remains
in review. Invalid syntax and undeclared schemas still require a user decision.

## Local qualification

The final working-tree qualification is preserved in
`/home/aella/.local/state/parserstudio-roadmap-followup-20261020`.
Before commit, all 66 checkpointed source/configuration file hashes matched
`handoff-worktree-snapshot.json`; repository documentation is finalized after
that comparison without changing the qualified application source.

| Gate | Observed result | Evidence |
| --- | --- | --- |
| Final Chromium candidate | 109/109 PASS; 0 failed, skipped or flaky; top-level errors empty; 353.8 seconds | `final-candidate-browser-summary.json`, `final-candidate-browser.json` |
| Final affected frontend | 113/113 PASS across 8 files | `precedence-frontend.log` |
| Final generated Ruby/helper/dispatcher | 84/84 PASS, 0 skipped | `precedence-native.log` |
| Full Python suite | 93/93 PASS | `final-python-corrected.log` |
| Final web and backend builds | Both PASS | `qualified-web-build.log`, `qualified-backend-build.log`, `precedence-and-build-results.json` |
| Earlier full frontend, before the last LEEF precedence addition | 997/997 PASS across 125 files | `final-frontend-units.log` |
| Earlier full product-scoped authoring backend, before that addition | 429/429 PASS, 0 skipped | `final-backend-authoring.log` |

The final browser run began at 2026-10-20 10:26:06 UTC on the current
working-tree candidate based on `00e783520c005a96b37b5fbf5eb4ad81c74381a6`.
The two earlier full-suite results are not promoted to final exact-HEAD
full-suite results. The committed candidate's CI is recorded separately in
the work packet. Four historical external/Drain3 backend cases remain
outside the explicitly scoped authoring gate.

The deterministic sender suite includes the existing offline/loopback sender
checks. Its URL-field assertion now compares the parsed query value: a changed
address such as `192.0.2.108` must not fail merely because it contains
`192.0.2.10` as a substring. The sender implementation itself was not changed by
that assertion correction.

### Actual browser coverage

The continuation gate executes eight Chromium cases with real local Multi-Pass
and authoring services: the three original source-to-download paths, 100- and
400-event source-preserving analysis, cancel/edit/late-response handling, the
complete reviewed partial-text repair and download, and generic-to-Zeek/CSV
preparation followed by browser version save and review. The race case delays
delivery of an actual service response to exercise the obsolete-result guard.

The wider final browser run adds the existing 100 authored corpus cases and
the two-user acceptance scenario. That scenario uses two independent browser
contexts, different authoring paths, separate saved versions and actual parser
downloads. It counts as one Playwright test containing two user journeys.

The 100-case corpus verifies original-source retention, meaningful analysis or
review, and available review/map transitions. It is not 100 manufacturer
attestations or 100 native-validated parser downloads. The explicit three new
source cases and reviewed-recovery case separately assert actual Ruby/CONF
downloads.

### Native runtime evidence boundary

The backend suite executes the additional helper grammars in actual Ruby 3.2.3.
It also compiles the project using `compilePair`, evaluates that exact generated
Ruby fragment and calls its public parse callback. The checks compare original
source, complete field trees, normalization mappings, literal spelling and
rejected-profile outcomes. The precedence regressions include spaced headers,
five TAB-separated values, Unicode and padded values that the legacy KV route
previously approximated incorrectly.

This is Ruby artifact execution. It does not load Fluentd, the listener CONF or
a Stellar target. `engineVerified` and target verification remain false unless
their independent gates are actually executed. Generated files remain DRAFT
artifacts with the existing honest compatibility labels.

## CI and application

The existing quality workflow keeps its full frontend and product-scoped
authoring gates and existing affected browser suites. It now also executes the
quoted-label/LEEF Python cases and the explicit eight-case continuation
Chromium gate. Historical external backend tests and retired Wizard tests are
not relabeled as current product passes.

Development application requires the qualified web build, authoring build and
schemas/templates, and the changed Python structural-label module. It therefore
requires restarting both existing preview services after hash-checked backups;
the old web-only operator is insufficient. The work packet records the actual
application and public verification result, or an observed operator privilege
block if normal service restart cannot be authorized in the execution session.

Public development hosting, authentication and routing boundaries are preserved.
DP upload/apply, sensor operations, Interflow readback and production/release
remain outside this work packet. Manufacturer/firmware oracle research and new
wire-format compiler contracts remain separately scoped future work.
