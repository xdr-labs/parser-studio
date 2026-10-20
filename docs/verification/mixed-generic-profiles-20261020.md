# Bounded mixed Generic Structural profile verification — 2026-10-20

## Scope and current status

This work adds one explicit, versioned combination of the existing
`syslog_prefix_kv` and `leef2_implicit_tab` Generic Structural profiles. It starts
from main `ec6df2473612e5dd0cb23de6209801a7dda1548a`, after the completed PR #121
continuation. It is a bounded support extension; the completed continuation is
not reopened or described as missing its accepted behavior.

The isolated development worktree is
`/home/aella/parser-studio-mixed-generic-profiles-20261020`, on branch
`feat/mixed-generic-profiles-20261020`. The original worktree and its uncommitted
changes, other worktrees and previous deployment are preserved. The active
product remains Auto Parser and ChatGPT Assisted Parser.

Implementation and local qualification are complete on the isolated candidate.
This document records evidence available before freezing the source commit.
Exact-candidate CI, main incorporation and development/public-address receipts
are recorded after that commit in the work packet linked below.
The gate table distinguishes observed local results from subsequent promotion gates. The
[current roadmap ledger](../06_ROADMAP_AND_ACCEPTANCE.md) and
[Issue #1 work packet](https://github.com/xdr-labs/parser-studio/issues/1#issuecomment-6287789712)
provide the continuation context.

The saved next-chat checkpoint was resumed with all 23 original source hashes,
Git HEAD/status and existing worktree inventory verified unchanged. The first
affected Chromium run exposed two automatic-transition failures. The corrected
run completed all eight scenarios with the original assertions unchanged.

## Reproduced baseline and fixture correction

The decisive baseline contains a Syslog description followed by **four** KV
fields and an original implicit-TAB LEEF 2.0 event. On the base implementation,
automatic draft construction returns `null` for the combined source in both
orders. The two negative feature probes are saved as
`baseline-profile-required-result.json` and
`baseline-profile-required-vitest.json` in the evidence directory below.
They establish that no existing single additional profile covers that complete
batch while preserving both required grammars.

An earlier diagnostic used a Syslog event with five KV fields. That event was
already handled by a V15 route, so the existing LEEF profile could cover the
batch. It was not evidence of a product failure and is not counted as the
reproduced mixed-profile limitation. The corrected four-key fixture is the
acceptance input for the extension.

The positive fixtures also include quoted Unicode Syslog values, padded LEEF
header fields, an optional initial TAB before the first LEEF extension key,
five TAB-separated extension values, padded Unicode values and a URL containing
an additional equals sign. Both event orders must preserve the same complete
set of source fields and the original sequence of events.

## Explicit contract

| Contract surface | Required behavior |
| --- | --- |
| Project extraction | `format: "generic_structural"` with scalar `genericStructuralProfile: "syslog_prefix_kv_leef2_implicit_tab_v1"`. No plural profile metadata is introduced. |
| Recipe projection | The `parse_generic_structural` stage carries the same scalar `profile`. Project and Recipe must agree exactly; missing, mismatched or unknown profile values are rejected. |
| Existing grammar advertisement | `authoring.genericStructuralGrammar` remains `GENERIC_STRUCTURAL_ULTRA_COMPILER_V15`. Existing no-profile projects retain their routes. |
| Existing profile advertisement | `authoring.genericStructuralProfiles` remains exactly `["syslog_prefix_kv", "leef2_implicit_tab"]`, in that order. The new value is not appended to this array. |
| Combined capability | Optional boolean `authoring.genericStructuralMixedProfileV1` advertises the new scalar profile. The updated Backend sets it to `true`; the updated frontend requires exactly `true` before requesting this profile. |
| Persistence | Project JSON, Recipe projection, browser versions and imported drafts reuse the existing scalar metadata contract. Generic and mapping-only edits retain it; explicit incompatible format preparation clears it. |
| Validation | A profile on a non-generic extraction format, an unknown version or an invalid capability shape is rejected. Existing source-path, mapping and destination-collision rules remain in force. |

The separate capability flag preserves compatibility with an already-loaded
older frontend, whose validation accepts only the two original names in the
legacy array. Such clients ignore the added authoring key and continue using
their existing profiles. A new frontend connected to an older Backend, or one
advertising the flag as false, enters the existing
`BACKEND_PROFILE_UNSUPPORTED` blocked flow for the combined profile. Source and
parsed fields remain available, and the explicit support retry requests fresh
capabilities. A malformed flag is a contract error rather than an unsupported
profile success.

The actual frontend capability parser from previous source
`19f3f5e7e82717d4c48a5ad8a24e599e84110201` accepted the actual new Backend
capability response for no-profile projects and both existing single profiles.
This is observed capability-contract compatibility; it is not a completed
browser flow against the new candidate.

## Parsing, mapping and preservation

Automatic draft construction still requires a fully supported single-line
batch within the existing event bounds. It checks every record and prefers an
existing single profile whenever that profile covers the complete source. The
combined scalar is selected only when the bounded combination is needed. This
does not create arbitrary profile composition or a general mixed-stream
compiler.

Under the combined profile, an event starting with `LEEF:2.0|` belongs to the
strict implicit-TAB LEEF parser before any legacy KV fallback. An invalid
implicit-TAB header or value sequence produces an extraction error; it cannot
be approximated by an older KV route. The Syslog extension uses the same
already-qualified prefix/KV routine, and the unchanged V15 routes remain
available for their existing records. Standalone profiles keep their existing
semantics.

The automatic draft includes the union of safe leaf fields from all records,
excluding internal mode/delimiter fields and duplicate raw-source mapping
entries. Exact original text remains in the extraction source data. Header
spelling, quoted values, Unicode, literal escapes, padded values and row order
must survive preview and generated Ruby execution. Additional-profile drafts
whose complete union exceeds 60 mappings remain in review; the extension does
not silently truncate fields or increase the existing bounds.

Distinct source paths can suggest the same official normalization destination.
For example, `generic.kv.src` and `leef_extension.src` can both suggest `srcip`.
The combined automatic draft keeps ambiguous paths as separate vendor fields
instead of assigning either path priority. Unambiguous high-confidence
suggestions can still be applied. Backend destination-collision rejection is
unchanged; this extension does not infer conditional normalization semantics.

## Automatic transition correction found in real Chromium

The first affected browser run completed six cases and failed the two positive
mixed-source journeys at the initial analysis summary. The strict compiler
could preserve both events, while the earlier source analyzer classified the
four-key Syslog record as PARTIAL. Auto Parser required every upstream status
to be SOURCE_PARSED before adopting a draft, leaving the novice at an
unnecessary manual recovery step. The browser assertions were not weakened.

The automatic transition now checks a bounded compiler candidate against the
same source review. Source identity, event count, event order and literal UTF-8
slices must agree, and all candidate events must normalize successfully.
A PARTIAL diagnostic is resolved automatically only when its actual field tree
comes from one of the strict additional grammar helpers and an explicit
profile was selected. Partial legacy routes, RAW_ONLY/STRUCTURED_EMPTY events,
stale or misaligned records, metadata and unsupported framing remain blocked.
The existing manual candidate builder and source-container gate are retained.

Eleven focused source-review tests cover both source orders and LF/CRLF,
legacy partial preservation, stale or reordered records, invalid UTF-8 ranges,
metadata/framing rejection and the previous complete legacy behavior.
The unchanged real-browser positive journeys then reached full field review,
22 exact source paths and both downloaded parser files. The reverse-order
journey also verified local save, reload, restore and re-save before analysis.
The malformed LEEF journey retained its original input and emitted no parser
POST or download. Success and rejection screenshots were visually inspected.

## Qualification evidence

The saved evidence root for this extension is:

`/home/aella/.local/state/parserstudio-mixed-generic-profiles-20261020`

| Gate | Observed status before source freeze | Evidence / remaining action |
| --- | --- | --- |
| Corrected base behavior | Both event orders return `null`; two reproduced negative feature probes | `baseline-profile-required-result.json`, `baseline-profile-required-vitest.json`. The earlier five-key diagnostic is not counted as a failure. |
| Focused frontend | Interim 112/112 PASS, including two temporary baseline probes | `frontend-focused.json`. The two temporary probes were saved by hash and removed from the worktree. The final committed candidate's full CI result remains separate; 112 is not a final permanent-suite count. |
| Actual generated Ruby/helper qualification | 91/91 PASS | `backend-focused-ruby.log`, `backend-focused-ruby-result.json`. Includes the generated-artifact callback and the focused existing grammar coverage. |
| Backend build | PASS | `mixed-backend-build-result.json`; no Backend source changes followed the saved qualification. Source/build hashes are recorded in `qualified-build-source-provenance.json`. |
| Web build | PASS after the automatic-transition correction | `adoption-check-results.json` and `adoption-web-build.log`; earlier test-only typing correction evidence is preserved. |
| Correction and language coverage | 11/11 PASS | Five UI, three language-policy and three multilingual cases passed at the handoff checkpoint. |
| Previous frontend / new Backend capability contract | PASS | The actual previous frontend capability parser accepted the actual new Backend response for both single profiles and no-profile projects. Browser execution remains separate. |
| First affected local Chromium | 6 PASS / 2 FAIL | `mixed-affected-browser-summary.json`: both mixed positive cases stopped at the analysis summary; no skipped or flaky tests and no top-level errors. This is preserved RED evidence. |
| Corrected focused source/frontend checks | 44/44 PASS | `adoption-focused.json`: 11 source-review guards, 15 mixed-profile contracts, three existing auto-draft, three multilingual and 12 source-container cases. |
| Corrected English authoring policy | 3/3 PASS | `adoption-language-result.json`. |
| Corrected Chromium against local services | 8/8 PASS | `adoption-affected-browser-summary.json`: 2026-10-20T13:49:28.894Z, 62.246 seconds, one worker, zero retries, zero skipped/unexpected/flaky cases and no top-level errors. Three mixed cases plus three original-source cases, one format transition and one two-independent-user scenario. |
| Exact-candidate CI | Recorded after this source commit | The active work packet pins the source/tree, exact CI run and final conclusion before promotion. The tracked roadmap lane requires all 11 cases and rejects top-level errors. |
| Main incorporation | Recorded after successful candidate CI | The active work packet records the actual remote main hash and its tree relationship to the qualified source. |
| Development application and public-address E2E | Separate application receipt | The active work packet records the full payload, old/new hashes, backup, normal authoring restart and public affected-eight result after actual application. Python bytes and the multipass PID must remain unchanged. Prior deployment evidence is not proof for this extension. |

The focused checks cover profile selection in both source orders, preference
for an existing single profile, complete mappings, ambiguous destination
preservation, schema and capability validation, scalar persistence and source
fidelity. The generated Ruby checks compile the actual downloadable artifact,
verify its bytes and manifest hashes, evaluate that exact Ruby source and call
its public parse callback. Complete independent expected field trees are
compared for the padded Unicode and quoted-value fixtures.

Malformed controls and unknown text retain extraction errors, including
duplicate LEEF keys, an invalid delimiter/header, a trailing TAB, an
unterminated Syslog quote and an invalid priority. The LEEF ownership regression
first demonstrates that the malformed input can reach a permissive legacy KV
route without the selected profile, then verifies rejection under the combined
profile. The callback checks require one result per input event, including a
static extraction error for rejected events; event loss is not treated as a
successful parse.

These checks execute Ruby artifact code. They do not load Fluentd or the
listener configuration and do not contact a target. Generated artifacts retain
`status: "DRAFT"`, `engineVerified: false` and `targetImportVerified: false`.
Passing the callback tests does not qualify a live listener, proprietary
loader or manufacturer-specific behavior.

## Completed prior packet and unchanged boundaries

The previous continuation source
`19f3f5e7e82717d4c48a5ad8a24e599e84110201` passed CI run #39416579705,
merged through PR #121 into the base main above and completed separate public
Chromium qualification at **109/109 PASS**, ending at
2026-10-20T12:59:55Z. The saved local 109-case browser, 113-case frontend,
84-case Ruby and 93-case Python results belong to that earlier packet's
pre-compatibility source `cb7cec246e5dd4fbd4269369b5d3c338c5692740`.
They are not relabeled as local qualification of the later `19f3f5e7` source
or as qualification for this extension.
The [earlier verification record](roadmap-followup-20261020.md) is preserved.

The extension changes only the explicitly bounded Generic Structural
combination and its authoring/persistence contract. Original-wire Audit, CRI,
Docker, W3C, Zeek and transport compiler gaps remain separate optional work.
Manufacturer/firmware oracle research and compilation of every stream format
are outside this packet. Owner visual acceptance remains separate.

Production deployment, releases, authentication or permission changes, DP
upload/apply, sensor operations and Interflow readback remain outside scope.
Development application does not authorize any of those actions.
