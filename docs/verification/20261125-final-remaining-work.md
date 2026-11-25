# Final remaining work and end of development (2026-11-25)

Scope: PR #316, range 81760c2..d4e98cb (follows `20261125-final-root-cause-review.md`). Owner directive of
2026-11-25 ("final remaining work and end of development"): the 14 golden cases that stop and the 11 unmapped
official fields are accepted as product limits; no vendor grammar and no redesign. Remaining work: the parse
verdict and ChatGPT route of text that mixes bare tokens with key=value pairs, manual mapping on a parser with
several event types, a check of the audit residuals for real value loss, a final independent audit, the final
verification and the end-of-development statement. No main merge, no deployment, no Stellar Cyber DP test.
KNOWN_TEMPLATES and the owner approval constants are unchanged.

Generated Ruby is unchanged in this range (battery step `tplset` passes at d4e98cb), so the digests awaiting owner
approval are the same as before:

| Digest | Value |
|---|---|
| Ruby template set (`contracts/ruby-template-set.v1.json`) | `bb653102732e01001b5a30d4ac05b14917bb43dbe84eb484c88c409b261e0e8a` |
| POC template (`pocTemplateSha256`) | `2b65c2706ebe7855cfd5a8a2086404bf5fda1ca65483c2d65437f9911dfd1466` |

## Result in one paragraph

The two product defects the owner named are fixed in the shared code, each with tests that failed before
(1e909af). A separate executor audited 6c6ebd2, 9c99189, 0688094 and 1e909af and found six defects in scope; all
six are fixed (d4e98cb) and a second separate executor confirmed the fixes and found no major regression. The
corpus metrics at d4e98cb are identical to the baseline. Within the product scope the development work is
complete. Template approval and release readiness are a separate state and are not reached: they wait for the
owner (section "Completion statement").

## 1. Parse verdict and ChatGPT route (1e909af, d4e98cb)

Defect: `evt=flow_open fragmented client=... verdict=permit` behind a Syslog header was adopted with a reading that
keeps the whole body as one message. The sample was reported as structurally parsed, no pair was extracted, no
ChatGPT route was offered, and a runtime line with one more pair was read in another shape.

Shared rule (`buildSourceReviewedBoundedDraft`, no grammar and no log-specific condition): the bounded compiler's
reading of an event is adopted only when

- it does not hold key=value pairs as message text (two or more pairs that start the text or follow white space,
  `;` or `,`), and
- the same event with one more key=value pair at its end is read the same way: same reading mode, every value
  still under its name.

Otherwise the event stays with the first scan. The screen then says "Values found in 2 of 2 log events" and
"Fields extracted - parser rule needs review", Review Fields is disabled and Fix with ChatGPT is offered. Free
text, prose with one key=value token and plain space-separated pairs are adopted as before. The values the first
scan found stay ("Values found in 2 of 2 log events"). The verdict is taken where it was taken before: the journey
goes on only when the browser preview and the server (Python) analysis both read the event, and the downloaded
Ruby parser was run on the same lines.

Chromium with the real backend and Multi-Pass, then the downloaded parser on Ruby 2.4.9
(`tests/kv-bare-token-verdict-20261125.spec.ts`, clean d4e98cb): not reported as parsed; the prompt holds the exact
events; a lossy reply is refused; a lossless reply is applied; 6 lines give 5 events with every value and 1 error
record. The error record is the runtime line with one more pair (`zone=dmz`); it keeps the complete original text
in `parser_raw_msg`.

## 2. Manual mapping on a parser with several event types (1e909af, d4e98cb)

Map Fields shows one event type at a time with the screen of a single-type parser (`EventTypeMappingReview`:
`projectFamilyDraft` on the records of the chosen type, the existing `NormalizationMappingReview`). A change is put
back into that type only (`applyFamilyMappingEdit` in `familyScopedAssist.ts`). No new mapping engine and no new UI
framework.

| Requirement | Behaviour |
|---|---|
| view per event type | selector "Mapping event type"; the count is the matches of the type |
| add, change, remove, choose an official destination | the controls of the single-type screen |
| shared and per-type matches | a match every type shares stays shared; an edit of another match is written to the chosen type |
| edit a match ChatGPT proposed | an applied ChatGPT match is a match of the type and is edited on the same screen; ChatGPT mapping keeps its own event type selector (the manual spec edits automatic matches; this combination has no Chromium test of its own) |
| one destination written twice in one event | refused with the reason (official fields and vendor field names, names another event type carries included); the typed text stays, the change is applied when the name is free, Continue is held meanwhile |
| other event types | unchanged, carried matches kept |
| final recipe and Ruby | the downloaded parser follows the edits |

Chromium, then Ruby 2.4.9 (`tests/map-fields-event-type-manual-20261125.spec.ts`, clean d4e98cb): in the JSON type
a match is removed (`src_ip`), one is changed (`dst_ip` to `srcip`), a second write of `srcip` is refused, a vendor
field is added and named key by key (`sensor_bytes`); the CEF type is unchanged. 5 lines, 5 events, 0 error
records: the JSON events hold `srcip` from `dst_ip`, `src_ip` and `sensor_bytes` as vendor fields; the key=value and
CEF events are as before. Function level: `familyMappingEdit20261125.test.ts`.

## 3. Audit residuals: is a real value lost?

No change was needed.

- A ChatGPT recipe that loses a value: not accepted in any run. The specs refuse the lossy replies (four in
  `chatgpt-key-outside-region-20261125.spec.ts`, one in `kv-bare-token-verdict-20261125.spec.ts`) and apply the
  lossless ones; the audits reported no accepted lossy recipe.
- H-2 fixed pattern text (comma between digits, a trailing `=`, colons between hex groups), probe
  `ps-takeover-scratch/fin/b1loss.ts` at d4e98cb: on every line the recipe accepts, every letter and digit reaches
  an output value; the fixed character is the same in every accepted line. A line with another separator
  (`3.14`, `YWJjZA==`, `aa-bb-cc-dd-ee-ff`) does not match and becomes an error record with its original text. No
  real loss was reproduced.
- ChatGPT route for unsupported logs: offered on every stopped sample of the unseen-log probes (below) and on the
  native CSV reading of finding F-7.

## 4. Final independent audit (separate executors)

First audit at 1e909af, over 6c6ebd2, 9c99189, 0688094 and 1e909af:

| Finding | Class | Resolution |
|---|---|---|
| F-1 `sport` still approved as srcport beside `client_ip_address`, `client_hostname`, client/server, remote/local | wrong official mapping | d4e98cb: `sport` is approved as the official source port only when the same record has a destination port, otherwise review. `sip dip sport dport`, `flow.sport` beside `flow.dport`, CEF spt/dpt, src_port/dst_port unchanged |
| F-2 pairs separated by `;` or `,` kept as one message and reported as parsed | false parsed verdict | d4e98cb: such pairs count as pairs |
| F-3 typing a destination key by key on a multi-type parser lost characters | major | d4e98cb: a change that cannot be applied yet stays as typed beside the reason |
| F-4 "Leave out of output" beside a field that is kept | major (wording) | d4e98cb: "Remove match", the field is kept under its original name |
| F-5 selector counted carried matches; F-6 refusal text incomplete | minor | d4e98cb |
| F-7 native CSV reading: "structurally parsed", then "parser not ready" after Review Fields; ChatGPT route offered | minor, outside the audited diffs | accepted limit, not changed |

Confirmation audit at d4e98cb (another separate executor): F-1 to F-6 confirmed fixed; no major defect and no
regression found. Remaining observations, not changed because they are cosmetic or older than this range:

- While a refused change is held, pressing Create Parser again repeats the notice text (cosmetic).
- A single-type generic parser without kept unmapped fields keeps the wording "Leave out of output", and a removed
  field still appears under `parserstudio_source.generic.kv.*` (same at 1e909af).
- Typing an official name into a vendor field sets the value type of that field (existing single-type behaviour).

Not verified by the auditor: the stepper control "4 Create Parser" while a change is held; some cases were checked
at function level only.

## 5. Final verification at d4e98cb

Full run on a clean tree (`fullx 38`):

| Check | Result |
|---|---|
| Battery (tsc, contract gate, grammar verify, TS-to-Ruby verify, duplicate ratchet, template set, Vitest, oracles TS/Python, independent oracle and fault, cross consumer, Python unit, build) | 14/14 pass; Vitest 2582/2582 |
| Backend | 792 tests, 778 pass, 14 fail: owner approval 2, Stellar legacy/POC 10, Drain3 2 (the same 14 as at 0688094; approval constants and environment) |
| Mapping gates (mcv2 Vitest, Python, mutants, AST, allocation, candidate oracle, candidate AST census, sink guard, reachability) | all pass; candidate AST census 90.35%, 8 equivalent, 0 invalid |
| Chromium, full catalogue with real backend and Multi-Pass | 455 passed, 62 skipped, 0 failed |
| Golden journeys T38 | identical to T36 and T33 |
| Phase 3 set | identical to T36 and T33 |

| Metric | Baseline | d4e98cb (T38) |
|---|---|---|
| Golden official mapping, downloaded cases | 171/182 | 171/182 |
| Golden official mapping, every case | 171/242 | 171/242 |
| Original values, downloaded cases (every case) | 179/179 (179/239) | 179/179 (179/239) |
| Event preservation | 99/99 | 99/99 |
| False FULL | 0/64 | 0/64 |
| Holdout official mapping | 102 correct, 0 wrong | 102 correct, 0 wrong |

No improvement of a corpus metric is claimed; the work of this range changes verdicts, routes and the mapping
screen on shapes that are in no corpus.

E2E on the clean final HEAD, downloaded parsers on Ruby 2.4.9 (`fin/f38specs`, 7 tests passed):

| Spec | Lines | Events | Error records (complete original text kept) |
|---|---|---|---|
| readable-events gate, free text beside key=value | 3 | 2 | 1 |
| readable-events gate, RFC 5424 VERSION 2 and 12 | 3 | 1 | 2 |
| ChatGPT Assisted, pipe-separated key=value | 6 | 6 | 0 |
| bare token beside key=value (section 1) | 6 | 5 | 1 |
| manual mapping per event type (section 2) | 5 | 5 | 0 |

Logs that are in no corpus (SYNTHETIC, the 14 samples of the previous document, rerun at d4e98cb): 12 parsers, 34
lines, 32 events and 2 error records with the original text; 236 of 236 expected values present, none missing or
hidden in a larger value; official mapping 46 correct, 36 unmapped, 0 wrong. The two samples without a parser
(pipe-separated key=value; RFC 3164 without a host and with a word before the pairs) stop and offer ChatGPT
Assisted Parser; their screens are byte-identical to the earlier run. The bare-token probe: stopped with Fix with
ChatGPT (was "structurally parsed" with no route before 1e909af); the sample with plain pairs gives a parser.
These are probe results, not an accuracy guarantee.

ChatGPT was not called in any run; replies were written by the tests. ChatGPT Assisted Mapping per event type
(`tests/chatgpt-jsonata-event-profile-20261123.spec.ts`) passes in the full Chromium run.

GitHub CI at d4e98cb (run 45565260140): browser regression 6/6 shards pass, native-isolated-synthetic pass,
ruby24-fluentd-udp-reception pass, release-eligibility skipped, web-quality fails on exactly two tests of 771: "the
real reviewed list accepts exactly the owner-approved current template and rejects any altered one" and "the
template set is owner-approved". Both compare against the owner approval constants, which this work does not
change.

## Limits that stay (accepted by the owner, not a roadmap)

- 14 golden cases stop in the automatic route and 11 official fields stay unmapped (document shapes, column
  meaning, free text and vendor forms, owner decisions, meaning the source does not establish).
- Lines with leading blanks, special logs, CSV column meaning, ambiguous official mappings and vendor grammars go
  to temporary names, review or ChatGPT Assisted Parser.
- F-7 and the three observations of the confirmation audit (section 4), and the minor items of the earlier
  documents.

## Not verified

- Stellar Cyber installation, reception and indexing of a generated parser (owner).
- Device logs captured by the project; production use.
- ChatGPT answer quality (ChatGPT is never called).
- Editing by hand a match that came from a ChatGPT reply on a multi-type parser, in Chromium (section 2).
- The commits of this document range were audited by separate executors; d4e98cb itself had the confirmation
  audit only.

## Completion statement

- Development within the product scope: complete at d4e98cb. No open defect of class major or blocker is known in
  scope; the remaining items are the accepted limits above. No further improvement roadmap is added.
- Template approval and release readiness: not reached. Open with the owner: approval of the two digests above
  (KNOWN_TEMPLATES and the approval constants are untouched, so web-quality stays red on the two approval tests
  until then), the main merge of PR #316 (Draft), the Stellar Cyber verification, and the deletion of the stray
  remote branch `claude/takeover-dev2-20261122`.
