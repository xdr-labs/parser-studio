# Final root-cause review and end-of-development check (2026-11-25)

Scope: PR #316, range d2b0fce..0688094 (follows `20261125-h2-d2-pri-cef-g5.md`). Owner directive of 2026-11-25:
look for remaining root-cause improvements in the shared parsing and mapping architecture, implement only those
that are proven and general, accept the product limits, then verify the final HEAD. No main merge, no deployment,
no Stellar Cyber DP test. KNOWN_TEMPLATES and the owner approval constants are unchanged. Generated Ruby is
unchanged in this range, so the digests awaiting owner approval are the same as at b2b800d:

| Digest | Value |
|---|---|
| Ruby template set (`contracts/ruby-template-set.v1.json`) | `bb653102732e01001b5a30d4ac05b14917bb43dbe84eb484c88c409b261e0e8a` |
| POC template (`pocTemplateSha256`) | `2b65c2706ebe7855cfd5a8a2086404bf5fda1ca65483c2d65437f9911dfd1466` |

## Result in one paragraph

Four structural defects were found by running logs that are in no corpus through the real journeys, and by the
independent audit; all four are fixed with a test that failed before. The corpus metrics are unchanged. The 14
golden cases that stop and the 11 unmapped official fields are product limits or user decisions, not engine
defects; no grammar was added for them. Three items stay open and need an owner decision before development is
declared finished (section "Open").

## The 14 golden cases that stop and the 11 unmapped fields

"Stop" is what the measuring journey records: it only clicks Review Fields. The screens of T33 show what the
product offers instead.

| Cases | Class | What the product offers |
|---|---|---|
| aws_cloudtrail_records, json_multiline_pretty, suricata_eve_alert_multiline, windows_4624_xml, w3c_iis, linux_audit | B: a file or document shape, not a line a sensor receives | every value read, Fix with ChatGPT |
| csv_quoted_unicode, panos_traffic_csv | B: column meaning needs the user | "Keep all N values with temporary names", then rename or map |
| cisco_asa_106023, juniper_srx_rtflow (file form without PRI and VERSION; the wire form h_srx_sd_close_deny passes) | B/C: free text or a vendor form that needs a rule | Fix with ChatGPT |
| r2_bsd_tagged_classic, r2_rfc5424_versions, r2_elastic_cef_envelopes, r2_cef_leef_escaped_envelopes | owner decisions (per-event creation, RFC 5424 VERSION 1 only, envelope policy) | "Create the parser for the N readable events"; before this range the offer dead-ended on two of the four (fixed, below) |

The 11 unmapped official fields (Meraki `ip:port` endpoints, ports without TCP/UDP evidence, invalid typed values,
fields held for review) are class B: the source does not establish the meaning, or a split would change parsed
data in the mapping step. They stay vendor fields with their original name and value.

## Structural defects found and fixed

| Commit | Defect (cause) | General effect | Proof |
|---|---|---|---|
| e8d8d26 | The offer "Create the parser for the readable events" split a sample on the browser preview verdict, while the journey goes on only on the server analysis (SOURCE_PARSED) and the first scan (RECOGNIZED). When they disagreed the reduced sample stopped again with no way forward; an RFC 5424 VERSION 2 line was shown as "read completely" (the browser-only approximate Syslog preview accepted any one-digit VERSION). | Every sample that mixes readable and unreadable events. One verdict source for the split and the gate. | `readableEventsGate20261125.test.ts` (8 of 9 RED before), `tests/readable-events-gate-20261125.spec.ts` (3 of 3 RED before). The four golden mixed samples reach a downloaded parser through the offer: 2 of 4 before, 4 of 4 now; on Ruby 2.4.9 every unreadable line is an error record with the complete original text. |
| 6c6ebd2 | H-2 key rule: a key such as `sip=` whose value the analysis already read ends an unparsed region; the rule looked only at captures that touch a region, so the key was counted as lost and every lossless recipe for key=value text with recognized values was refused. The repair prompt did not state the Regex export rule of the 7.0 target, so a reply could pass, be applied and then be stopped at Review Fields. | ChatGPT recovery of any key=value text with recognized addresses; both prompts state one export rule. | `residualKeyOutsideRegion20261125.test.ts` (4 of 5 RED), `repairPromptRegexExportRule20261125.test.ts` (RED), `tests/chatgpt-key-outside-region-20261125.spec.ts`. The probe suites of the earlier H-2 audits give the same verdict for every probe before and after (127 accept, 131 refuse, 7 unavailable). |
| 9c99189, 0688094 | A-2: `sport` was approved as the official source port in records that name their endpoints client and server (`cip sip cport sport`): srcport held the server port. | Shared candidate policy: beside a client-side endpoint name and without a destination port the mapping is offered for review; `sip dip sport dport` keeps its mapping. Same family of rule as the existing `spt` beside `cpt`. | `serverPortReading20261125.test.ts` (7 of 10 RED), 15 independent oracle cases; unseen samples on Ruby 2.4.9: official mapping wrong 2 -> 0. |
| 9c99189 | A-1: Map Fields counted only the matches shared by every event type; for a multi-type parser it said "Matched to Stellar 0 ... Left out of output 27" and "NO MAPPING RULE" for fields the generated parser maps and keeps. A-4: an unreadable header was called an RFC 3164 header. | The summary, the per-event statements and the source tree follow the rules of each event type and the kept unmapped fields; the matches of each type are listed (read-only). | `tests/map-fields-event-types-20261125.spec.ts` (RED before). |

No vendor rule, no golden-specific condition and no new engine were added. The existing architecture (shared
grammar, TypeScript-to-Ruby generation, per-event parsing, event profiles, canonical mapping contract, Q3-1
preservation, H-2 provenance) was kept as it is.

## Logs that are in no corpus (SYNTHETIC; Chromium, real backend and Multi-Pass, downloaded Ruby on Ruby 2.4.9)

14 new samples with runtime lines the sample never showed (new keys, IPv6, UTF-8, quoted delimiters, unreadable
lines); 11 samples run at e8d8d26, the three KV naming variants at 9c99189:

| Route the product offered | Samples |
|---|---|
| parser directly | KV in RFC 3164, nested JSON, CEF, LEEF with `^`, RFC 5424 structured data, RFC 5424 with JSON body, free text behind an RFC 3164 header without PRI (kept whole as message), three KV naming variants |
| temporary column names | headerless CSV |
| parser for the readable events | KV lines mixed with free-text lines |
| stopped, Fix with ChatGPT offered | pipe-separated key=value; RFC 3164 without a host, with a word before the pairs |

12 parsers, 34 lines, 32 events and 2 error records (complete original text kept): 236 of 236 expected values
present, none missing or hidden in a larger value; official mapping 46 correct, 36 unmapped, 0 wrong (2 wrong
before 9c99189). These are probe results on synthetic lines, not an accuracy guarantee.

## ChatGPT Assisted

ChatGPT was not called; the replies were written by the tests, so no AI answer success rate is reported.

- Prompt of a log the Auto Parser cannot read (pipe-separated key=value): the exact original events, what failed
  (`NO_SUPPORTED_GRAMMAR`), the unparsed regions with byte ranges, the values already read, the verdict of every
  record, the reply contract (ParserRecipe v0.2, digest, one code block), the capture rules and the export rule.
- Four lossy replies refused (a value prefix read as pattern text, a key kept before a capture of another name, two
  values matched but not captured); the lossless reply applied; parser files downloaded; Ruby 2.4.9 on sample, test
  and runtime lines: 6 lines, 6 events, every value kept, srcip and dstip mapped (IPv6 and UTF-8 included).
- Mapping per event type with ChatGPT (`tests/chatgpt-jsonata-event-profile-20261123.spec.ts`) passes (run at 9c99189).

## Independent audit (separate executor, e8d8d26)

Workspace `/home/aella/.local/state/parserstudio-audit-final-20261125/` (probe scripts and outputs). No False FULL,
no silent drop and no dead end in the readable-events gate (21 offered reduced samples all resolved) and in five
single-family journeys on Ruby 2.4.9.

| Finding | Disposition |
|---|---|
| A-1 MAJOR wrong statements on Map Fields for a multi-type parser | fixed in 9c99189; editing per event type on this screen stays open (below) |
| A-2 wrong official mapping of `sport` | fixed in 9c99189 / 0688094 |
| A-4 MINOR wording of an unreadable header | fixed in 9c99189 |
| C-1 MAJOR (borderline), C-2 MINOR: key=value text with a bare token | open (below) |
| B-1 MAJOR: H-2 accepts recipes that read a comma between digits, a trailing `=` or a colon between hex groups as fixed pattern text (function level, not through the UI) | not fixed, documented limit: these characters are field separators in other logs (`a,b`, `key:value`); counting them as value refuses common lossless recoveries (`mode:fast`, `code:200`). Every accepted line has the separator at the same place, so no variable text is dropped; a line that differs does not match and keeps its original text. |
| A-3 MINOR: lines with leading blanks stop at Review Fields with the ChatGPT route, the cause is not named; A-5 INFO: a line of only U+00A0 gives no offer | not fixed, conservative stops |

The commits after the audit (6c6ebd2, 9c99189, 0688094) have tests that failed before, the full validation below
and CI, but no independent re-audit.

## Validation of the final HEAD 0688094 (`fullx 36`, same corpus, journeys and scorer as T29..T33)

| Metric | T33 (4c04b0b) | T36 (0688094) |
|---|---|---|
| Official mapping, downloaded golden cases | 171/182 | 171/182 |
| Official mapping, every golden case (UI-stopped = 0) | 171/242 | 171/242 |
| Original values, downloaded / every golden case | 179/179 / 179/239 | 179/179 / 179/239 |
| Event preservation | 99/99, 0 failure records | 99/99, 0 failure records |
| False FULL | 0/64 | 0/64 |
| Holdout canonical correct / wrong | 102 / 0 | 102 / 0 |

The measuring journey does not use the readable-events offer, so the four mixed golden samples still count as
stopped; no improvement of the corpus metrics is claimed.

- Battery 14/14 (tsc, contract gate, grammar and ts2rb verification, duplication ratchet, template set in sync,
  Vitest 2564/2564, semantic oracles, cross-consumer parity, Python unit, build, Python oracle).
- Backend 792 tests, 778 passed, 14 failures that are owner approval or environment (template approval 2, Stellar
  legacy/POC 10, Drain3 2), as before. Mutation checks pass; candidate AST census 90.38% (8 equivalent, 0 invalid).
- Chromium 453 passed, 62 skipped by their own guards, 0 failed.

## CI (Parser Studio quality)

| HEAD | Browser shards | native-isolated-synthetic | ruby24-fluentd-udp-reception | web-quality |
|---|---|---|---|---|
| e8d8d26 | 6/6 | pass | pass | failed (log not inspected; superseded) |
| 9c99189 | 6/6 | pass | pass | failed: candidate AST census below 90% (the new rule had no oracle case) |
| 0688094 | 6/6 | pass | pass | 771 tests, 2 failures: the two owner template-approval tests |

## Open (owner decision)

1. Key=value text with a bare token (audit C-1, C-2; reproduced by the auditor on Ruby 2.4.9, root cause not
   traced). A sample such as `evt=flow_open fragmented client=... server=... verdict=permit` behind an RFC 3164
   header is reported as structurally parsed with the whole body kept as message text: the pairs are not
   extracted and no ChatGPT route is offered. A runtime line with one more pair is read in another shape
   (`evt` = `flow_open fragmented`, header tokens as `prefix_001..005`, no official hostname) without an error
   record. No text is lost (message, `source_raw`); the shape of the output depends on the number of pairs.
2. Map Fields on a multi-type parser: the matches of each event type are shown but cannot be edited or removed
   there; one type is changed with Improve with ChatGPT and its event type selector. Adding a shared match by hand
   on such a parser is NOT VERIFIED.
3. Owner approval of the template digests above; Stellar Cyber installation and DP indexing tests are the owner's.

Carried over, none of them a silent value loss: the MINOR items of `20261125-h2-d2-pri-cef-g5.md` (A-4..A-9, F-6,
R-2 residue, N-3, F-7), the remote branch `claude/takeover-dev2-20261122` (deleting it needs the owner's
permission).
