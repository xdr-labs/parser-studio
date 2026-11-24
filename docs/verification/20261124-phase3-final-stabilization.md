# Phase 3 final stabilization: ChatGPT Assisted Q3-1, audit fixes, grammar checks — verification (2026-11-24)

Scope: PR #316, range a21155c..512df81 (follows `20261124-phase3-q31-unmapped-fields-fortinet-cef.md`). No main
merge, no deployment. KNOWN_TEMPLATES and approval constants unchanged. The generated Ruby templates are unchanged
since 2b6602c, so the digests awaiting owner approval stay:

- Ruby template set: `cefa3150928a9a108cd7ae668bf8cfcf475bf24d922f9ec168ae0d00a94894d1`
- POC template: `1ae4b12dad98ca424aa9efff590f4d308924cac162aaae6ed0e3d969bfd588e2`

## What changed

| Commit | Change | Proof (tests failed before the change) |
|---|---|---|
| 95609b1 | ChatGPT Assisted recovery parsers set `preserveUnmapped` (Owner decision Q3-1): a capture the reviewed reply leaves unmapped, or a key the sample never showed, is kept in the vendor namespace as in the Auto Parser. | `src/guided/chatGptAssistedQ31.test.ts`; its project on Ruby 2.4.9: 4 units, 4 records, 0 problems |
| 9f51499 | F-4: Python Generic Structural declines a malformed CEF/LEEF claim inside an RFC 5424 message. | `tests/test_fortinet_cef_space_20261124.py` |
| 0f3a003 | Audit of 2b6602c, G-1..G-4: backend validation, the browser preview and the UI contract refuse writes to the names Q3-1 reserves. | `backend/test/unmapped-fields-audit-2b6602c.test.ts`, `src/guided/unmappedFieldsAudit2b6602c.test.ts` |
| 62263b3 | Tests only: CEF/LEEF header forms through the Auto Parser journey and the Python preview. | `src/grammar/cefLeefHeaderForms20261124.test.ts` |
| d630a62 | Chromium spec for ChatGPT Assisted Q3-1. | `tests/chatgpt-q31-unmapped-20261124.spec.ts` |
| 3f363d2 | Final re-audit H-1 (top/ns mappings into the vendor namespace) and H-3 (Multi-Pass preview endpoint); H-2 relaxation, reverted in 512df81. | `backend/test/unmapped-fields-reaudit-20261124.test.ts`, `src/guided/unmappedFieldsReaudit20261124.test.ts`, `PreviewDeclinesMalformedClaimInsideSyslog` |
| 512df81 | Restores the strict residual check of the AI review (verification D-1). | IIS and Apache tests in `AutoParserAIReview.source-preservation.test.tsx` (both recipes were applied at 3f363d2) |

### AI review guard tests changed by 95609b1

`src/guided/AutoParserAIReview.source-preservation.test.tsx` had three guard tests whose recipes lost a value only
because a capture was unmapped. Q3-1 keeps that capture, so those recipes are no longer lossy. The three tests now
send recipes that lose source text the way a recovery still can (text read as a regex literal outside any capture)
and assert the same rejection messages; two new tests send the old recipes and check, value by value, that the
applied parser keeps every source value of the sample and of each additional test log. No guard was removed or
relaxed. Recipes that would lose a value through a type conversion or two mappings to one target are refused earlier
by the recipe check (UNTRUSTED_RECIPE).

## Independent audits (separate executors)

### Audit of 2b6602c (41 cases, ~250 events; browser, Ruby 3.2, Ruby 2.4.9)

| ID | Severity | Finding | Status |
|---|---|---|---|
| G-1 | MAJOR | An event-profile vendor field could write `parserstudio_unmapped`; Ruby wrote it silently. | Fixed (0f3a003) |
| G-2 | MINOR | An enrichment could write `<vendor>.parserstudio_unmapped`. | Fixed |
| G-3 | MINOR | With fields kept and no vendor field, the manufacturer could name a system root; Ruby lost the kept fields or wrote them into the system root. | Fixed |
| G-4 | MINOR | With fields kept, an enrichment could write the bare manufacturer name; events failed depending on their content. | Fixed |
| G-5 | MINOR | Kept names may be forms the mapping contract forbids as destinations (`__proto__`, `constructor`, empty key); all engines agree. | Open: Fluentd/Stellar Cyber acceptance NOT VERIFIED |

### Final re-audit of a21155c..62263b3

No data loss, no value of one event in another and no browser-vs-Ruby 2.4.9 record difference (regex, JSON, KV, CEF,
LEEF 1.0, CSV, RFC 5424 + KV and mixed recipes; runtime keys absent from the sample, UTF-8, nested and dotted keys).

| ID | Severity | Finding | Status |
|---|---|---|---|
| H-1 | MAJOR | While fields are kept, a top or ns mapping could write into the vendor namespace (`acme.x`, bare `acme`, `acme.parserstudio_unmapped.x`); events then failed or not depending on whether they had a field to keep (reachable from any ChatGPT `map_field`). | Fixed (3f363d2): backend validation (shared and event-profile sections), the browser preview (every event) and the UI contract refuse it; without the decision nothing changes |
| H-2 | MAJOR | The AI review refuses a lossless ChatGPT recovery on real Multi-Pass evidence: a residual region must be a substring of one output value, but Multi-Pass residuals span several tokens (`" TCP_MISS/200 5120 GET "`) that a correct recipe reads into several fields. Pre-existing guard. | **Open.** A word-counting relaxation (3f363d2) was reverted (512df81) after verification D-1. Kept as an `it.fails` test |
| H-3 | MAJOR (parity) | F-4 reached only `parse_generic_structural`; the Multi-Pass preview endpoint still read `CEF :0|`, `CEF\t:0|`, `LEEF :1.0|` in RFC 5424 (and after RFC 3164) as a parsed free-form message. | Fixed (3f363d2): the source reader does not turn a CEF/LEEF claim its decoders refused into free-form MSG/CONTENT |

MINOR, documented: an unproven regex runs FULL in the browser but fails closed on Ruby 2.4.9 (no bounded Regexp;
export is refused for the 7.0 target); without the decision, a constant written to the bare manufacturer with vendor
fields passes the UI contract but is refused by the backend (pre-existing); Python reads LEEF 2.0 without a delimiter
field (implicit tab) and lowercase `cef:` in RFC 5424, which the browser declines (pre-existing).

### Verification of 3f363d2

| ID | Severity | Finding | Status |
|---|---|---|---|
| D-1 | MAJOR (introduced by 3f363d2) | The H-2 relaxation let lossy recoveries pass: IIS `... (?<status>\d+) 0 0 (?<taken>\d+)$` (the zeros matched an IP's octets) and Apache `-(?<tz>\d{4})` (tz became `0500`, the sign lost) were applied, FULL in the browser and on Ruby 2.4.9. | Fixed by reverting H-2 (512df81); both recipes with real `preview_batch` evidence are refused (tests failed at 3f363d2) |
| D-2 | MINOR | After H-3, the Python preview declines RFC 5424 messages that begin with a CEF/LEEF-like claim, also free text such as `CEF : 3 alerts today` and `CEF :0|A|B|1|2|n|3|x`, which a raw-body RFC 5424 parser in the browser and Ruby keeps whole as `message` (lossless). Valid CEF/LEEF, `CEF team meeting at 10:00`, lowercase `cef:0|` and claims after NBSP/ideographic space are unchanged; 168 header/body combinations agree between `preview` and `preview_batch`. | Kept (the preview is the conservative side: "review needed", no loss). Whether a raw-body parser should accept a malformed CEF/LEEF claim as text is an owner question |
| D-3 | MINOR | The UI contract does not check event-profile mappings (pre-existing); the backend refuses H-1 targets there, so no parser is built. | Documented |
| D-4 | MINOR | A dotted manufacturer (`acme.io`) with top target `acme` is accepted; Ruby writes `"acme"` and `"acme.io"` side by side. With a vendor-field mapping the backend refuses it. Whether Stellar Cyber expands dotted keys is NOT VERIFIED. | Documented |

Ruby 2.4.9: no template change; nine projects compiled at d630a62 and 3f363d2 give byte-identical Ruby, all run on
Ruby 2.4.9 with the browser's values.

## Grammar checks (P3)

| Form | Browser journey | Python preview | Ruby 2.4.9 | Decision |
|---|---|---|---|---|
| `CEF:0|` / FortiGate `CEF: 0|`, no header, RFC 3164, RFC 3164 without PRI | FULL, every value kept | SOURCE_PARSED | same records | supported |
| `LEEF:2.0|`, no header, RFC 3164 | FULL | SOURCE_PARSED | same records | supported |
| `LEEF: 2.0|` (A-6), also after PRI or RFC 3164 | stops | PARTIAL | — | declined: the IBM QRadar LEEF guide defines the header as `LEEF:Version|`, no space |
| `CEF :0|`, `CEF:  0|`, also after PRI | stops | PARTIAL | — | declined (spacing never makes a malformed header CEF) |
| PRI only: `<189>CEF:0|`, `<189>CEF: 0|`, `<111>LEEF:2.0|` | stops (MIXED_OR_UNKNOWN) | SOURCE_PARSED | — | unchanged; preview mismatch remains (no parser is built, so no wrong output). Support needs a grammar change in every engine; FortiGate wire format NOT VERIFIED |
| `<189> CEF:0|` (space after PRI) | stops (policy) | SOURCE_PARSED | — | unchanged |

Numbers: browser and Ruby keep a JSON number's value, not its spelling (`1.0` → "1", `1e2` → "100", `-0` → "0"), for
mapped string fields and kept fields alike. The Python preview shows the parsed float (`1.0`, `100.0`) and its byte
span points at the original text. Numeric equality holds in all three; the original spelling is kept only in a
Generic Structural `parserstudio_source`. Keeping the spelling elsewhere would be an owner decision.

## Measurements (same corpus, journeys and scorer as T29)

| Metric | T29 (288db7d) | T30 (62263b3) | T31 (3f363d2) |
|---|---|---|---|
| Official mapping, downloaded golden cases | 171/182 | 171/182 | 171/182 |
| Official mapping, every golden case (UI-stopped = 0) | 171/242 | 171/242 | 171/242 |
| Original values, downloaded / every golden case | 179/179 / 179/239 | 179/179 / 179/239 | 179/179 / 179/239 |
| Event preservation | 99/99, 0 failure records | 99/99, 0 failure records | 99/99, 0 failure records |
| False FULL | 0/64 | 0/64 | 0/64 |
| Holdout canonical correct / wrong (kept 16, embedded 8, lost 0) | 102 / 0 | 102 / 0 | 102 / 0 |

Per-case comparison (verdict, events, error records, mixing, linkage, canonical, preserve, mapping set) of the
golden, public, Issue #315 and Phase 3 sets, T29 vs T30 and T30 vs T31: no difference.

These commits do not change Auto Parser grammars or mappings, so the accuracy numbers stay; no improvement of 171/182
or 171/242 is claimed. 512df81 differs from 3f363d2 only in the AI review residual check and its tests, which the
Auto Parser journeys do not use.

Full validation at 3f363d2 (`fullx 31`): battery 14/14; mutants, AST census (90.36%), allocation and candidate checks
pass; backend 792 tests, 14 failures that are all environment or owner approval tests (template approval 2, Stellar
legacy client/HTTP/plan 10, Drain3 worker 2); Chromium 442 passed, 62 skipped, 0 failed (the new ChatGPT Q3-1 spec included).

At 512df81 (`check.sh`): Vitest 2452 passed and 1 expected failure (the open H-2 test), Python unit passed, backend
792 tests with the same 14 environment/approval failures, mutants and AST census (90.36%) pass.

## ChatGPT Assisted Q3-1 through Chromium

`tests/chatgpt-q31-unmapped-20261124.spec.ts` on the live backend: a log the Auto Parser cannot read → prompt → two
wrong replies (one column for two values; the action read as the source IP, a wrong official mapping) → never reach
parser files → a reply that maps one of the two columns → test PASS → approval → parser files → download. The
downloaded Ruby on Ruby 2.4.9 with the sample, the test logs and two runtime lines (IPv6, UTF-8), at 512df81:
6 units, 6 records, 0 problems; the unmapped column is in the vendor namespace of every record, no value of another
line, no error record. ChatGPT was not called, so no AI response success rate is reported.

A regex reply passes the browser review, but parser files stay blocked for the Stellar Cyber 7.0 target (Ruby 2.4.9
has no bounded Regexp), so the downloadable path is shown with CSV. A reply for a log the Auto Parser already reads is
a baseline edit that may only change mappings; its context draft comes from the Auto Parser and already keeps
unmapped fields. H-2 limits the full-recovery path for logs whose Multi-Pass residuals span several tokens.

Q3-1 Auto Parser Chromium E2E (`q31e2e/run.sh`, runtime lines in order and reversed) at 512df81: kv_newkey,
mixed_root_body, json_nested_utf8, rfc5424_header_body, fortinet_cef: 10/10 runs, 0 problems.

## The 14 golden cases that stop at Review Fields (screen text of each journey)

| Cause | Cases | What the screen says |
|---|---|---|
| A file or document shape, not a line a sensor receives | aws_cloudtrail_records, json_multiline_pretty, suricata_eve_alert_multiline, windows_4624_xml, w3c_iis, csv_quoted_unicode, linux_audit | every value read, parser files not built for this shape (CloudTrail suggests ChatGPT); events need attention; part of an event unparsed (linux_audit nested `msg=audit(...)`) |
| Column meaning unknown | panos_traffic_csv | keep every value with temporary names, then map after confirming the meaning |
| Free text needing a rule | cisco_asa_106023, r2_bsd_tagged_classic (the sshd line) | events need attention / part of an event unparsed |
| Mixed envelopes or envelope policy | juniper_srx_rtflow (no PRI), r2_rfc5424_versions (VERSION 2 and 12), r2_elastic_cef_envelopes (space after PRI), r2_cef_leef_escaped_envelopes (CEF and LEEF bodies in one sample) | events need attention / part of an event unparsed |

None of them is a silent wrong parse. Creating a parser from only the readable events of such a sample, and new
grammars for these shapes, were not implemented in this range.

## The 11 official fields still unmapped (171/182)

Meraki IDS `ip:port` endpoints (4: needs a typed endpoint split for IPv4/IPv6 in every engine), mixed_types ports
without TCP/UDP evidence (withheld on purpose), r2_invalid_types (invalid typed values, withheld on purpose), and
fields held in REVIEW. Mapping them without that evidence would risk wrong official mappings; no change in this range.

## CI (Parser Studio quality)

| HEAD | Browser shards | native-isolated-synthetic | ruby24-fluentd-udp-reception | web-quality |
|---|---|---|---|---|
| 62263b3 | 6/6 | pass | pass | 769 tests, 2 failures: the two owner template-approval tests |
| d630a62 | 6/6 | pass | pass | 769 tests, 2 failures: the two owner template-approval tests |
| 3f363d2 | 6/6 | pass | pass | 771 tests, 2 failures: the two owner template-approval tests |
| 512df81 | 6/6 | pass | pass | 771 tests, 2 failures: the two owner template-approval tests |

The web-quality failure is the approval gate (owner approval of the template digests pending), not a product defect
and not Drain3; Drain3 and Stellar legacy failures appear only in the dev-atlas run (environment).

## Remaining

1. H-2: lossless ChatGPT recoveries on logs with multi-token Multi-Pass residuals are refused; needs span-level
   evidence of each capture and a rule for separator punctuation (`/` in Squid vs the sign in `-0500`).
2. G-5: Stellar Cyber/Fluentd acceptance of kept names such as `__proto__` (NOT VERIFIED).
3. D-2: whether a malformed CEF/LEEF claim in an RFC 5424 message is text (browser/Ruby raw body) or needs review
   (Python preview): owner decision.
4. PRI-only CEF/LEEF (`<189>CEF:0|`): browser declines, Python reads; a grammar change in every engine if supported.
5. The 14 UI-stopped golden cases and the 11 unmapped official fields (above).
6. Owner approval of the template digests; Stellar Cyber installation tests are the owner's.
