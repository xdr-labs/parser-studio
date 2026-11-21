# Phase 3 independent audit: commits 714d272, 1768ba8, 7a255a6

Auditor: independent (did not write the code). Date: 2026-11-21 (UTC). Nothing was fixed or changed in the worktree.

## 0. Scope, method and state of the tree

- Reviewed the full diff of each commit and the code it interacts with: `src/guided/normalizationCandidates.ts`, `src/guided/genericStructuralAutoDraft.ts`, `src/guided/AutoParser.tsx` (lines 640-680), `src/guided/autoParserEnvelope.ts` (first scan), `src/guided/canonicalMappingPlan.ts`, `src/guided/jsonataMappingAssist.ts`, `src/genericStructural.ts` (reader containers), `runtime/multipass/semantic-policy.v1.json`, the two test files and the two verification scripts the commits touch.
- Executed product code with small TypeScript scripts (tsx) and, for the adoption path, with the REAL source witness: `runtime/multipass/multipass_preview_api.py` (`preview` / `preview_batch`) was imported in Python (no bytecode written) to get the status the preview service returns for each input, then `analyzeLogEnvelopes` + `headerlessCsvEvents` + `buildSourceReviewedBoundedDraft` were called exactly as `AutoParser.tsx:664-666` does. The React component itself was not run.
- Differential test: `normalizationCandidates.ts` of the parent commit 1d23770 was extracted to scratch and run against the same parsed events as the 7a255a6 version ("OLD" / "NEW" below).
- IMPORTANT, state of the worktree: at the start HEAD was 7a255a6 and the tree was clean. During the audit another process committed b117e05 (11:35:19 UTC, changes `src/grammar/parseStatus.ts` and `backend/templates/grammar-core.generated.rb.tpl`) and left uncommitted edits (`src/grammar/kvBody.ts`, `runtime/multipass/source_kv.py`, syslog header grammar files, templates, contracts). `src/grammar/parseStatus.ts` was already modified on disk from 11:27:34 UTC. To keep the audit on the requested commit I exported 7a255a6 with `git archive` to `phase3/tree7a` (node_modules symlinked) and RE-RAN EVERY result quoted in this report against that export (scripts in `phase3/pin/`). All results were identical to the earlier live-tree runs. b117e05 and the uncommitted edits are NOT audited here.
- Templates: `git diff --name-only 1d23770 7a255a6 -- backend/templates` returns 0 files. The range 1d23770..7a255a6 touches 8 files only (3 under `src/guided/` + 2 tests there, 2 scripts under `scripts/verification/`, 1 audit document). None of the three commits changes a Ruby template, the compiler, `contracts/` or `runtime/`. (b117e05, outside the scope, does change a template.)

## 1. Summary

| ID | Sev | Commit | Short description | Verified |
|----|-----|--------|-------------------|----------|
| F-01 | P1 | 1768ba8 | A double quote in one cell switches the headerless-CSV rule off; the cell-moving misreading is adopted as FULL and a wrong value is written to official `url` | CONFIRMED |
| F-02 | P1 | 714d272 | A sample the first scan fully recognized (unsupported = 0) is now handed to the bounded compiler when it contains a PRI-less PAN-OS TRAFFIC line; natively readable lines are re-read worse (key=value pairs not extracted) and reported FULL | CONFIRMED |
| F-03 | P2 | 714d272 | Protocol evidence is no longer found for literal dotted keys (`flow.proto` beside `flow.sport`): ICMP type/code become official srcport/dstport with HIGH (was REVIEW) | CONFIRMED |
| F-04 | P3 | 714d272 | A protocol field whose value is an object or array is now ignored: ports HIGH where they were REVIEW | CONFIRMED |
| F-05 | P1 | 7a255a6 | The Host header is still proposed as official `hostname` (HIGH) for most other HTTP log shapes; the rule is a fixed name list in one container | CONFIRMED |
| F-06 | P2 | 7a255a6 | A genuine device host name is refused (no candidate at all, was HIGH); one HTTP-looking event refuses it for the whole sample | CONFIRMED |
| F-07 | P3 | 7a255a6 | The rule is not shared with the reviewed AI-proposal path (CHECK_FIRST, not BLOCKED) and no mutant covers it although the commit cites "Mutants 18/18 killed" | CONFIRMED (execution / reading) |
| F-08 | P3 | 714d272 + 1768ba8 | Two lines of one comma key=value family, one quoted and one unquoted, are no longer adopted (the quote decides, not the reading) | CONFIRMED |

No finding in: Ruby templates (untouched), JSON number precision, UTF-8 handling, cross-event index alignment of the per-event flags.

## 2. Findings

### F-01 (P1) 1768ba8: a quote character in a cell switches the headerless-CSV rule off

- Where: `src/guided/genericStructuralAutoDraft.ts:182-186` (`headerlessCsvEvents`: flag only when `status===RECOGNIZED`), used by `:196-208` and `src/guided/AutoParser.tsx:664-666`.
- Cause: the first scan calls a comma line `none/csv/BODY_MALFORMED` as soon as the strict CSV lexer fails, for example for one double quote inside an unquoted cell. 1768ba8 treats every such line as "unsupported, free for the compiler". That is the same class of line the rule of 714d272 (N1) exists for; only the BIG-IP shape was considered.
- Input (2 lines; the audit sample "one cell holds key=value pairs" with the user value quoted):
```
2026-11-21 10:00:00,web01,request user="bob" src=10.0.0.5 method=GET status=200 url=/index.html,10.0.0.9,8443,ok
2026-11-21 10:00:01,web01,request user="amy" src=10.0.0.6 method=POST status=403 url=/admin,10.0.0.9,8443,denied
```
- Actual: first scan `none/csv/BODY_MALFORMED` x2, flags `[false,false]`, real witness `SOURCE_PARSED` x2, draft ADOPTED, counts total 2 / matched 2 / extracted 2 / normalized 2 / failures 0, both events `parseStatus=FULL`, reading `space_kv`. Fields: `prefix_001="2026-11-21"`, `prefix_002="10:00:00,web01,request"`, `kv.url="/index.html,10.0.0.9,8443,ok"`. Normalized output: `srcip=10.0.0.5`, official `url="/index.html,10.0.0.9,8443,ok"` (event 2: `url="/admin,10.0.0.9,8443,denied"`). Three CSV cells (an address, a port, a result) are appended to the URL and written to an official field; time, host and the word "request" are merged into one vendor field.
- Expected: not adopted (CSV column review stays), as for the same sample without the quotes, which is flagged and refused.
- History: with the flags of 714d272 (`none/csv` whatever the status) the same call returns null (executed). At the parent 1d23770 the general route adopted it. So 714d272 closed it and 1768ba8 re-opened it.
- Also adopted the same way (executed, single lines): `2026-11-21 10:00:00,web01,"request" user=bob src=10.0.0.5 dst=10.0.0.9 method=GET status=200 url=/index.html,10.0.0.9,8443,ok` (url takes the cells) and the semicolon form `2026-11-21 10:00:00;web01;request user="bob" src=10.0.0.5 method=GET status=200 url=/index.html;10.0.0.9;8443;ok` (`url="/index.html;10.0.0.9;8443;ok"`).
- Not adopted (executed): the quoted variants of the two other audit samples (first cell like a BSD timestamp, host followed by a comma) because the real witness is PARTIAL; a mixed sample of one valid CSV line and one quoted line (the valid line is flagged).
- Related, unchanged by these commits (executed): the same record behind a PRI, `<14>2026-11-21 10:00:00,web01,request user=bob src=10.0.0.5 method=GET status=200 url=/index.html,10.0.0.9,8443,ok`, is `rfc3164/unknown/HEADER_MALFORMED` for the first scan, never flagged, and adopted FULL with the same wrong `url`. Same at the parent commit.
- Supplementary: the first live-tree run of this case happened after `parseStatus.ts` of b117e05 was already on disk and gave the same FULL result; b117e05 does not close it.
- CONFIRMED by execution (real witness, pinned 7a255a6).

### F-02 (P1) 714d272: fully recognized samples are now adopted by the bounded compiler when a PRI-less PAN-OS TRAFFIC line is present

- Where: `src/guided/AutoParser.tsx:665-666` (route condition `report.unsupported>0||csvFound` with one builder) and `src/guided/genericStructuralAutoDraft.ts:201-207` (events that are not flagged are unconstrained).
- Cause: before 714d272 the branch for `unsupported===0 && csvFound` required EVERY event to be read as `panos_traffic_csv`. Now only the flagged events are checked. Events the first scan fully recognized as another native format are re-read by the Generic Structural compiler and the whole sample is adopted.
- Input A (line 1 = the constant `PAN` of `headerlessCsvBoundedCompilerGate20261121.test.ts`, line 2 below):
```
<134>Nov 21 10:00:01 fw1 system: logdesc=login user=bob srcip=10.0.0.7 action=accept
```
- Actual A: first scan `none/csv/RECOGNIZED, rfc3164/kv/RECOGNIZED`, `unsupported=0`, real witness `SOURCE_PARSED` x2, ADOPTED. Line 2 is read as `bsd_tagged_message`: one field `generic.message="logdesc=login user=bob srcip=10.0.0.7 action=accept"`, `parseStatus=FULL`. None of the four pairs is extracted, `srcip` is not mapped. Line 2 alone is not offered to the compiler at all (route closed) and the native reader extracts `body.logdesc`, `body.user`, `body.srcip`, `body.action` with `syslog_hostname`.
- Input B: `PAN` + `<134>Nov 21 10:00:00 fw1 traffic: srcip=10.0.0.1 dstip=10.0.0.2 srcport=51234 dstport=443 proto=6 action=accept`. Actual B: ADOPTED; line 2 read as `space_kv` with `syslog={pri}` only and `prefix_001="Nov"`, `prefix_002="21"`, `prefix_003="10:00:00"`, `prefix_004="fw1"`, `prefix_005="traffic"` (the Syslog header becomes five vendor fields, no hostname mapping for that line). The PAN event gets NO official field at all in the adopted draft (normalized top-level keys: `parserstudio_source` and the vendor object only), where the PAN line alone gets 7 (`hostname, srcip, dstip, srcport, dstport, proto_name, action`). Output names with reader paths appear: vendor fields `generic.fields.action` and `generic.kv.action` (input B), `generic.fields.src`, `body.src`, `body.dst` (PAN + a CEF line, also adopted, zero official mappings).
- Same with a UTF-8 line (`... msg="<Korean text> e-acute" user=<Korean name>`): adopted, line 2 one `message` field, FULL. The bytes are preserved; the pairs are not extracted.
- Expected: as before 714d272, no adoption (returns null with the pre-714d272 rule; executed), the natively readable lines keep their native reading.
- Not affected: PAN + a JSON line (not adopted), PAN only, PAN lines with CRLF or blank lines between them.
- Note: the readings themselves (`bsd_tagged_message` graded FULL, header as prefix tokens) are older compiler behaviour; what 714d272 introduces is their adoption for lines that were recognized natively.
- CONFIRMED by execution (real witness, pinned 7a255a6).

### F-03 (P2) 714d272: protocol evidence is lost for literal dotted keys

- Where: `src/guided/normalizationCandidates.ts:103-118` (`protocolValuesBeside`; line 109 falls back to the root object and then compares WHOLE key names with the protocol name list).
- Cause: the old code looked up `prefix + name` (`flow.` + `proto`) with `lookupFieldValue`, which finds a literal dotted key. The new code needs an object at the parent path; for a literal key `flow.sport` there is none, the root is scanned, and the key `flow.proto` is not equal to `proto`.
- Input (JSON, 2 lines):
```
{"flow.src":"10.0.0.1","flow.dst":"10.0.0.2","flow.sport":51234,"flow.dport":443,"flow.proto":"tcp"}
{"flow.src":"10.0.0.3","flow.dst":"8.8.8.8","flow.sport":8,"flow.dport":0,"flow.proto":"icmp"}
```
  and the same record as key=value: `flow.src=10.0.0.3 flow.dst=8.8.8.8 flow.sport=8 flow.dport=0 flow.proto=icmp` beside a tcp line.
- Actual: NEW `flow.sport->srcport HIGH`, `flow.dport->dstport HIGH` (ICMP type 8 / code 0 as ports). OLD (1d23770): both REVIEW. Also with every event ICMP, and with a numeric `net.protocol=1`.
- Expected: REVIEW, as before and as for the same record written as a nested object (control case: no difference old/new).
- CONFIRMED by execution (old vs new on the same events).

### F-04 (P3) 714d272: a protocol field holding an object or array no longer blocks a port

- Where: `src/guided/normalizationCandidates.ts:114` (`typeof value===object` is skipped).
- Input: `{"src":"10.0.0.1","dst":"10.0.0.2","sport":8,"dport":0,"protocol":{"name":"icmp","number":1}}` (2 such lines); also `"proto":["icmp"]`.
- Actual: NEW `sport->srcport HIGH`, `dport->dstport HIGH`. OLD: REVIEW (the object counted as unknown protocol evidence).
- Expected: REVIEW (unknown evidence must not approve a port), or the nested name read. The oracle line added by 714d272 ("object protocol field" -> HIGH) pins the new behaviour with a TCP record only.
- CONFIRMED by execution.

### F-05 (P1, wrong mapping still present) 7a255a6: the Host header is still proposed as `hostname` for other HTTP log shapes

- Where: `src/guided/normalizationCandidates.ts:184-193` (`HTTP_METHOD_NAMES`, `HTTP_REQUEST_NAMES`, `httpRequestRecord`) and `:224-225` (only `leaf===host`, only the object that directly holds the field).
- Assessment: the rule is not a Zeek string match, but it is not semantic either. It fires only when (a) the source leaf is exactly `host`, (b) the SAME object has a key named `method`, `request_method` or `http_method`, and (c) the same object has one of `uri, url, request_uri, user_agent, useragent, status_code, referrer, referer`. Any other naming keeps `hostname` with confidence HIGH. All cases below gave HIGH before the commit as well, so they are not regressions; the commit does not fix the class it names.
- Inputs that still give `-> hostname HIGH` (each executed through `preview(..., format auto)` and the candidate engine; one event each):
  1. nginx JSON: `{"time":"2026-11-21T10:00:00+09:00","remote_addr":"10.0.0.5","host":"shop.example.com","request":"GET /cart HTTP/1.1","status":200,"body_bytes_sent":512,"http_user_agent":"Mozilla/5.0"}` -> `host`
  2. Suricata EVE http: `{"timestamp":"2026-11-21T10:00:00.000000+0900","flow_id":1,"event_type":"http","src_ip":"10.0.0.5","src_port":51234,"dest_ip":"93.184.216.34","dest_port":80,"proto":"TCP","http":{"hostname":"example.com","url":"/index.html","http_user_agent":"curl/8.5.0","http_method":"GET","protocol":"HTTP/1.1","status":200,"length":1256}}` -> `http.hostname` (leaf is `hostname`, not `host`)
  3. pino-http style: `{"level":30,"time":1763719200100,"req":{"method":"GET","url":"/index.html","headers":{"host":"example.com","user-agent":"curl/8.5.0"},"remoteAddress":"10.0.0.5"},"res":{"statusCode":200}}` -> `req.headers.host` (a literal Host header)
  4. flattened keys: `{"@timestamp":"2026-11-21T10:00:00Z","http.method":"GET","http.host":"example.com","http.uri":"/index.html","http.status_code":200}` -> `http.host`
  5. key=value nginx: `time=2026-11-21T10:00:00+09:00 remote_addr=10.0.0.5 host=shop.example.com request="GET /cart HTTP/1.1" status=200 bytes=512` -> `host`
  6. Zeek http record without `method`: `{"ts":1763719200.1,"uid":"CmES5u32sYpV7JYN","id.orig_h":"192.168.1.10","id.orig_p":51234,"id.resp_h":"93.184.216.34","id.resp_p":80,"host":"example.com","uri":"/index.html","status_code":200}` -> `host`
  7. `{"time":"2026-11-21T10:00:00Z","client_ip":"10.0.0.5","host":"example.com","http_method":"GET","request_url":"https://example.com/","elb_status_code":200}` -> `host`
  8. `{"ts":"2026-11-21T10:00:00Z","client":"10.0.0.5","host":"example.com","verb":"GET","path":"/index.html","status":200,"agent":"curl"}` -> `host`
  9. method one level deeper: `{"ts":"2026-11-21T10:00:00Z","http":{"request":{"method":"GET"},"host":"example.com","url":"/x","status_code":200}}` -> `http.host`
  10. leaf `host_name` or `hostname` beside method/uri/status_code at the root -> HIGH.
- Expected: no automatic `hostname` for the requested host of an HTTP request, whatever the field names.
- Correct (executed): the Zeek http.log JSON record of the test is refused; the same record inside a Syslog envelope is refused for `body.host` while `syslog_hostname -> hostname` stays HIGH.
- CONFIRMED by execution.

### F-06 (P2) 7a255a6: a genuine device host name is now refused

- Where: same lines. The candidate is dropped (`return null`), it is not even offered as REVIEW; the test is `events.some(...)`.
- Inputs (OLD: `host -> hostname HIGH`; NEW: no candidate for `hostname`):
  1. `{"@timestamp":"2026-11-21T10:00:00Z","host":"web01","vhost":"shop.example.com","method":"GET","uri":"/cart","status_code":200,"clientip":"10.0.0.5"}` (shipper-added host, the requested host is in `vhost`)
  2. `date=2026-11-21 time=10:00:00 host=waf01 src=10.0.0.5 dst=10.0.0.80 method=POST url=/login action=block rule=942100`
  3. `{"ts":"2026-11-21T10:00:00Z","host":"api-node-3","method":"GetUser","status_code":0,"caller":"svc-a"}` (RPC method and status, no HTTP)
  4. `{"ts":"2026-11-21T10:00:00Z","host":"bastion01","method":"publickey","user":"bob","user_agent":"OpenSSH_9.6"}`
  5. three-line device sample, `host=fw01` in every line, ONE web-filter line: `date=2026-11-21 time=10:00:00 host=fw01 type=traffic src=10.0.0.5 dst=10.0.0.80 action=allow` / `date=2026-11-21 time=10:00:01 host=fw01 type=webfilter src=10.0.0.5 dst=93.184.216.34 method=GET url=http://example.com/a action=allow` / `date=2026-11-21 time=10:00:02 host=fw01 type=system msg="admin login"` -> `hostname` refused for the whole sample.
- Expected: at least a REVIEW proposal; a decision that looks at the value or at a second host-like field, not at two names.
- CONFIRMED by execution (cases 1 and 5 also in the old/new differential).

### F-07 (P3) 7a255a6: the rule is local to one consumer and has no mutant

- `fortiGateFalseFriend` is exported "for every consumer"; the HTTP rule is inside `incompatibleVendorMeaning` only. Executed: `reviewJsonataMapping` with the proposal `host -> hostname` on the Zeek http record returns status `CHECK_FIRST` ("The data type fits but the semantic meaning needs manual review."), not `BLOCKED` as for a FortiGate false friend (`src/guided/jsonataMappingAssist.ts:154-174`). CONFIRMED by execution.
- `scripts/verification/mcv2-semantic-candidate-mutants.mjs` is not changed by 7a255a6 and contains no mutant for `hostname` or the HTTP name lists (grep), so "Mutants 18/18 killed" in the commit message says nothing about this rule. By reading; the mutant script was NOT run.

### F-08 (P3) 714d272 + 1768ba8: the quote decides, not the reading

- Input (2 lines of one family; line 2 is line 1 with every value quoted):
```
Oct 15 00:14:27 bigip-waf01 ASM: unit_hostname=bigip-waf01,management_ip_address=10.1.1.10,request_status=blocked,ip_client=203.0.113.210,route_domain=0,method=POST,protocol=HTTPS,dest_port=443,dest_ip=10.20.1.25,uri=/api/login
Oct 15 00:14:28 bigip-waf01 ASM: unit_hostname="bigip-waf01",management_ip_address="10.1.1.10",request_status="blocked",ip_client="203.0.113.211",route_domain="0",method="POST",protocol="HTTPS",dest_port="443",dest_ip="10.20.1.25",uri="/api/login"
```
- Actual: first scan `none/csv/RECOGNIZED` (line 1, flagged) and `none/csv/BODY_MALFORMED` (line 2); not adopted. With the pre-714d272 rule it is adopted, both lines read as `delimited_kv` with the same ten fields and no cell moved (line 1 graded PARTIAL, line 2 FULL). Line 1 alone is not adopted either (same as before).
- Together with F-01 this shows the criterion of 1768ba8 is a proxy: a quote makes a cell-moving reading acceptable (F-01) and its absence makes a boundary-keeping reading unacceptable.
- Expected: decide on the reading (does it keep the delimiter cells of the line), not on the status of the first scan.
- CONFIRMED by execution.

## 3. Behaviour changes that follow the stated intent (not counted as defects)

Executed old vs new:
- N3: `srcip=10.0.0.1 dstip=10.0.0.2 srcport=51234 dstport=443 action=allow` + `srcip=10.0.0.3 dstip=10.0.0.4 srcport=- dstport=- action=deny`: ports HIGH -> REVIEW. Same for JSON `src_port` / `dst_port` with `null` in one event and `"transport":"tcp"`: HIGH -> REVIEW, because `transport` is deliberately not a protocol name. Any sample with one placeholder port now needs one of the nine protocol field names in every event that has a port.
- N4: `SrcPort=8 DstPort=0 Protocol=ICMP` beside a TCP line: HIGH -> REVIEW (intended). Side effect: `sport=51234 dport=443 Protocol=HTTPS` (application protocol in a capitalised field): HIGH -> REVIEW; the lower-case spelling was REVIEW already.
- `proto=TCP` (a name) is never sparse-approved (`proto -> proto_name`, leaf differs from target) while `proto=6` is; unchanged by these commits.

## 4. Tests and verification scripts added by the commits

- `headerlessCsvBoundedCompilerGate20261121.test.ts` uses a hand-made witness (every line `SOURCE_PARSED`). I checked the four MISREAD samples with the real witness: all are `SOURCE_PARSED` and are refused only by the rule (with the rule off they are adopted), so these tests are not vacuous. The test for 1768ba8 pins the BIG-IP line only; there is no case for a CSV line that is BODY_MALFORMED and misread (F-01) and no case with `unsupported===0` and a non-CSV recognized line (F-02).
- `officialNameSparseCoverage20261121.test.ts`, HTTP part: the four "must refuse" shapes use only names from the two lists of the implementation, and the "must keep" cases are the complement of the same lists. They assert the name lists, not the behaviour "a Host header is not a host name" (see F-05, F-06).
- `mcv2-candidate-independent-oracle.mjs`: the lines added are fixed expectations that mirror the unit tests; one earlier expectation was changed from HIGH to REVIEW in 714d272 to follow the new implementation (`generic.kv.srcip` without a format). By reading; not run.
- Not run by me: vitest, the mutant script, the AST census, CI.

## 5. Checked and found correct

- No template, compiler, contract or runtime file is changed by the three commits (git, see section 0).
- Ordinary well-formed logs, old vs new candidates identical (executed): key=value (2 events, sparse ports with `proto=6`), RFC 3164 + key=value, RFC 5424 + key=value, CEF, LEEF 1.0; five Generic Structural samples (BSD header + key=value, PRI + tag + key=value, Syslog + JSON body with and without a nested `nat` object, Syslog + CEF). All events FULL in both.
- N2 (record level from the reading): `body.srcport` HIGH under Syslog readings, `generic.kv.*` and `body.*` HIGH under Generic Structural, a nested JSON object (`flow.srcip`, `body.nat.srcip`) stays REVIEW. The reader containers produced by `src/genericStructural.ts` (`generic.kv`, `generic.fields`, `body`, `junos_sd`, `watchguard.kv`) are the ones the new expression accepts (reading); WatchGuard and Junos samples were not executed.
- N1: a valid headerless CSV line beside other lines keeps its rule (not adopted); PAN TRAFFIC without PRI is adopted alone, with CRLF and with a blank line between events; the flags stay aligned with the events (same `splitEvents`, length mismatch refuses). No state is shared between events in the changed functions (reading).
- BIG-IP ASM line with commas and `=` inside quoted values: adopted, every value intact (`violations="SQL-Injection,Cross Site Scripting"`, `uri="/api/login?a=1,b=2"`).
- UTF-8: a line with Korean text and an accented letter passes the byte-exact witness comparison and keeps its bytes.
- JSON number precision: a JSON event with `12345678901234567890` fails extraction ("Unsafe JSON numeric precision"), it is not FULL; this path is not touched by the commits.
- Zeek TSV (`#fields` header) is not parsed by the preview (unknown / fail); no candidate is produced.

## 6. Not checked

- Generated Ruby and browser-vs-Ruby agreement were not executed. The commits change no generator input, so the Ruby for a given draft is unchanged; F-01 and F-02 change WHICH draft is generated.
- The React component and Playwright flows were not run; `AutoParser.tsx:664-666` was reproduced in a script.
- CSV with a header row (needs column configuration), LEEF 2.0, WatchGuard, Junos structured data, declared forwarders, blank-line event boundaries.
- b117e05 and the uncommitted edits present in the worktree at the end of the audit.

## 7. Reproduction files (scratch, read-only for others)

`/home/aella/.local/state/ps-audit-20261121/phase3/`: `tree7a/` (export of 7a255a6), `pin/` (scripts bound to the export: `witness.py` real witness, `auto.ts` adoption as in AutoParser, `f1.ts` F-01, `f2.ts` `f3.ts` `f6.ts` F-02, `e5.ts` `e7.ts` F-03 F-04 and section 3, `e4.ts` F-05 F-06, `e8.ts` F-07, `f5.ts` F-08, `f4.ts` section 4, `e3.ts` `e6.ts` section 5, inputs `in1..in6.json`, witnesses `w1..w6.json`, `old_nc.ts` = normalizationCandidates.ts of 1d23770). Run from `tree7a` with `node backend/node_modules/tsx/dist/cli.mjs <script>`.
