# Phase 3 accuracy and final stabilization: verification (2026-11-24)

Scope: work order "Parser Studio — Phase 3 accuracy improvement and final stabilization" on PR #316
(branch `experiment/codex-accuracy-lab-20261117`), changes after e78feb9. No new features; no main merge, no
deployment, no change of KNOWN_TEMPLATES or approval constants.

## Measurement

Same corpus and scorer for every row: the real Chromium user journey (Analyze Logs → Review Fields → Map Fields
→ Create Parser → download) for 68 golden journeys (44 golden cases), 24 holdout, 23 public and 4 Issue #315
samples; the downloaded Ruby parser runs on Ruby 2.4.9 and is scored by the final-audit scorer (acc.py). Golden
expectations were not changed. Samples are PUBLISHER_ORIGINAL, MODIFIED_FROM_PUBLISHER or SYNTHETIC as recorded
in each case's meta.json.

- Before: T22 = 6b40461 (parent of e78feb9; e78feb9 changes only the family-scoped ChatGPT assist path).
- After: T25 = bdf76cd. The following commit (Q3 fixes below) changes only the ChatGPT regex recipe check and
  prompt, which no journey of this corpus uses.

| Metric | Before (T22) | After (T25) |
|---|---|---|
| Official mapping recall, cases with a downloaded parser (historical basis) | 148/182 (81.3%) | 171/182 (94.0%) |
| Official mapping recall, every golden case (UI-stopped cases count 0) | 148/242 (61.2%) | 171/242 (70.7%) |
| Original value preservation, downloaded cases (historical basis) | 176/179 (98.3%) | 177/179 (98.9%) |
| Original value preservation, every golden case | 176/239 (73.6%) | 177/239 (74.1%) |
| Event preservation (input units → output records) | 99/99 | 99/99 |
| False FULL (golden events emitted parsed with a golden value lost, changed or hidden) | 3/64 | 2/64 |
| Holdout canonical mapping CORRECT / WRONG (mapping precision) | 102 / 0 (100%) | 102 / 0 (100%) |
| Public set, Issue #315 set, Phase 3 set | — | no per-case change T23→T25 |

Vendor-level changes (canonical ok/total, preserve ok/total): Cisco Meraki 0/8 → 4/8 and 4/5 → 5/5; Trend Micro
Deep Security 2/5 → 5/5; WatchGuard Fireware 0/10 → 10/10; mixed envelope (generic) 18/24 → 24/24. All other
vendors are unchanged.

## Changes (e78feb9..HEAD)

- f5b9c3f: a mixed Auto Parser sample is routed by the family its router read each event with
  (eventProfiles discriminator `@reading_family`, carried out of band; browser, backend validation, Ruby).
- c1cf22b: CEF/LEEF extension keys the specification defines (src, dst, spt, dpt, proto, request; LEEF srcPort,
  dstPort, url) are approved in record families that carry them.
- 51112f1: documented WatchGuard Traffic Monitor and Meraki syslog layouts (Generic Structural).
- d0bfd10, 0e8edaf: browser journeys assert the routed project.
- 751b3e9: a ChatGPT regex recipe may not read text it keeps in no field (UNCAPTURED_SOURCE_TEXT); the prompt
  states the Ruby 2.4.9 static cost rule instead of refusing regex export.
- ad53b51, e65baa6, bdf76cd and the Q3 commit: fixes of three independent audits (below).

## Independent audits (separate executors)

| Id | Severity | Finding | Resolution |
|---|---|---|---|
| F1 | BLOCKER | A family-routed draft dropped sources another family maps (user=alice lost in FULL events) | Mixed routing carries them as vendor text (ad53b51, bdf76cd) |
| F2 | MAJOR | An author-written cef_version in a JSON/KV body switched on CEF key meanings | Only a CEF/LEEF reading counts (EventResult.bodyKind) |
| F3 | MINOR | WatchGuard layout read two numbers after ICMP as ports | Line declined |
| P1 | pre-existing | Ruby read relay hops from a source field named __parserstudio_forwarder_hops | Hops passed out of band |
| Q2-1 | MAJOR | Container rule (e65baa6) dropped root keys of JSON families | Carry is a property of the routing; Generic Structural keeps every field in parserstudio_source |
| Q2-2 | MAJOR | Carried mapping typed by another family's values (007 → 7, abc failed) | Carried sources are strings |
| Q2-3 | MAJOR | `(?:DENIED )?` passed the uncaptured-text check | Optional/variable non-blank piece reads uncaptured text |
| Q2-4 | MINOR | A family merge could overwrite a carried output | Refused (DESTINATION_COLLISION) |
| Q2-5 | MINOR | A family merge could leave out a mapped source | Refused (FAMILY_SOURCE_REMOVED) |
| Q3-2 | MAJOR (751b3e9) | A capture in a repeated group keeps its last repetition only | Rejected as uncaptured text |
| Q3-3 | MINOR | Prompt allowed optional literals; `\x20`, `\r` not white space | Prompt states the rule; escapes are white space |
| Q3-1 | MAJOR, pre-existing | A runtime key absent from the sample (or present only at another path, root vs body.*) is not in the output of a FULL event of a mixed, JSON, KV, CEF, LEEF or Syslog parser | NOT FIXED: owner decision needed (see below) |

P1 is verified on Ruby 3.2 (backend test); on Ruby 2.4.9 it is NOT VERIFIED directly (it uses the same out-of-band
tag as the reading family, which the Ruby 2.4.9 journeys exercise).

Each fixed finding has a repro test that fails before the fix:
`src/guided/independentAuditFindings20261123.test.ts`, `backend/test/forwarder-hops-out-of-band-20261123.test.ts`.

## Validation of the final HEAD

Whole Vitest, Python unit, backend suite (14 known failures: the two owner template approvals and environment-
only drain3/legacy Stellar client tests), semantic candidate mutants (all killed), AST mutation census 90.36%
(≥ 90%), Chromium Playwright at bdf76cd 441 passed, 0 failed (62 skipped by their own guards), CI browser shards and native jobs green; CI web-quality fails
only on the two owner-approval tests.

## Templates (approval pending, constants unchanged)

- Ruby template set: sha256 `b031810fcf88d4afb2c6804714556209a7dde83fe0859364528b9042899f8c8c`
  (contracts/ruby-template-set.v1.json; approved constant 16824f8e…c7e4 unchanged).
- POC template: sha256 `2362d0c679f5ea80490eafcb17bd8c88ce7e6eea460ed5a7e2f63d00ad083e64`
  (approved constant 4efddd8b…bfb8 unchanged).
These replace the earlier pending digests 4b37d899…dd9c and f4d22b47…19ca.

## Remaining (not fixed, by policy or needing an owner decision)

1. Q3-1 / unseen runtime keys (pre-existing, all non-Generic-Structural formats): the generated parser emits
   mapped sources only, so a key the sample never showed is not in the output of a FULL event. Options: a vendor
   catch-all for unmapped leaves, or PARTIAL for an event with unmapped leaves. Both change every generated
   parser and the template set.
2. Fortinet `CEF: 0|` (space after the colon, as Fortinet documents for FortiOS 6.0.3–7.6): read as space_kv,
   deviceExternalId hidden in a larger value; the 2 remaining false FULL events and 2 preservation misses.
   Accepting it changes the CEF grammar contract (TS, generated Ruby, Python) and an existing policy test.
3. 14 golden cases stop at Review Fields by design (ChatGPT required: AWS CloudTrail Records, pretty JSON,
   Suricata multi-line, Linux audit, Cisco ASA, Juniper RT_FLOW, Windows XML, W3C IIS header; positional CSV
   names to confirm: PAN-OS TRAFFIC CSV, quoted CSV; one unreadable event in a sample: BSD tagged, CEF/LEEF
   escaped envelopes, Elastic CEF envelopes, RFC 5424 versions).
4. mixed_types_kv ports without TCP/UDP evidence and Meraki IDS `ip:port` endpoints stay vendor fields (no proof
   of meaning); r2_invalid_types needs a runtime invalid-value fallback.
5. Real Stellar Cyber installation tests are the owner's (out of scope).
