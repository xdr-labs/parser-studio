# Security-System Source Extraction — Primary PoC Scope

Status: **ENGINE POC ONLY. Security source scope supersedes generic prose mining.**

## Owner priority

The primary targets are ordinary security-product logs, including complex AWS
WAF, IPS/IDS, NGFW, EDR and related security-service events. Complexity means
nested objects and rule groups, repeated arrays and HTTP headers, CEF/LEEF
extensions, escaped delimiters, payload fields and transport framing. It does
not mean recovering semantic variables from arbitrary sentence-style OS,
Hadoop, Spark or application messages.

Preserve every native source name/path, type, value, array occurrence and
original byte position. A message, rule string or payload is an opaque original
field unless its enclosing format explicitly defines further structure.
Stellar Dictionary normalization is optional and later. Masking is lowest
priority: recognize visible masking when practical and preserve it; never
reconstruct hidden values. A source fixture with no literal mask marker may
still have been anonymized upstream.

## Primary evidence recorded in this change

| Evidence | Events | Original scalar fields | Result |
| --- | ---: | ---: | --- |
| AWS WAF integration fixtures + six official AWS examples; Suricata alert, metadata, DNS, HTTP/TLS and mixed EVE fixtures | 77 | 2,110 | Existing and candidate trees and every independently verified byte span agree; zero FP/FN |
| Documented Suricata CEE framing applied to existing EVE samples, including BSD and RFC5424 envelopes | 198 derived cases | 5,127 payload fields | Baseline 0 TP / 5,127 FN; candidate 5,127 TP / 0 FP / 0 FN, all payload byte positions correct |
| Additional synthetic security edge cases | Separate focused tests | Not pooled into original corpus | 200 repeated HTTP headers, multiple WAF rule groups/match-detail arrays, maximum unsigned flow ID, exact payload/rule strings, null/empty containers, Unicode and ambiguous display paths |

The 198 transport cases are **derived format variants**, not 198 additional
production or independently collected original events. Existing known security
fixtures remain regression evidence. None of these results is a universal
parsing or proprietary Stellar/native compatibility claim.

The reference decoder uses independent standard-library JSON scalar
recognition, a separate token/path ledger and exact source slices. No external
normalized/semantic gold or LLM output is used as source-field truth. The
benchmark explicitly accounts for every input and does not drop exclusions.
Raw sources and official example text stay in ignored research caches.
Only provenance, source hashes and aggregate metrics are Git-tracked.

## Implemented bounded repair

`security_source.parse_security_source()` recognizes an exact `@cee: ` JSON
prefix at the event start or the body of a verified Syslog envelope. It reuses
existing JSON/KV/CSV/CEF/LEEF decoders elsewhere. It does not search arbitrary
messages for a JSON substring. Invalid CEE JSON cannot fall back to a CSV
candidate; it retains the original raw event with an explicit incomplete
status. Original payload offsets are shifted through each documented envelope
without rebuilding or normalizing the data.

The old `parse_source()` default remains unchanged for historical baseline
reproducibility. This security adapter is an engine PoC entry point, not Web UI,
Ruby/CONF, DP or sensor integration.

## Suspended work preservation

The generic message-body experiments present at the owner correction remain
uncommitted and unmodified. Their fingerprints were recorded in ignored
`.cache/security-scope-transition-wip.json`. Do not run or promote these as the
primary roadmap. In particular, F1 changes on Loghub template variables are
not evidence of complete security-product source extraction.

## Ordered remaining security roadmap

1. Extend actual WAF/IPS/NGFW source fixtures and independently tested vendor
   versions, retaining complete native fields rather than selecting only
   source/destination/user roles. Prioritize commercial IPS and complex CEF/
   LEEF alongside JSON and vendor KV/CSV.
2. Fix only measured field/framing/boundary failures, then qualify the same
   security corpus and independently collected version/format holdout.
3. Preserve exact licensing/provenance and decide the engine architecture from
   security-source evidence. Research fixtures are not commercial parser assets.
4. Add verified Stellar Dictionary mappings after source extraction; otherwise
   keep native fields. Masking recognition remains lowest priority.
5. Native Ruby+CONF, actual DP/sensor qualification and product integration are
   separate authorized gates, not completed by this PoC.

## Source contracts and attribution

- AWS WAF log fields: https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
- AWS WAF official log examples: https://docs.aws.amazon.com/waf/latest/developerguide/logging-examples.html
- Suricata EVE JSON, optional CEE prefix, alert and protocol metadata:
  https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Upstream fixtures: `elastic/integrations`, pinned revision
  `99b5848f5863e395dc61f2ce227efd3969af826b`; individual paths/hashes and
  source classes are in `security-source-manifest.json`. Local research/review
  only, not approved for raw redistribution; upstream license notice retained.

Reproduce the primary aggregate benchmark with local pinned caches present:

```bash
python3 poc/vendor_engine/benchmark_security_sources.py
python3 -m unittest discover -s poc/vendor_engine -p 'test_security_source.py' -v
python3 -m unittest discover -s poc/vendor_engine -p 'test_benchmark_security_sources.py' -v
```
