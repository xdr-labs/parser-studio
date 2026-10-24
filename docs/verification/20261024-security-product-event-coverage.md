# Security product event diversity and existing-field preservation

Date: 2026-10-24. Scope: security-solution logs only (NGFW, IDS/IPS, WAF,
NDR/NSM, EDR/XDR, VPN, cloud-security and identity products). Infrastructure
and general application-observability corpora such as Hadoop, HDFS, Spark
and ZooKeeper are not part of this new acceptance set.

## Product change

- Describe only observed literal event-type selectors from the user's exact
  original records: type/subtype/eventtype, JSON event_type, CEF signature
  and LEEF event ID. No manufacturer grammar or absent event is invented.
- Warn when the supplied examples show just one source event category and
  therefore do not establish support for traffic, IPS, antivirus, VPN,
  authentication or any other unobserved category.
- When a browser preview matches the entire unchanged source, include
  previously extracted field paths and actual normalized mapping identities
  (source, target, type, group) without copying field values into the summary.
- Keep the already implemented strict parser import, field-preservation
  regression comparison and independent holdout gates unchanged. Propose
  REVIEW_REQUIRED if additional field meanings or event shapes cannot be
  established from source evidence.
- Do not truncate a mapping-evidence JSON object mid-string. The user must
  receive a syntactically complete copyable prompt.
- No additional UI mode, no automatic LLM provider transfer, no production
  or native target installation.

## Security-only provenance

Official public vendor documentation (not actual customer captures):

- FortiGate sample logs: https://docs.fortinet.com/document/fortigate/7.6.2/administration-guide/986892/sample-logs-by-log-type
- Suricata EVE JSON examples: https://github.com/OISF/suricata/blob/main/doc/userguide/output/eve/eve-json-format.rst
- Zeek network-security examples: https://github.com/zeek/zeek-docs/tree/master/logs

Source originals were decoded from vendor HTML, or reserialized as compact
JSON with field values unchanged. Explicitly exclude any CLI output line
prefix. Existing product security fixture examples are SYNTHETIC, not
manufacturer-captured source evidence.

Private test manifest:
  /home/aella/.local/state/parserstudio-security-scope-20261024/security-corpus.json

Corpus has 86 distinct examples (57 vendor-documented, 29 project-synthetic).
229 real browser prompt scenarios comprise 200 mixed-event original-vendor
document combinations and 29 project-synthetic examples. Scenarios reuse
the distinct examples. Do NOT claim 229 independent manufacturer captures.

## Measured scoped evidence

- Original browser generation before the no-truncation correction: 229/229
  source identity, SHA-256, observed coverage evidence, no third-party calls.
- Repeated actual browser tests after no-truncation correction: 229/229,
  including 229 complete evidence JSON blocks, zero API 5xx / JS exceptions,
  and original input source identities preserved. 217/229 contained
  current-preview extracted source-field evidence.
- Additional unit/security workflow/holdout test results are recorded
  in GitHub's exact-head acceptance comment and local logs.
- Not a new model-first-response success percentage, not a guarantee that
  all future firewall firmware records parse correctly and not a real
  Stellar Cyber 7.0 DP/Interflow compatibility test.

## Safety

Use exact-source-preview binding and fail closed on stale/mismatched events.
Field examples never change source bytes. No raw public vendor samples or
customer logs are included in the Git commit, and no unexpected external
AI requests are issued during the tests.
