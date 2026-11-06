# Semantic Mapping Acceptance — Issue #232

## Evidence boundary

The original two-event Juniper SRX RFC5424 tutorial sample is stored at
`tests/fixtures/docs-practice-20261104/01-juniper-srx.log`. It is a
published documentation example, not an independently attested device
capture or a proof of Stellar Cyber 7.0 DP import.

Event 1: ICMP protocol ID 1, source-port 594 and destination-port 10400.
These are not Layer 4 TCP/UDP ports; do not emit Stellar srcport/dstport.
Event 2: UDP protocol ID 17, source-port 37233 and destination-port 161.
Emit official srcport=37233 and dstport=161. Preserve the original vendor
source-port and destination-port values in both events.

## Deterministic, bounded policy

A MappingRule may contain a validated when predicate with sourcePath,
operator=in and 1-16 exact string values, such as values ["6","17"] and
sourcePath syslog_sd.element_1.params.protocol-id. Both the browser
preview and generated Ruby consume the same conditional mapping IR.
Unknown protocols omit only the conditional official output, not the
whole event. Manufacturer-specific values remain accessible.

AI/JSONata is limited to read-only selectors; no arbitrary JSONata
functions or generated Ruby execution. Local deterministic evidence
supplies any condition. The user must review uncertain semantic mapping
proposals before applying them.

## Acceptance labels

- Precision: correct emitted official values / all emitted official values.
- Eligible recall: correct emitted eligible values / all eligible values.
- Per-event coverage: eligible fields normalized correctly for each event.
- False-positive count: official fields assigned without valid semantics.
- Vendor preservation: original manufacturer data retained unchanged.

The Juniper gold oracle requires 2/2 port precision and recall, zero
false-positive ICMP ports, preservation of both raw port pairs, TCP
holdout success and unknown-protocol omission without event rejection.
All other normalized fields, including protocol, source/destination IP
and policy name, remain usable. Vendor-only source fields do not count
as failed official mappings merely for being vendor-specific.

Cross-vendor synthetic tests for Fortinet, Cisco ASA, PAN-OS, WAF and
IAM must remain distinct from independent manufacturer capture metrics.

## Verification and release

Validation includes frontend tests, backend schema tests, native Ruby
parity (both parser templates) in GitHub CI, real browser authoring
and generated DRAFT Ruby/conf. Passing these tests does NOT mean actual
Stellar Cyber 7.0 DP ingestion or import has been verified. Merge and
public preview deployment require separate owner approval.

Extension of auto-inference to other products needs semantic provenance,
gold-labelled original and holdout records, no false positive mapping,
and browser/native equivalence.
