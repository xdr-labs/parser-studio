# Juniper RFC 5424 Structured Data → Stellar Cyber 7.0 field-mapping audit

Date: 2026-11-04
Scope: Parser Studio Auto Parser, Map Fields, local preview, backend authoring contract; no production deployment.

## Primary evidence

- Stellar Cyber 7.0.x Standard Metadata Dictionary: https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm
- Juniper SRX *Monitoring Security Flow Sessions*, tables for RT_FLOW_SESSION_CREATE, CLOSE and DENY: https://www.juniper.net/documentation/us/en/software/junos/flow-packet-processing/topics/topic-map/security-flow-session-and-error-handling.html
- Juniper RT_FLOW_SESSION_CREATE official field inventory: https://apps.juniper.net/syslog-explorer/?msg=RT_FLOW_SESSION_CREATE&rel=25.4R1&sw=Junos+OS
- Pinned Stellar catalog in `src/guided/stellarMetadataCatalog.ts` (documented public 7.0.xs, **not** a DP import certification).

## Source-path vs target-path interpretation

The left UI column is the **extracted source path**, e.g. `syslog_sd.element_1.params.source-address`. This is correct RFC 5424 SD structure and must remain unchanged. The right column is the **output field**, which should be `srcip` if the source's semantic meaning and observed IP values agree. The prior `Juniper.syslog_sd_element_1_params_source-address` was a vendor-only fallback, not a Stellar field.

The UI showed 41 source fields, 2 official mappings, 39 vendor-only mappings, and no HIGH bulk suggestions. The screenshot alone does **not** supply the full 41-field JSON/raw samples; exact per-value validation of that session is not asserted here.

## Mapping decisions (public metadata semantics and sample evidence)

| Juniper SD-PARAM (under `syslog_sd.element_N.params.`) | Stellar 7.0 target | Confidence / treatment | Why |
| --- | --- | --- | --- |
| `source-address` | `srcip` | HIGH when valid IP and unambiguous | Packet source IP |
| `destination-address` | `dstip` | HIGH when valid IP and unambiguous | Packet destination IP |
| `source-port` | `srcport` | HIGH for non-ICMP/IGMP, REVIEW for ICMP/IGMP | Stellar specifies Layer 4 source port; Juniper ICMP examples carry port-like identifiers |
| `destination-port` | `dstport` | HIGH for non-ICMP/IGMP, REVIEW for ICMP/IGMP | Same protocol-specific guard |
| `protocol-id` | `proto` | HIGH for integer 0–255 when unique | IP protocol number, not application |
| `policy-name` | `rule.name` | HIGH when informative and unique | Juniper policy that permitted/denied session, Stellar verified rule namespace |
| `icmp-type` | `icmp_type` | REVIEW when missing from other event families | Juniper ICMP type and published Stellar 7.0 field |
| `username` | `username` | HIGH only for informative value in every sample | `N/A` does not prove a user identity |
| `service-name` | none automatic | vendor-only | Juniper's traversed application/service (e.g. `junos-https`), not Stellar Layer 4 `proto_name` |
| `nat-source-address`, `nat-destination-address` | none automatic | vendor-only | Translated address must not overwrite original source/destination |
| `nat-source-port`, `nat-destination-port` | none automatic | vendor-only | Translated port must not overwrite original L4 ports |
| `src-nat-rule-type`, `src-nat-rule-name`, `dst-nat-rule-type`, `dst-nat-rule-name` | none automatic | vendor-only | Distinct NAT policy vs security policy semantics |
| `connection-tag`, `nat-connection-tag` | none automatic | vendor-only | Distinct vendor/session-specific identifiers |
| `source-zone-name`, `destination-zone-name` | none automatic | vendor-only | No proven matching destination in pinned scalar 7.0 catalog |
| `session-id`, `session-id-32` | none automatic | vendor-only | No validated equivalent scalar destination |
| `reason`, `roles`, `packet-incoming-interface` | none automatic | vendor-only | Meaning differs by event family, origin, and representation |
| `application`, `nested-application`, `application-category`, `application-sub-category`, `application-risk`, `application-characteristics` | none automatic | vendor-only | Vendor application classification != Stellar DPI-derived appid metadata without independent contract |
| `encrypted`, `src-vrf`, `dst-vrf`, `src-vrf-grp`, `dst-vrf-grp`, `tunnel-inspection`, `tunnel-inspection-policy-set` | none automatic | vendor-only | Protocol/meaning/value-type contract not established |
| `forwarded-for`, `source-tenant`, `destination-service`, `dst-identity-context-name`, `dst-identity-context-roles`, `gbp-src-tag`, `gbp-dst-tag` | none automatic | vendor-only | Preserve source-specific fields rather than infer a semantic alias |
| `packets-from-client`, `packets-from-server`, `bytes-from-client`, `bytes-from-server` | none automatic | vendor-only | Network flow direction semantics require review before mapping to Stellar in/out totals |
| `elapsed-time` | none automatic | vendor-only | Juniper elapsed time units must be verified before conversion to Stellar millisecond `duration` |

Header fields: `syslog_timestamp → timestamp` and `syslog_hostname → hostname` are pre-existing mappings in current UI. `syslog_pri`, `syslog_version`, `syslog_appname`, `syslog_procid`, `syslog_msgid`, `syslog_structured_data`, and `syslog_sd.element_N.sd_id` remain source/vendor context; RFC5424 priority and message ID are not interchangeable with Stellar severity and action.

## Root cause / technical path

1. RFC 5424 Structured Data extraction preserves leaf paths (verified by existing parser tests).
2. `suggestUnmappedFields` correctly preserves unmapped fields under vendor namespace.
3. `normalizationCandidates.ts` lacked the literal hyphenated aliases; `source-address` did not match `sourceaddress` or `source.ip`.
4. `prepareAutoParserDraft` therefore lacked HIGH candidates to upgrade output to standard targets. Review UI faithfully displayed the suboptimal vendor mapping.
5. A separate prior overmapping risk mapped `protocol: HTTPS` to `proto_name` because only the `string` data type was checked. The 7.0 description is **Layer 4** protocol; this now requires compatible names for HIGH confidence.
6. IP value validation, two-source target collisions, empty placeholders, event-family sparsity, and ICMP pseudoport semantics remain fail-closed/manual review conditions.

## Regression verification

- Unit: `src/guided/juniperSdNormalization20261104.test.ts` exercises two log families, standard targets, ICMP guards, incomplete identity, event-scope sparsity, duplicate SD elements, Auto Parser draft, backend conversion and normalized preview.
- Browser E2E: `tests/juniper-sd-field-normalization-20261104.spec.ts` uses a real Chromium session from raw Juniper syslog to Map Fields; validates visible normalized names and preservation of vendor-specific fields.
- Existing generic WAF regression expectation updated: application value `HTTPS` remains vendor-local, not official L4 `proto_name`.
- Generated parser pair validation is compile-contract / browser preview only; actual Stellar Cyber 7.0 DP import, receiving, and production semantics remain **unverified**.
- Dev-atlas does not currently have a `ruby` executable. The pre-existing Ruby runtime parity test cannot execute locally; it is not reported as PASS.

## Remaining separate product considerations

- `RT_FLOW_SESSION_CREATE` / `DENY` in `syslog_msgid` could drive event-class or action mapping, but assigning a constant/conditional `action` is **not** equivalent to relabeling the full message ID. It would require a separate, explicit, tested event-value transform.
- An E2E test with the user's full original **41-field raw sample** is necessary to assert exact counts and per-field semantics for that exact dataset. The screenshots alone only establish visible rows and summary metrics.

## 2026-11-09 vendor-local destination naming correction

The prior automatic fallback flattened source path dots and the mapping review
could show the manufacturer-qualified output path as if it were a destination
field name. These are distinct concepts. The original extracted source path
remains unchanged, and vendor-only destination names now prefer the final,
unchanged path segment:

- Source `syslog_sd.element_1.params.source-port` → destination `source-port`.
- Source `syslog_sd.element_1.params.destination-port` → destination `destination-port`.
- Source `syslog_sd.element_1.params.service-name` → destination `service-name`.
- If multiple sources would use the same leaf name, keep each safe original
  source path, e.g. `syslog_sd.element_1.params.source-port`.
- Do not prepend the manufacturer to the destination input or field-change
  preview; the native serializer still groups vendor-only keys inside the
  manufacturer object as required by its output contract.
- Official Stellar dictionary mappings (e.g. `srcip`, `dstip`, `proto`) remain
  authoritative when supported by the source semantics and values.
- Only untouched auto-generated legacy fallback names are migrated; user
  edits and official mappings are preserved.

Deterministic regression coverage: `vendorFieldNames.test.ts`,
`NormalizationMappingReview.test.tsx`, `issue232SemanticMapping.test.ts`, and
Chromium `tests/juniper-sd-field-normalization-20261104.spec.ts`.
