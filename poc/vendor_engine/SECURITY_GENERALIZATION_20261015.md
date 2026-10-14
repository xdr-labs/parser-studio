# Security Log Source Generalization — 2026-10-15

## Scope

This validation extends the accuracy-first Multi-Pass source engine with additional public security-product log shapes. It scores only source extraction:

- literal source field/value preservation;
- original value type where the source format carries one;
- exact UTF-8 value spans;
- complete raw-event accounting;
- conservative incomplete/malformed handling.

Field semantics, normalized destination names, and whether a value represents a source address, destination address, user, action, or other business meaning are intentionally outside this validation.

## Public-source cases exercised

The regression cases are minimized from public integration fixtures or documentation and do not contain customer data.

| Family | Public evidence shape | Previous result | Candidate result |
| --- | --- | --- | --- |
| F5 ASM | RFC3164-like header followed by `ASM:CEF:...` with no space after the tag colon | PARTIAL | SOURCE_PARSED |
| Zscaler NSS | RFC5424 + LEEF 2.0 with an omitted delimiter field and literal TAB-delimited extension | PARTIAL | SOURCE_PARSED |
| Juniper SRX | RFC5424 MSGID immediately followed by structured data | RAW_ONLY | SOURCE_PARSED |
| Juniper SRX legacy | BSD Syslog + `RT_FLOW_SESSION_*` positional body | PARTIAL | SOURCE_PARSED |
| Cisco Meraki | Epoch/custom Syslog `flows`, `ids-alerts`, and `urls` records | RAW_ONLY/PARTIAL | SOURCE_PARSED |
| WatchGuard Firebox | BSD/PRI headers with optional serial/device time/PID and mixed positional + KV traffic bodies | PARTIAL | SOURCE_PARSED |
| Sophos XG | PRI + quoted key/value security event | SOURCE_PARSED | SOURCE_PARSED |
| Netskope | BSD/PRI + CEF security event | SOURCE_PARSED | SOURCE_PARSED |
| SentinelOne-shaped EDR JSON | Nested object/array/bool/int/null source values | SOURCE_PARSED | SOURCE_PARSED |
| CrowdStrike-shaped EDR JSON | Nested event/metadata JSON | SOURCE_PARSED | SOURCE_PARSED |

Representative public references reviewed include:

- Azure Sentinel F5 ASM ASIM raw-log fixtures.
- Tenzir `test/inputs/syslog/leef-over-syslog.log` for Zscaler NSS.
- Elastic Integrations Sophos XG and WatchGuard Firebox sample logs.
- Sumo Logic and Elastic/Sentinel community Cisco Meraki samples.
- Public Juniper SRX structured and legacy RT_FLOW examples.
- Elastic/Sumo Logic public EDR documentation examples.

## Implementation constraints

The general parser remains strict. Product compatibility behavior is additive and bounded:

- F5-style tag adjacency is accepted only when the bytes following the tag begin a recognized structured payload.
- RFC5424 structured-data adjacency is enabled only by the security adapter; the generic RFC5424 parser remains strict by default.
- LEEF 2.0 implicit-TAB compatibility requires five standard header fields, a literal TAB, and a completely valid TAB-delimited key/value extension. No delimiter field is invented.
- Meraki, WatchGuard, and Juniper legacy profiles run only when the generic source parser is incomplete and only promote a complete source-accounted result.
- Positional tokens remain positional. The engine does not invent semantic field names.
- Malformed/lookalike controls remain incomplete rather than being promoted to `SOURCE_PARSED`.

## Verification

Focused public generalization and Multi-Pass regressions passed after the changes. The final full `vendor_engine` acceptance run completed **332 tests PASS / 19 optional skips / 0 failures / 0 errors**, using the same ignored reference fixtures and local optional Drain3 dependency as the qualified PR #16 environment.

This work does not claim native Ruby/CONF compatibility, Stellar target compatibility, semantic normalization accuracy, or universal open-world vendor coverage.
