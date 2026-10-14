# Verified Stellar Dictionary normalization — bounded P1 pass

Status: **development PoC, source extraction preserved, Native/target NOT VERIFIED**

This pass runs only **after** the accuracy-first Multi-Pass source extractor. It
never changes the source event, source tree, raw SHA, source spans, parser
status, or the `normalization_attempted=false` source-extraction evidence.
Unknown or unsupported fields stay available under their original vendor identity.

## Authoritative target contract

Stellar Cyber Parser Studio 7.0 directs users to the Standard Metadata
Dictionary during Field Mapping to choose standard schema fields with their
documented data types:

- https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Parser-Studio-Parsers.htm
- https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm
- retained compatibility reference:
  https://docs.stellarcyber.ai/prod-docs/6.5.xs/Common/Metadata-Dictionary.htm?TocPath=REFERENCE%7C_____8

The initial bounded contract contains only fields whose current documented name
and type are explicit: `action:string`, `srcip:ip`, `dstip:ip`,
`srcport:integer`, `dstport:integer`, `proto:integer`, `proto_name:string`,
`hostname:string`, `username:string`, `url:string`, and `severity:integer`.

No field is normalized merely because a value *looks* like an IP address, port,
user name, URL, action, or protocol.

## Source semantic evidence

Two mapping classes are deliberately separated:

1. **Exact Dictionary-name mapping** — an extracted source field already has
   the exact documented Stellar field name. This is a lossless identity-style
   projection with target type validation. It is compatibility evidence, not a
   claim that every vendor independently documented the same semantic role.
2. **CEF standard alias mapping** — only inside an extracted CEF extension
   container with CEF provenance, the following independently standardized CEF
   keys may be mapped:
   - `src -> srcip`
   - `dst -> dstip`
   - `spt -> srcport`
   - `dpt -> dstport`
   - `act -> action`

CEF evidence:
https://community.opentext.com/cfs-filesystemfile/__key/communityserver-discussions-components-files/224/3731.CommonEventFormatV25.pdf

Fortinet independently documents the same network-field semantics for native
FortiGate traffic logs (`srcip`, `dstip`, `srcport`, `dstport`, `proto`,
`action`) and its CEF conversion (`src`, `dst`, `spt`, `dpt`, `proto`, `act`):

- https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- https://docs.fortinet.com/document/fortigate/7.2.7/fortios-log-message-reference/949981/traffic-log-support-for-cef

PAN-OS positional CSV columns are **not** mapped by column number here. Their
source meanings remain unresolved until an independently version-qualified
column schema is attached to the parser profile.

## Fail-closed rules

- IP fields require a syntactically valid IPv4/IPv6 source string.
- Ports require integer values in `0..65535`.
- `proto` requires integer `0..255`.
- Stellar top-level `severity` requires integer `0..100`; string vendor
  severities are retained unmapped instead of coerced.
- Multiple source occurrences proposing the same target are ambiguous and none
  is silently overwritten.
- Generic aliases such as `src`, `dst`, `user`, `host`, or `port` are never
  inferred outside their independently documented source grammar.
- No Regex, LLM, ECS-name similarity, value-shape heuristic, or hidden-value
  reconstruction participates in Dictionary mapping.

## Value-free acceptance evidence

`benchmark_stellar_dictionary.py` publishes counters only; raw values and
customer/vendor event bodies are never written to its summary.

Current pinned development corpus:

| Evidence set | Records | Source occurrences | Mapped | Preserved unmapped | Source/raw/tree preserved |
| --- | ---: | ---: | ---: | ---: | ---: |
| Commercial security corpus | 392 | 27,991 | 626 exact-name | 27,365 | 392/392 |
| Commercial CEF corpus | 22 | 482 | 39 CEF-standard alias | 443 | 22/22 |
| Authored CEF boundary corpus | 96 | 900 | 120 CEF-standard alias | 780 | 96/96 |

Six commercial-source occurrences named `severity` are string values while the
Stellar Dictionary field is integer. They are explicitly rejected and retained
as vendor fields. This is expected type safety, not parser failure.

These counts measure **mapping coverage**, not open-world semantic accuracy.
Source extraction remains independently gated. Native Ruby/CONF behavior and
actual Stellar target import remain separate qualification gates.

## Product integration contract

The local Multi-Pass preview may expose a **value-free exact-key projection**
containing only source path, documented target field/type, and exact UTF-8 byte
span. It must not include source values, infer aliases automatically, or claim
Native/target verification. The richer CEF-standard normalization pass remains
an explicit post-extraction operation.

Masked/redacted reconstruction remains out of scope and lowest priority; visible
tokens may be preserved but hidden content must never be reconstructed.
