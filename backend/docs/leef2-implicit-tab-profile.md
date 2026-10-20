# Explicit implicit-TAB LEEF 2.0 profile

## User outcome and source interpretation

Some LEEF 2.0 producers use TAB-separated extension fields without an explicit delimiter slot. The source analyzer already preserves these fields as `LEEF_2_IMPLICIT_TAB`. This successful source interpretation must not be downgraded merely because the earlier downloadable parser supports a smaller grammar.

The additional `leef2_implicit_tab` Generic Structural profile compiles the bounded standalone form directly. The original event stays unchanged through analysis, review, mapping and parser generation. This profile does not rewrite a sample into `|0x09|` form or claim that a parser built from a rewritten sample supports its original input.

This variant is not universally malformed LEEF. [IBM's LEEF event components](https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components) document the explicit delimiter form; [Trend Micro's event syslog formats](https://docs.trendmicro.com/en-us/documentation/article/trend-micro-cloud-one-workload-security-event-syslog-message-formats) document an optional delimiter when TAB is used. The supported compiler contract here is deliberately narrower than all possible producer variants.

## Closed grammar and limits

The helper accepts exactly `LEEF:2.0|`, four nonempty header fields (`vendor`, `product`, `product_version`, `event_id`), their four unescaped pipe separators, an optional single leading TAB, and 2–55 distinct TAB-separated `key=value` fields.

The complete record is at most 8 KiB. Each header value is at most 256 UTF-8 bytes and each extension value at most 512 UTF-8 bytes. Five header values plus at most 55 extension values fit the 60-field explicit mapping budget. Header values cannot contain TAB or backslash and cannot consist solely of ASCII spaces. Source keys use `[A-Za-z_][A-Za-z0-9_-]{0,63}`; prototype-related keys are excluded. Extension values must be nonempty.

Only literal TAB separates extension fields. Spaces, quote marks, backslash spellings, non-ASCII spaces and other Unicode characters remain literal source data. The helper never trims or unescapes accepted values. ASCII control characters other than TAB, including CR, LF and DEL, are rejected. The browser helper also rejects an unpaired UTF-16 surrogate so UTF-8 encoding cannot invent a replacement value.

An explicit delimiter slot, any additional pipe, a duplicate key, empty field/value, consecutive or trailing TAB, missing header separator, oversized token or multiple physical records stays outside this profile. In particular, an invalid explicit delimiter is never reinterpreted as implicit TAB. A Syslog wrapper and escaped header pipes remain outside this standalone subset. Rejection retains the original source for review.

## Output and compatibility

The output contains `leef_header`, `leef_extension`, and `generic: {mode: "leef2_implicit_tab", source_raw: <original event>}`. Header and extension namespaces remain separate when they use the same source key. No delimiter value, timestamp, dictionary alias, source/destination role or manufacturer meaning is inferred.

The selected profile is explicit in the project and recipe and must be advertised by the backend. Existing LEEF extraction and Generic Structural V15 routes retain their previous behavior. The profile is additional parser capability; a source preview or an older V15 capability response alone does not establish support.

The shared fixture has eight positive examples and 37 negative controls. It includes the original authored NSS sample, unrelated producer names, Unicode data, literal escapes, source-key collisions across namespaces and exact byte/field boundaries. The TypeScript and emitted Ruby helpers must produce the same complete source tree. Additional browser qualification must use the original source through field review, mapping and actual Ruby/CONF downloads. These tests establish only the reviewed authoring subset, not manufacturer-wide accuracy, proprietary loader compatibility or live sensor installation.
