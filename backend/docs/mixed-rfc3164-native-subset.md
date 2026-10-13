# Strict RFC3164 TAG KV mixed one-line native subset

## Supported opt-in input families

ParserProject v0.1 extraction format `mixed` can now explicitly allowlist `rfc3164_kv` together with the existing standalone JSON/KV/CEF/LEEF and RFC5424-wrapped CEF/LEEF. The project must select **2–4 distinct families**. On a leading RFC3164-like `<PRI>Mon ...` line the generated Ruby routes to the already Native-tested `parserstudio_syslog_rfc3164` function using the **strict TAG: + key=value** body parser. No alternate fallback is allowed after a rejected Syslog prefix. The original raw record is not leaked through diagnostic error responses.

The parser's `.conf` listener port **equals** the sensor destination port and is **at least 6800** when a mixed Syslog family is selected. The Ruby parser records `syslog_timestamp` as yearless and `syslog_time_policy=YEAR_AND_ZONE_UNKNOWN`. Mapping the RFC3164 header timestamp to `date` is **rejected** for mixed projects containing this family. This cannot provide an engine event timestamp without an independent explicit year/timezone source.

## Qualification and known limits

The 14th fixed public-synthetic Native Ruby 3.2 / Fluentd 1.17.1 profile verifies the emitted `.conf` listener, parser registration, generated pair SHA, ParserRecipe v0.2 exact v0.1 projection and normalized callback output for JSON, KV and 2 strict RFC3164 TAG KV variants. Nine malformed/unsupported cases (RFC5424, invalid PRI/month/day/TAG, disallowed CEF body, broken quoted KV, standalone CSV, physical multiline) must emit **exactly one** static extraction diagnostic each. The project output and API claim **neither Stellar import nor actual sensor/Interflow E2E**; Native synthetic qualification is not a customer-parser readiness badge.

Generic RFC3164 multiline, unbounded mixed framing, RFC3164-wrapped JSON and any CEF/LEEF without the new explicit strict reviewed allowlist, CSV mixed routing and timestamp inference are unsupported. Unknown and malformed events must remain visible as rejected rather than being silently coerced into another family.
