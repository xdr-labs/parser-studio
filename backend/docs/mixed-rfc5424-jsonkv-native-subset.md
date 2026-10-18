# Strict mixed RFC5424-wrapped JSON/KV — Native reviewed subset

## Format and event accounting

Two new explicitly selected one-line family identifiers, `rfc5424_json` and `rfc5424_kv`, are available to the `mixed` ParserProject v0.1 and identical staged ParserRecipe v0.2 projection. A project may select **2–4 unique identifiers** from the server-owned allowlist of nine reviewed standalone, RFC3164 and RFC5424 families. Each raw record must be attributable to exactly one allowed family; unsupported envelopes and malformed bodies fail closed instead of being assigned to KV or dropped. The mixed parser has no Native physical multiline reassembler and does not infer timestamps or other metadata.

For each wrapped record the generated Ruby invokes the already-reviewed strict RFC5424 version-1 parser (PRI 0–191; offset-bearing RFC3339 time or NILVALUE; bounded ASCII header and reviewed SD grammar) to obtain the body. Only `{`-prefixed body records are decoded with the bounded JSON object parser, and only key=value-prefix records with the strict duplicate-safe, quoted/escaped KV parser. Both branches are enforced by an explicit family allowlist. A valid but unselected CEF/LEEF or arbitrary unstructured message is not accepted as JSON/KV. The generated `.conf` listener port is identical to the sensor destination port, with **Syslog >=6800**.

## Evidence and compatibility

The 15th fixed, public-synthetic Native Ruby 3.2 / Fluentd 1.17.1 qualification profile, `v02_mixed_rfc5424_bodies`, uses one standalone JSON, one standalone KV and two RFC5424-wrapped JSON/KV messages. Three additional synthetics have independent expected normalized fields, types and explicit timestamp; nine negative cases cover RFC5424 version/time/PRI corruption, JSON/KV syntax errors, disallowed CEF/LEEF, CSV and physical multiline. Generated `.conf` AST, parser registration, strict callback accounting, `ParserRecipe v0.2`→v0.1 pair bytes and SHA-256 receipts are checked. The native JSON parser can safely emit the static exception class `JSON::ParserError`; its original exception text and input are not echoed.

These fixtures **do not** validate a user-submitted parser on a real target. `engineVerified`, `targetImportVerified` and all actual DP/sensor/Interflow readiness flags remain false in the DRAFT API. The external AI provider and any target write/sensor sending are disabled or independently approved.

Remaining unsupported: arbitrary RFC3164 mixed body extensions beyond explicit strict TAG KV or separately allowlisted RFC3164 CEF/LEEF, CSV within mixed routing, unframed Java stack traces, arbitrary per-vendor Ruby, dynamic regex dispatch and unsupported RFC5424 variants outside the reviewed subset.
