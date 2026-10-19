# Strict RFC3164 CEF/LEEF mixed Native subset

## Exact reviewable contract

`rfc3164_cef` and `rfc3164_leef` are additional explicit one-line mixed event-family IDs in the server-owned vocabulary. A generated parser selects **2–4 distinct reviewed families**, without auto-fallback or unbounded regex dispatch. Each RFC3164 envelope must parse the existing exact `PRI BSD-MON day hh:mm:ss host TAG[PID]: message` grammar, and each body must strictly match an allowlisted CEF 0 or LEEF 1.0/2.0 body. The Syslog receiver port is the identical number written in the `.conf` listener stanza and must be >=6800.

RFC3164 has **no year or timezone**: `syslog_timestamp` remains a string and `syslog_time_policy=YEAR_AND_ZONE_UNKNOWN`; a date-cast field mapping from the RFC3164 header must be rejected for any mixed project choosing RFC3164 KV/CEF/LEEF. Native callbacks must not synthesize an event timestamp, nor echo raw content in diagnostics. Unsupported envelopes, CEF/LEEF syntax, unselected RFC3164 KV, malformed PRI/calendar/TAG and physical multiline fail closed.

## Evidence and scope

The 16th pinned public-synthetic Native Ruby 3.2/Fluentd 1.17.1 profile uses standalone JSON/KV and separately wrapped RFC3164 CEF and LEEF with independent expected normalized fields and `session`/`threat` classification. Three additional positive and nine negative synthetic cases verify exactly one callback per record, static exceptions, no invented time, exact `.conf` port and deterministic `ParserRecipe v0.2`→`ParserProject v0.1` paired Ruby/CONF SHA correspondence. The browser-guided code offers only explicitly reviewable DRAFT mappings; Native synthetic fixture qualification **does not** establish the user's compiled parser or Stellar Cyber DP/loader/Interflow acceptance.

Unframed Java stack traces, arbitrary RFC3164 body syntax including wrapped JSON, mixed CSV, dynamic Grok/Ruby, sensor sends, external AI and real proprietary target E2E remain unsupported or separately gated.
