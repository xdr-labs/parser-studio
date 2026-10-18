# Strict mixed CSV with an explicitly reviewed schema

## Supported subset

`csv` may be one explicitly selected family among 2–4 single-line mixed JSON/KV/CEF/LEEF/Syslog families. The user must supply **at least two unique, valid CSV field names in the correct order** and an **explicit comma, semicolon or TAB delimiter**. No backend API or compiled Ruby guesses these values. A blank row, unmatched quote, incorrect number of columns, unselected format, physical multiline, wrong delimiter, duplicate KV or unrecognized Syslog cannot be silently accepted. The CSV branch is considered only after checked JSON, KV, CEF, LEEF and strict Syslog prefixes, and only when the selected delimiter is present.

The existing strict Ruby `CSV.parse_line(..., liberal_parsing: false)` and full field-count comparison are reused; no dynamic Regular Expression or caller-authored Ruby executes. The exact receiver port in the generated CONF is the same port the sensor would send to. Syslog port >=6800 still applies to any selected Syslog family. Input/source examples remain in the browser for no-code review and are never automatically transmitted to an external LLM.

## Evidence, limits and safety

The 18th public synthetic Native Fluentd 1.17.1/Ruby 3.2 profile verifies standalone JSON/KV and both quoted/unquoted semicolon CSV in one fixed allowlisted parser, independent expected normalized fields and classification, a fixed 9-record malformed/unsupported corpus, exact CONST-safe extraction diagnostics, AST CONF port and v0.2 stage/v0.1 byte-identical Ruby+CONF SHA. Backend `engineVerified` and `targetImportVerified` remain false for a *user-authored parser*. A synthetic fixture is not proof of actual Stellar Cyber loader, sensor packet arrival or Interflow indexing.

This narrow subset does not support dynamic CSV column inference, schema merging, CSV with unreviewed multiline quotes, arbitrary mixed CSV without an explicit delimiter, Java stack-trace reconstruction without TCP LF LF framing, or executing any AI-generated code. The user must explicitly review any CSV column metadata before the DRAFT pair can be generated.
