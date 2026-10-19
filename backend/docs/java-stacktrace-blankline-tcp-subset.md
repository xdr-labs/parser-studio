# P0 — Explicit TCP LF LF framed Java exception stack trace (bounded Native subset)

## Source contract and no-code experience

Parser Studio supports a **strict, explicit** Java exception and stack-trace subset as ParserProject v0.1 `extraction.format=java_stacktrace`, `receiver.protocols=[tcp]`, `receiver.tcpFraming=blank_line_java`. Each **complete logical event** must be sent by the source over the **same sensor and .conf listener port** with an empty line (`LF LF`) separating events. This is an explicit sender transport agreement, **not** a Fluentd line-by-line Java stack assembler and **not** generic Java/UDP multiline support.

The beginner Web UI can recognize two or more strict Java exceptions separated with `LF LF` in a raw sample, but **never silently activates the transport**. The user must select **I Confirm TCP Java Events Are Separated by LF LF**, after which the reviewable draft sets TCP-only, blank-line boundaries and three bounded source field candidates. Existing edited mappings are preserved; the suggestion is offered only for untouched default drafts. Edit Details has a manual Java format and explicit framed TCP selector, plus a public-synthetic Java starter. Unframed streams and unsupported Java grammar remain visible as rejected, not false Native PASS.

## Accepted syntax and deterministic decoding

A complete trace begins with a fully qualified `...Exception` or `...Error` class, optionally a short message, then at least one indented `at ...(...java:<line>)` stack frame. Reviewed fixed variants `(Unknown Source)`, `(Native Method)`, `Caused by:` and bounded `... N more` are supported. Source is capped at **8192 UTF-8 bytes**, **64 physical lines**, **512 bytes per line**, **4 causes**. Unsupported arbitrary prefixes, orphan stack frames, missing frames, unframed events, embedded blank lines, Windows CRLF sent directly, non-Java file sources and unsafe/malformed input are **rejected**. Browser and Native parsers emit only the reviewed `exception_class` string, `frame_count` integer and optional `cause_class` string. They never automatically persist or export source stack text.

The compiler emits one `customized_<slug>` Ruby fragment and matching `customized_<slug>.conf`. The source stanza uses literal `delimiter "\\n\\n"` interpreted by Native Fluentd as `LF LF`, the exact configured sensor receive port, and TCP only; no Ruby eval, unbounded regex dispatcher, or external provider call. The v0.2 staged plan adds the typed `parse_java_stacktrace` operation and strict `split_event(blank-line)`, which must project to exactly the same v0.1 pair files and SHA-256 receipts without metadata loss.

## Qualification and remaining limits

The 17th isolated Native Ruby 3.2/Fluentd 1.17.1 synthetic profile `v02_java_blanks` uses two independently authored complete Java exceptions separated by `LF LF`, the actual parsed Fluentd CONF AST and parser callback normalization, plus **nine** malformed/unframed events with exactly one fixed extraction diagnostic each. Static logs remain safe; `engineVerified`, `nativeUserParserVerified`, `targetImportVerified`, actual listener binding and Interflow verification remain **FALSE** for user-generated artifacts. The Native fixture runner does not send sensor logs or import anything into a real Stellar Cyber target.

Outside this reviewed fixed-framing subset, generic live Java stack reassembly (unknown event boundaries), multiline UDP, mixed Java+Syslog/CSV, exception syntax from other vendors, user-editable arbitrary Regex/Ruby, actual DP/sensor operation and external AI metadata are **not supported or separately gated**.
