# English documentation and multilingual security log sources

Parser Studio's project-authored UI, help, accessibility labels, diagnostic
explanations, code comments, tests and documentation prose are written in
English. This controls how the product explains itself. It **does not** limit
the characters or languages that a security log may contain.

Logs may carry Korean, Japanese, Chinese or other Unicode characters in
message bodies, usernames, places, event values and original field names.
Their original UTF-8 bytes, event boundaries, escaped content and meaningful
positions must not be translated, normalized to English, discarded, or marked
invalid solely because of their language. A source field name that cannot
safely be normalized is retained as source evidence or left for review.

Test samples and source-log fixtures may use any language. Fixture metadata
and test descriptions are written in English. For examples in documentation,
place multilingual source logs in fenced log, json, syslog, cef, leef, csv,
kv or text code blocks to distinguish data from authored prose.

The language-policy test checks authored documentation, source comments,
visible JSX text and accessibility labels without scanning log payload
values as presentation copy.

This language clarification is not a claim of complete support for all
locale-specific timestamp spellings or unknown native field mappings.
Unsupported source grammar still returns a truthful review requirement.
