# Explicit Syslog prefix and KV profile

## User outcome and compatibility

Some complete source analyses contain a valid BSD Syslog header, a short text prefix and a fully delimited KV suffix. The earlier Generic Structural grammar did not compile these records unless a different reviewed grammar also matched. The additional `syslog_prefix_kv` profile lets the user review those extracted values and produce a DRAFT without a manufacturer-specific expression.

The project explicitly stores `extraction.genericStructuralProfile: "syslog_prefix_kv"`. The frontend requires the same entry in the backend's `genericStructuralProfiles` capability before generation. A backend that only advertises `GENERIC_STRUCTURAL_ULTRA_COMPILER_V15` remains insufficient for this additional profile. The optional `profile` on the `parse_generic_structural` recipe stage must match the project exactly; removing, injecting or changing it is rejected. Existing projects and recipe stages without the option keep their prior grammar.

## Additional bounded grammar

The new fallback accepts one physical record with a PRI in 0–191, a valid yearless BSD month/day/clock, a printable host token, a nonempty text prefix and a suffix of 2–60 distinct KV fields. The complete record is at most 8 KiB; the preserved prefix is at most 1 KiB and each field value is at most 512 UTF-8 bytes. Keys use a bounded identifier/hyphen subset and cannot be prototype-related names. A quoted value may be empty, contain spaces, or use escaped matching quotes/backslashes. Quote delimiters are removed from the extracted value while the literal escape spelling remains intact; `source_raw` retains the complete original representation.

All suffix bytes must be consumed as fields or separating ASCII space/TAB. Other Unicode, including non-breaking spaces (U+00A0), line separators (U+2028) and paragraph separators (U+2029), remains literal prefix/value data. These characters do not substitute for field separators or create physical records; CR/LF remains invalid inside this single-record fallback. The prefix must contain non-whitespace text, using the same explicit whitespace set in TypeScript and Ruby. An unclosed quote, unknown quoted escape, duplicate/unsafe key or trailing prose keeps the record outside this fallback. Structured payload markers and network tuples in the prefix are excluded so the prefix cannot conceal a failed structured parser or replace independently useful network atoms. Unsupported inputs retain their source and review status.

The fallback returns the source header fields, `generic.prefix`, `generic.message_raw`, `generic.source_raw` and `generic.kv`. The prefix includes its original separator before the first key. No year, timezone, manufacturer field meaning or device identity is inferred. `syslog.time_policy` is `YEAR_AND_ZONE_UNKNOWN`.

This is an extension to the existing V15 dispatcher: a record already supported by an earlier route retains that route and its existing limits. The 2–60 field bound applies specifically to the new fallback. A line-delimited batch is framed into separate records; passing multiple physical records to the single-record helper remains invalid.

## Preservation and qualification

The selected profile survives the browser draft, checksum-protected local versions, exact Project JSON import, backend project and staged recipe. A profile-only revision is shown in local version comparison. Unknown profile values and use with another extraction format are rejected.

The focused TypeScript and Ruby regressions share authored synthetic examples: the original source-complete compiler-review case, a multilingual vendor-neutral holdout and invalid grammar/boundary controls. Tests also verify refusal by an older capability response, exact project/recipe agreement and source/profile preservation on restoration. These are scoped authoring tests; they do not establish manufacturer-wide accuracy, proprietary loader support or sensor acceptance. Generated manifests remain DRAFT with engine and target verification flags false.
