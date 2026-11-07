# Independent Oracle H3 — deterministic event-order metamorphic regression

Status: **H3 first increment**. This is not full semantic acceptance for every
security-source grammar or proof of Stellar Cyber DP compatibility.

`src/guided/mappingMetamorphicOracle20261107.test.ts` exercises
100 fixed-seed synthetic combinations containing 2–10 event types, each with
fewer than 100 individually safe source leaf fields. Independent expected
official fields are `srcip`, `dstip`, `srcport`, `dstport` and `proto`.

Each seed generates forward, reversed, rotated and seeded-shuffled event orders
and checks the same source/target/type/observed-count proposal set. All five
official fields must remain human-review candidates rather than being
silently auto-promoted when present in only one event type. Unicode values in
vendor-only fields remain byte-identical, and intentionally competing source
aliases for one official destination must remain ambiguous in both orders.

The oracle is **separately authored**: target expectations are fixed in the
test and are not copied from Parser Studio output. The seeds and fixture text
are static, reproducible and contain no customer data.

Remaining H3 coverage: independently sourced positive/negative fixtures for
each supported grammar, UTF-8 byte offset accounting, numeric/NULL/boundary
mutations, complete generated Ruby field/error parity and real user browser
scenarios. Do not claim a vendor-wide accuracy percentage from these synthetic
metamorphic tests.

## H3 independently authored eight-grammar native goldens (stacked Draft)

The next CI Native oracle increment adds 16 fixed positive/negative
**synthetic** source records over eight supported ParserProject extraction
grammars: JSON, KV, CSV, CEF 0, LEEF 2.0, RFC 5424 with KV body, RFC 3164
with KV body and reviewed bounded named-capture Regex.

Each grammar fixture has separately authored input text, expected official
`srcip` and `action`, expected event index, and a deliberately invalid IP
variant. The latter must produce a `normalization`-stage
`MappedFieldError`, identify the exact offending field, retain the
independently valid action and exclude the invalid official `srcip` without
echoing source text. Multiple structured fixtures contain original Korean
Unicode values; source identity is preserved by SHA-256 and UTF-8 byte count.
The native test generates the real Ruby parser from each validated DRAFT
project and executes it with the fixture pair in Ruby CI.

This is an additional independently specified, small synthetic
grammar-coverage gate, **not** real-manufacturer accuracy evidence, not
grammar-complete matched/unmatched byte accounting and not Stellar DP 7.0
qualification. The remaining H3 target requires larger independent
manufacturer-sourced positive/negative corpora, protocol-specific
holdouts, matched/residual offset goldens and repeated browser/Native
differential runs without reusing implementation-produced expected output.
