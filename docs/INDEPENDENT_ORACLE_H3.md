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
