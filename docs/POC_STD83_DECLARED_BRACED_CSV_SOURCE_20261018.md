# P0-ACC-E1 / P0-STD-83 — Declared Braced CSV Source Boundaries

## Real producer format mismatch (not generic RFC 4180)

A Palo Alto Networks manufacturer-authored knowledgebase article documents that SD-WAN PAN-OS 9.1+ traffic logs may contain a link_switches value enclosed in curly braces, with internal unescaped commas. Splitting that field using *strict RFC 4180* CSV commas shifts later positional fields. A separately reported Elastic integrations parser issue #16486 provides a collector-side counterexample and explicitly flags the unsupported CSV semantics. This does **not** establish all PAN-OS firmware-specific values or a true matched upstream/collector original capture.

Sources:
- Palo Alto Networks official article: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000004LaOCAU
- Palo Alto Networks official field catalog: https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields
- Independent parser misalignment report: https://github.com/elastic/integrations/issues/16486
- RFC 4180 §2: https://www.rfc-editor.org/rfc/rfc4180

The real reported original line is *not* redistributed or counted as a new independently manufacturer-certified event. All committed test input is synthetic and structurally authored from the published dialect description.

## Generic shared lexer change

The existing bounded src/csvSourceCells.ts lexer now supports opt-in declaredBracedGroupColumns, a list of exact zero-based column ordinals. This is a **declared non-RFC 4180 source dialect**, NOT an automatic extension to all CSV, not a vendor-specific regex, and never inferred from a product/vendor name alone.

For declared ordinals only, an entire unquoted cell beginning with a curly bracket may contain commas within a bounded properly balanced curly-brace group. The group remains the *raw source value*, including brackets. Nested groups up to four levels can be observed without changing original value or source intervals. Unknown backslash/quote escape behavior, unmatched/unclosed braces, characters trailing the closing brace, input controls and out-of-bounds nesting ABSTAIN rather than silently unescape or split. Outside declared ordinals the exact existing strict RFC 4180 scanner runs unchanged.

The existing src/poc/independentQuotedCsvSource.ts source observer reuses that same lexer. To use the nonstandard grouping, the caller must explicitly provide CONFIRMED_SINGLE_CSV_RECORD framing, a source header or ordered field-name definition, and exact declared braced-group column indices. Group indices outside the declared header width, duplicate/unsafe header names or inconsistent widths ABSTAIN. Original absolute UTF-8 field lexemes, byte ranges and RFC 4180 quoted/empty semantics survive separately. Special grouped cells carry BOUNDED_SOURCE_BYTE_AND_DECLARED_BRACED_GROUP evidence, never a misleading RFC 4180 claim.

Even with an externally stated layout, all extracted names and values remain **REVIEW_ONLY_NAMED**, independentOracleCertified:false, autoPromoted:false, nativeVerified:false. The provided column names are merely review context, not a certified device schema. Without that explicit declaration there is no automatic nonstandard grouping and the old observer behavior is unchanged.

## Independently authored source oracle

- scripts/poc/freezeStd83DeclaredBracedCsv.py pins 33 new format-derived **synthetic** source cases (14 positive / 19 negative), 54 independent raw/decoded field/value/UTF-8 byte interval claims.
- scripts/poc/standard83DeclaredBracedCsv.pinned.json SHA256 **c1f149a7e831c99bf25e68c9d5c82bf72ef07ffc1cedf5b9c9033d3fc6eb1027**.
- Positives include ordinary/nonstandard braced values, nested groups, multiple declared columns, first/last ordinal, adjacent proper RFC 4180 quoted fields, empty and scalar variants, and multibyte offsets. Negative controls include absent/wrong declaration, missing schema, wrong/duplicate ordinal, malformed/over-deep braces, unknown escapes, NUL/control/newline, duplicate field names, width shifts, invalid Unicode and malformed standard quoting.
- Before shared scanner change 14 tests RED; narrow generic change plus explicit schema-width validation yields **94/94 focused tests GREEN** across new and prior CSV suites.
- This is a demonstrated source-cell **boundary** improvement on independently authored cases, not a new genuine manufacturer field accuracy TP/FN score, not device capture, not a native loader test, and not proof that manufacturer-dependent output semantics are resolved.

## Qualification gates / limits

Full deterministic Vitest, TypeScript/Vite, SHA-pinned historical 1,361 originals + 2,892 prior malformed (197 remain REVIEW_ONLY), prior independent source replay and exact-head GitHub CI are independently required before completion. No blanket RFC 4180, Palo Alto, or Stellar Cyber compatibility claim follows from this lexical proof.

Further real-field qualification requires a version-scoped manufacturer original raw wire, declared ordered column schema, independent exact lexical and decoded expectations, safe relay provenance and actual native Fluentd/Stellar execution. Never expand this group rule automatically to undeclared cells: a bracket may also be ordinary user content. The later approved product UI should expose source-schema/field-ordinal authoring and mark results for operator review.

## Isolation and reproduction

This is a source-only isolated worktree branched directly from Draft PR #82 exact c02761250fd06bc004fd2dc429c37e2923f6b3df. No product/main/native/DP/sensor/credential/production/release/merge changes are authorized.

~~~sh
python3 scripts/poc/freezeStd83DeclaredBracedCsv.py
sha256sum scripts/poc/standard83DeclaredBracedCsv.pinned.json
npx --no-install vitest run src/poc/standard83DeclaredBracedCsv.test.ts src/poc/standardCsvWhitespaceSourceParity.test.ts src/poc/standardCsvMultilineOriginalSpans.test.ts src/poc/independentQuotedCsvSource.test.ts
npm test
npm run build
npx --no-install tsx scripts/poc/runIndependentQuotedCsvSafetyReplay.ts
npx --no-install tsx scripts/poc/auditHistoricalMalformedReviewBounds.ts
npx --no-install tsx scripts/poc/runIndependentNonJsonSafetyReplay.ts
git diff --check
~~~
